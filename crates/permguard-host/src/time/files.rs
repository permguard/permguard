// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The file backend of [`ClockMark`]: the view `host/state/CLOCK`, the highest wall time
//! observed, seconds since the epoch, eight bytes big-endian.

use std::sync::{Mutex, PoisonError};

use super::{ClockMark, MarkError};
use crate::storage::StorageError;
use crate::storage::dir::Dir;
use crate::storage::format;
use crate::storage::volume::Volume;
use crate::storage::write::{read_view, replace_view};

/// The directory below `host/` the high-water mark is kept in.
const STATE: &str = "state";
/// The view holding the mark.
const CLOCK: &str = "CLOCK";

impl From<StorageError> for MarkError {
    fn from(error: StorageError) -> Self {
        match error {
            StorageError::Corruption(detail) => Self::Record(detail),
            other => Self::Unavailable(Box::new(other)),
        }
    }
}

/// The clock's mark on one volume.
pub struct FileClockMark {
    dir: Dir,
    /// Held from the read of the mark to the write that raises it.
    raising: Mutex<()>,
}

impl std::fmt::Debug for FileClockMark {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileClockMark")
            .finish_non_exhaustive()
    }
}

impl FileClockMark {
    /// The mark of `volume`, its directory created when absent.
    pub fn open(volume: &Volume) -> Result<Self, StorageError> {
        Ok(Self {
            dir: volume.host().subdir(STATE, true)?,
            raising: Mutex::new(()),
        })
    }
}

impl ClockMark for FileClockMark {
    fn read(&self) -> Result<Option<i64>, MarkError> {
        let Some(body) = read_view(&self.dir, CLOCK, format::VIEW)? else {
            return Ok(None);
        };
        let bytes: [u8; 8] = body.as_slice().try_into().map_err(|_| {
            MarkError::Record(format!(
                "{} holds {} bytes where a wall time takes 8",
                self.dir.child_path(CLOCK).display(),
                body.len()
            ))
        })?;
        Ok(Some(i64::from_be_bytes(bytes)))
    }

    fn raise(&self, mark: i64) -> Result<(), MarkError> {
        let _raising = self.raising.lock().unwrap_or_else(PoisonError::into_inner);
        if self.read()?.is_some_and(|held| held >= mark) {
            return Ok(());
        }
        replace_view(&self.dir, CLOCK, format::VIEW, &mark.to_be_bytes())?;
        Ok(())
    }

    fn remedy(&self) -> String {
        format!(
            "stop the server and remove {}, which makes the next start a first start",
            self.dir.child_path(CLOCK).display()
        )
    }
}
