// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `--confirm-file <receipt>`: the plan a run consumes, read whole from the file the plan step
//! wrote (TC-1). A receipt never travels in argv; what it holds is never echoed in a refusal,
//! which names the file and what is wrong with it, and nothing it contains.

use std::path::Path;

use serde::de::DeserializeOwned;

use crate::failure::Failure;

/// Reads the receipt `confirm_file` names as a `what`: refused when no file was named, when it
/// cannot be read, when it is empty, or when it is not a `what`.
pub fn read<T: DeserializeOwned>(confirm_file: Option<&Path>, what: &str) -> Result<T, Failure> {
    let path = confirm_file.ok_or_else(|| {
        Failure::usage(format!(
            "--confirm-file names the {what} the plan step wrote"
        ))
    })?;
    let bytes = std::fs::read(path)
        .map_err(|error| Failure::usage(format!("--confirm-file {}: {error}", path.display())))?;
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Err(Failure::usage(format!(
            "--confirm-file {} is empty",
            path.display()
        )));
    }
    serde_json::from_slice(&bytes).map_err(|error| {
        // The position, never the bytes: a receipt may carry what only its owner should see.
        Failure::usage(format!(
            "--confirm-file {} is not a {what} (line {}, column {})",
            path.display(),
            error.line(),
            error.column()
        ))
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[derive(serde::Deserialize, Debug)]
    struct Receipt {
        #[allow(dead_code)]
        plan_id: String,
    }

    #[test]
    fn a_confirm_file_is_read_whole_and_never_echoed() {
        let dir = std::env::temp_dir().join(format!("permguard-confirm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("created");
        let good = dir.join("good.plan");
        std::fs::write(&good, r#"{"plan_id":"p-1"}"#).expect("written");
        assert!(read::<Receipt>(Some(&good), "plan").is_ok(), "a plan reads");

        let Err(missing) = read::<Receipt>(None, "plan") else {
            panic!("nothing named")
        };
        assert_eq!(missing.status, crate::failure::EXIT_USAGE);
        let empty = dir.join("empty.plan");
        std::fs::write(&empty, "  \n").expect("written");
        assert!(
            read::<Receipt>(Some(&empty), "plan")
                .expect_err("empty")
                .message
                .contains("is empty")
        );
        let secret = "capability-0123456789-do-not-print";
        let garbage = dir.join("garbage.plan");
        std::fs::write(&garbage, format!("{{\"plan_id\": {secret}}}")).expect("written");
        let Err(refused) = read::<Receipt>(Some(&garbage), "plan") else {
            panic!("not a plan")
        };
        assert!(
            refused.message.contains("is not a plan"),
            "{}",
            refused.message
        );
        assert!(!refused.message.contains(secret), "{}", refused.message);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
