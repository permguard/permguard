// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A Data Plane Host joining its coordinator by itself, at start, from an invitation mounted as a
//! file (iteration 02, TD-5, `1-architecture/11` Join from an invitation file). The join makes a
//! pending membership the coordinator approves as any other: the enrollment is automated, never
//! the approval. The token is never logged; the files are read only while the Host holds fewer
//! memberships as a member than it names invitations, so a Host that joined never reads them again
//! and an operator may remove or reissue them.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use permguard_core::config::HostJoin;
use permguard_core::{ErrorClass, Health, codes};
use permguard_host::api::HostApi;
use permguard_host::api::host_input::InvitationHandoff;

/// What the Host reports while a configured join has made no membership.
const CAPABILITY: &str = "join";
/// The most an invitation file may hold.
const MAX_BYTES: u64 = 64 * 1024;
/// The longest wait between two attempts while the coordinator does not answer.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// The running joins; dropping it stops them with the server.
pub(crate) struct Joining(tokio::task::JoinHandle<()>);

impl Drop for Joining {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Starts the joins a configuration names, one per invitation file, each made once. A Host that
/// already holds as many memberships as it names invitations never reads them again: an operator
/// may remove or reissue them once the replica joined. A Host that cannot join at all, with no
/// client to reach a coordinator, is refused at start rather than retried for ever.
pub(crate) fn drive(api: Arc<HostApi>, join: HostJoin, health: Health) -> anyhow::Result<Joining> {
    if let Err(refusal) = api.can_join() {
        anyhow::bail!(
            "host.join: this Host cannot reach a coordinator: {}",
            refusal.error().map(ToString::to_string).unwrap_or_default()
        );
    }
    Ok(Joining(tokio::spawn(async move {
        let (held, pending) = api.joined_memberships();
        let mut waiting = pending;
        let mut refusal: Option<String> = None;
        if held >= join.invitation_files.len() {
            tracing::info!(
                event.name = "host.join_done",
                component = "host",
                memberships = held,
                "this Host joined with its invitations before: they are not read again"
            );
        } else {
            for file in &join.invitation_files {
                match join_one(&api, &join, file, &health, refusal.is_none()).await {
                    Ok(Some(id)) if !waiting.contains(&id) => waiting.push(id),
                    Ok(_) => {}
                    Err(reason) => {
                        refusal.get_or_insert(reason);
                    }
                }
            }
        }
        match &refusal {
            // The first refusal is the one reported, whatever came after it.
            Some(reason) => health.lifecycle().degrade(
                permguard_core::lifecycle::HOST,
                CAPABILITY,
                format!("a join was refused: {reason}"),
            ),
            None => health
                .lifecycle()
                .restore(permguard_core::lifecycle::HOST, CAPABILITY),
        }
        await_decisions(&api, waiting).await;
    })))
}

/// One invitation: the membership it made, when it still waits for its approval; `Err` with the
/// reason when it was refused, which is reported and not tried again.
async fn join_one(
    api: &HostApi,
    join: &HostJoin,
    file: &Path,
    health: &Health,
    report: bool,
) -> Result<Option<String>, String> {
    let refuse = |reason: String| {
        tracing::error!(
            event.name = "host.join_refused",
            component = "host",
            invitation = %file.display(),
            reason = %reason,
            "the join from a configured invitation was refused; it is not tried again"
        );
        reason
    };
    let path = file.to_path_buf();
    let handoff = match tokio::task::spawn_blocking(move || read(&path)).await {
        Ok(Ok(handoff)) => handoff,
        Ok(Err(reason)) => return Err(refuse(reason)),
        Err(error) => return Err(refuse(format!("reading the invitation: {error}"))),
    };
    if let Some((id, pending)) = api.joined_with(&handoff) {
        return Ok(pending.then_some(id));
    }
    if report {
        health.lifecycle().degrade(
            permguard_core::lifecycle::HOST,
            CAPABILITY,
            "a join from an invitation is configured and has made no membership yet",
        );
    }
    tracing::info!(
        event.name = "host.join_started",
        component = "host",
        invitation = %file.display(),
        selector = %handoff.requested.selector,
        "joining the coordinator the invitation names, as this Host"
    );
    let mut backoff = Duration::from_secs(1);
    let mut unanswered = false;
    loop {
        match api
            .join_from_invitation(
                &handoff,
                &join.pin_fingerprint,
                join.name.clone(),
                join.groups.clone(),
            )
            .await
        {
            Ok(view) => {
                tracing::info!(
                    event.name = "host.join_pending",
                    component = "host",
                    membership = %view.membership_id,
                    status = %view.status,
                    "joined: the membership waits for the coordinator's approval"
                );
                return Ok((view.status == "pending").then_some(view.membership_id));
            }
            Err(refusal) => match refusal.error() {
                Some(error)
                    if error.class() == ErrorClass::Unavailable
                        && error.code() != codes::host::PEER_CLIENT_UNCONFIGURED =>
                {
                    unanswered = true;
                    tracing::warn!(
                        event.name = "host.join_retry",
                        component = "host",
                        invitation = %file.display(),
                        reason = %error,
                        // What the transport or the coordinator said: the operator's to diagnose
                        // with, never a token or a secret.
                        detail = error.internal_detail().unwrap_or_default(),
                        after_seconds = backoff.as_secs(),
                        "the coordinator did not take the join: trying again"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
                // An answer lost after the coordinator took the invitation leaves its pending
                // membership there, and this retry refused as a spent invitation: said so, for
                // the operator to approve it after checking its fingerprint, or to reject it.
                Some(error) if unanswered && error.code() == codes::host::ENROLLMENT_REFUSED => {
                    return Err(refuse(format!(
                        "{error}; an earlier attempt went unanswered, so the coordinator may hold \
                         this Host's pending membership: approve it after checking its \
                         fingerprint, or reject it and issue a new invitation"
                    )));
                }
                Some(error) => return Err(refuse(error.to_string())),
                None => return Err(refuse("refused by this Host's authorization".to_owned())),
            },
        }
    }
}

/// Syncs the memberships the joins made, all of them at each pass, until the coordinator decides
/// each: approved, it is active and its tasks run; rejected, it says so; a membership this Host no
/// longer knows is left. Every 15 seconds at first, then up to a minute apart.
async fn await_decisions(api: &HostApi, mut waiting: Vec<String>) {
    let mut every = Duration::from_secs(15);
    while !waiting.is_empty() {
        tokio::time::sleep(every).await;
        let mut still = Vec::new();
        for id in waiting {
            match api.sync_joined(&id).await {
                Ok(view) if view.status == "pending" => still.push(id),
                Ok(view) => tracing::info!(
                    event.name = "host.join_decided",
                    component = "host",
                    membership = %view.membership_id,
                    status = %view.status,
                    "the coordinator decided the membership this Host joined"
                ),
                Err(refusal)
                    if refusal
                        .error()
                        .is_some_and(|error| error.code() == codes::host::MEMBERSHIP_UNKNOWN) =>
                {
                    tracing::error!(
                        event.name = "host.join_sync_failed",
                        component = "host",
                        membership = %id,
                        "the joined membership is unknown: it is no longer synced"
                    );
                }
                Err(refusal) => {
                    tracing::warn!(
                        event.name = "host.join_sync_failed",
                        component = "host",
                        membership = %id,
                        reason = %refusal.error().map(ToString::to_string).unwrap_or_default(),
                        "the joined membership could not be synced: trying again"
                    );
                    still.push(id);
                }
            }
        }
        waiting = still;
        every = (every * 2).min(MAX_BACKOFF);
    }
}

/// The invitation handoff, from a regular file no other user can read, of a handoff's size.
fn read(path: &Path) -> Result<InvitationHandoff, String> {
    use std::io::Read as _;

    let refused = |why: &str| format!("{}: {why}", path.display());
    let named = std::fs::symlink_metadata(path).map_err(|error| refused(&error.to_string()))?;
    // A Secret mounted by Kubernetes is a link to its current version: what it points to is read.
    let file = std::fs::File::open(path).map_err(|error| refused(&error.to_string()))?;
    let opened = file
        .metadata()
        .map_err(|error| refused(&error.to_string()))?;
    if !opened.is_file() || (!named.is_file() && !named.file_type().is_symlink()) {
        return Err(refused("is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        // Readable by its owner and, where an orchestrator mounts it so, its group: never by
        // every user of the machine.
        if opened.permissions().mode() & 0o027 != 0 {
            return Err(refused(
                "is readable by every user or writable by its group: mount it 0400 or 0440",
            ));
        }
    }
    if opened.len() > MAX_BYTES {
        return Err(refused("is larger than an invitation"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| refused(&error.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|_| refused("is not an invitation handoff"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("pg-join-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a folder");
        dir
    }

    fn write(path: &Path, text: &str, mode: u32) {
        let _ = std::fs::remove_file(path);
        std::fs::write(path, text).expect("written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("mode");
        }
        #[cfg(not(unix))]
        let _ = mode;
    }

    const HANDOFF: &str = r#"{"version":1,"coordinator":{"address":"https://cp:5444","host_id":"0198f2aa-0000-7000-8000-000000000001","fingerprint":"sha256:aa"},"invite_id":"0198f2aa-0000-7000-8000-000000000002","token":"dG9rZW4","requested":{"selector":"plane/data/*","tasks":[]},"expires":"2099-01-01T00:00:00Z"}"#;

    #[test]
    fn an_invitation_file_is_read_only_when_no_other_user_can() {
        let dir = scratch("read");
        let file = dir.join("invitation-0");
        write(&file, HANDOFF, 0o440);
        let handoff = read(&file).expect("a handoff");
        assert_eq!(handoff.coordinator.address, "https://cp:5444");
        #[cfg(unix)]
        {
            write(&file, HANDOFF, 0o444);
            assert!(read(&file).is_err_and(|why| why.contains("every user")));
            write(&file, HANDOFF, 0o460);
            assert!(read(&file).is_err_and(|why| why.contains("writable by its group")));
        }
        write(&file, "{\"version\":1}", 0o400);
        assert!(read(&file).is_err_and(|why| why.contains("not an invitation")));
        write(
            &file,
            &"x".repeat(usize::try_from(MAX_BYTES).expect("small") + 1),
            0o400,
        );
        assert!(read(&file).is_err_and(|why| why.contains("larger")));
        assert!(read(&dir.join("absent")).is_err());
        assert!(read(&dir).is_err_and(|why| why.contains("regular file")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_error_names_the_file_never_the_token() {
        let dir = scratch("token");
        let file = dir.join("invitation-0");
        write(
            &file,
            &HANDOFF.replace("\"version\":1", "\"version\":1,\"extra\":true"),
            0o400,
        );
        let why = read(&file).expect_err("an unknown field");
        assert!(
            why.contains("invitation-0") && !why.contains("dG9rZW4"),
            "{why}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
