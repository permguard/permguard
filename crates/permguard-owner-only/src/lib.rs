#![deny(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used, clippy::expect_used)]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Owner-only files and directories on Windows (BUG-0324, BUG-0325, owner decision of
//! 2026-11-20).
//!
//! On Unix a file is its owner's when its mode says so, and the callers create and check modes.
//! Windows has no mode: who may open a file is its access list, inherited from its folder unless
//! it is protected. This crate is the one place allowed to call the Win32 security API, `unsafe`
//! by nature, so every other crate keeps `#![forbid(unsafe_code)]`.
//!
//! | Function                   | Windows                                                         | elsewhere      |
//! | -------------------------- | --------------------------------------------------------------- | -------------- |
//! | [`restrict_to_owner`]      | a protected access list granting the current user full control, | nothing to do  |
//! |                            | inherited by what a folder holds and will hold                  |                |
//! | [`access_beyond_owner`]    | every principal the access list grants anything to besides the | always empty   |
//! |                            | current user, `SYSTEM` and the Administrators                   |                |
//!
//! `SYSTEM` and the Administrators are not judged: they can take any file whatever its list says,
//! so a list naming them grants nothing they lack. A file with no access list at all is open to
//! everyone and reported as `Everyone`.

use std::path::Path;

/// What an access list grants to everyone when it holds none.
pub const EVERYONE: &str = "Everyone (no access list)";

/// Restricts `path` to the current user: on Windows its access list becomes a protected one
/// granting the current user full control, inherited by everything a directory holds and will
/// hold. Elsewhere nothing is done: the callers create and check the mode.
pub fn restrict_to_owner(path: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        windows::restrict_to_owner(path)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Ok(())
    }
}

/// The principals the access list of `path` grants anything to besides the current user,
/// `SYSTEM` and the Administrators, as SID strings (`S-1-5-…`), or [`EVERYONE`] when it holds no
/// list. Empty when the file is its owner's alone, and always empty elsewhere than on Windows.
pub fn access_beyond_owner(path: &Path) -> std::io::Result<Vec<String>> {
    #[cfg(windows)]
    {
        windows::access_beyond_owner(path)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Ok(Vec::new())
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows {
    //! The Win32 calls. Each `unsafe` block passes pointers this module owns for the duration of
    //! the call, and frees what Windows allocated with `LocalFree`.

    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt as _;
    use std::path::Path;

    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, EXPLICIT_ACCESS_W, GetNamedSecurityInfoW, NO_MULTIPLE_TRUSTEE,
        SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID,
        TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
        GetTokenInformation, NO_INHERITANCE, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, SUB_CONTAINERS_AND_OBJECTS_INHERIT, TOKEN_QUERY, TOKEN_USER,
        TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// The largest SID: `SECURITY_MAX_SID_SIZE`.
    const MAX_SID: usize = 68;

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn failed(what: &str, code: u32) -> std::io::Error {
        std::io::Error::new(
            std::io::Error::from_raw_os_error(code as i32).kind(),
            format!("{what}: {}", std::io::Error::from_raw_os_error(code as i32)),
        )
    }

    /// The current user's SID, as the process token names it.
    fn current_user() -> std::io::Result<Vec<u8>> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: the pseudo-handle of the current process needs no closing; `token` is written.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut needed = 0u32;
        // SAFETY: a null buffer of length zero asks the size the user information needs.
        unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
        let mut buffer = vec![0u8; needed as usize];
        // SAFETY: `buffer` holds `needed` bytes, the size Windows asked for.
        let read = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast::<c_void>(),
                needed,
                &mut needed,
            )
        };
        let error = std::io::Error::last_os_error();
        // SAFETY: `token` was opened above and is closed once.
        unsafe { CloseHandle(token) };
        if read == 0 {
            return Err(error);
        }
        // SAFETY: the buffer starts with a TOKEN_USER whose SID points inside the same buffer.
        let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        sid_bytes(sid)
    }

    /// The bytes of `sid`, copied out of whatever holds it.
    fn sid_bytes(sid: PSID) -> std::io::Result<Vec<u8>> {
        // SAFETY: a valid SID's length is `8 + 4 * SubAuthorityCount`, read from its own header.
        let count = unsafe { *sid.cast::<u8>().add(1) } as usize;
        let length = 8 + 4 * count;
        if length > MAX_SID {
            return Err(std::io::Error::other("a SID longer than any SID"));
        }
        // SAFETY: `length` bytes are the SID's own.
        Ok(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) }.to_vec())
    }

    /// A well-known SID: `SYSTEM` or the Administrators.
    fn well_known(kind: i32) -> std::io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; MAX_SID];
        let mut size = MAX_SID as u32;
        // SAFETY: `buffer` holds `size` bytes; no domain SID is needed for these two.
        if unsafe {
            CreateWellKnownSid(
                kind,
                std::ptr::null_mut(),
                buffer.as_mut_ptr().cast::<c_void>(),
                &mut size,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        buffer.truncate(size as usize);
        Ok(buffer)
    }

    pub(super) fn restrict_to_owner(path: &Path) -> std::io::Result<()> {
        let mut user = current_user()?;
        let inheritance = if path.is_dir() {
            SUB_CONTAINERS_AND_OBJECTS_INHERIT
        } else {
            NO_INHERITANCE
        };
        let access = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_ALL_ACCESS,
            grfAccessMode: SET_ACCESS,
            grfInheritance: inheritance,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                ptstrName: user.as_mut_ptr().cast::<u16>(),
            },
        };
        let mut acl: *mut ACL = std::ptr::null_mut();
        // SAFETY: one entry, a new list (no old one), written to `acl`, freed below.
        let built = unsafe { SetEntriesInAclW(1, &access, std::ptr::null(), &mut acl) };
        if built != ERROR_SUCCESS {
            return Err(failed("building the owner's access list", built));
        }
        let name = wide(path);
        // SAFETY: `name` is NUL-terminated; only the list is set, protected from inheritance.
        let set = unsafe {
            SetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl,
                std::ptr::null(),
            )
        };
        // SAFETY: `acl` was allocated by SetEntriesInAclW.
        unsafe { LocalFree(acl as HLOCAL) };
        if set != ERROR_SUCCESS {
            return Err(failed(
                &format!("restricting {} to its owner", path.display()),
                set,
            ));
        }
        Ok(())
    }

    pub(super) fn access_beyond_owner(path: &Path) -> std::io::Result<Vec<String>> {
        let user = current_user()?;
        let system = well_known(WinLocalSystemSid)?;
        let administrators = well_known(WinBuiltinAdministratorsSid)?;
        let name = wide(path);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `name` is NUL-terminated; the list points inside `descriptor`, freed below.
        let read = unsafe {
            GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        if read != ERROR_SUCCESS {
            return Err(failed(
                &format!("reading the access list of {}", path.display()),
                read,
            ));
        }
        let beyond = granted(dacl, &[&user, &system, &administrators]);
        // SAFETY: `descriptor` was allocated by GetNamedSecurityInfoW.
        unsafe { LocalFree(descriptor as HLOCAL) };
        beyond
    }

    /// The principals `dacl` allows anything to, past those `allowed`.
    fn granted(dacl: *mut ACL, allowed: &[&Vec<u8>]) -> std::io::Result<Vec<String>> {
        if dacl.is_null() {
            return Ok(vec![super::EVERYONE.to_owned()]);
        }
        let mut size = ACL_SIZE_INFORMATION {
            AceCount: 0,
            AclBytesInUse: 0,
            AclBytesFree: 0,
        };
        // SAFETY: `dacl` is a valid list; `size` is the structure the class asks for.
        if unsafe {
            GetAclInformation(
                dacl,
                (&mut size as *mut ACL_SIZE_INFORMATION).cast::<c_void>(),
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let mut beyond = Vec::new();
        for index in 0..size.AceCount {
            let mut ace: *mut c_void = std::ptr::null_mut();
            // SAFETY: `index` is below the list's count; `ace` points inside the list.
            if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: every entry starts with its header.
            let header = unsafe { *ace.cast::<ACE_HEADER>() };
            if header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8 {
                // A deny entry grants nothing; the other kinds are judged by their SID below
                // only when they allow.
                continue;
            }
            // SAFETY: an allowed entry's SID starts at `SidStart`, inside the entry.
            let sid = unsafe {
                std::ptr::addr_of_mut!((*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart)
                    .cast::<c_void>()
            };
            let known = allowed.iter().any(|allowed| {
                // SAFETY: both are valid SIDs for the duration of the call.
                unsafe { EqualSid(sid, allowed.as_ptr().cast_mut().cast::<c_void>()) != 0 }
            });
            if !known {
                beyond.push(sid_text(sid).unwrap_or_else(|_| "an unreadable SID".to_owned()));
            }
        }
        beyond.sort();
        beyond.dedup();
        Ok(beyond)
    }

    /// `sid` as `S-1-5-…`.
    fn sid_text(sid: PSID) -> std::io::Result<String> {
        let mut text: *mut u16 = std::ptr::null_mut();
        // SAFETY: `text` receives a string Windows allocates, freed below.
        if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut length = 0;
        // SAFETY: the string is NUL-terminated.
        while unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        // SAFETY: `length` code units precede the terminator.
        let wide = unsafe { std::slice::from_raw_parts(text, length) };
        let rendered = String::from_utf16_lossy(wide);
        // SAFETY: allocated by ConvertSidToStringSidW.
        unsafe { LocalFree(text as HLOCAL) };
        Ok(rendered)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pg-owner-only-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory is created");
        dir
    }

    /// BUG-0324, BUG-0325: a folder restricted to its owner holds a file its owner alone is
    /// granted, created after the restriction as before it; elsewhere than on Windows both calls
    /// do nothing and find nothing.
    #[test]
    fn a_folder_restricted_to_its_owner_grants_nobody_else_what_it_holds() {
        let dir = scratch("restricted");
        let before = dir.join("before");
        std::fs::write(&before, b"secret").expect("written");
        restrict_to_owner(&dir).expect("restricted");
        let after = dir.join("after");
        std::fs::write(&after, b"secret").expect("written");
        assert_eq!(
            access_beyond_owner(&dir).expect("read"),
            Vec::<String>::new()
        );
        assert_eq!(
            access_beyond_owner(&after).expect("read"),
            Vec::<String>::new(),
            "inherited"
        );
        restrict_to_owner(&before).expect("restricted");
        assert_eq!(
            access_beyond_owner(&before).expect("read"),
            Vec::<String>::new()
        );
    }

    /// BUG-0324: a file in a folder open to others, as a temporary folder or a profile's
    /// subfolder may be, is found open; on Windows the inherited list of the temporary folder
    /// grants at least one principal besides the owner, SYSTEM and the Administrators.
    #[cfg(windows)]
    #[test]
    fn a_file_left_open_names_who_else_may_read_it() {
        let dir = scratch("open");
        let file = dir.join("open");
        std::fs::write(&file, b"secret").expect("written");
        // The test cannot rely on what the runner's temporary folder grants: it grants
        // `Users` explicitly instead, through a fresh unprotected file under a restricted folder
        // whose list is replaced by `icacls`.
        let granted = std::process::Command::new("icacls")
            .arg(&file)
            .args(["/grant", "*S-1-5-32-545:R"])
            .output()
            .expect("icacls runs");
        assert!(granted.status.success(), "{granted:?}");
        let beyond = access_beyond_owner(&file).expect("read");
        assert!(beyond.iter().any(|sid| sid == "S-1-5-32-545"), "{beyond:?}");
        restrict_to_owner(&file).expect("restricted");
        assert_eq!(
            access_beyond_owner(&file).expect("read"),
            Vec::<String>::new()
        );
    }
}
