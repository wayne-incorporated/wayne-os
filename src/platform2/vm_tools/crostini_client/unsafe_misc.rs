// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module contains all the unsafe code necessary for this crate.

use std::ffi::CString;
use std::mem::zeroed;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use libc::{__errno_location, statvfs64, EINTR, EINVAL};

/// Gets free disk space in bytes on the filesystem that contains `path`. Returns a positive `errno`
/// on failure.
pub fn get_free_disk_space<P: AsRef<Path>>(path: P) -> Result<u64, i32> {
    let path_cstr = CString::new(path.as_ref().as_os_str().as_bytes()).or(Err(EINVAL))?;

    // Safe because `stats` is never accessed until after being initialized by the `statvfs64` call
    // returns successfully.
    let mut stats: statvfs64 = unsafe { zeroed() };
    let mut errno = EINTR;
    while errno == EINTR {
        // Safe because a valid C-style string is passed in, along with the correct type of mutable
        // pointer for returned data. The return value is also checked for errors.
        unsafe {
            if statvfs64(path_cstr.as_ptr(), &mut stats) == 0 {
                // This clippy override is needed because the type of `stats.f_frsize` is sometimes
                // `u64` depending on the target architecture.
                #[cfg_attr(feature = "cargo-clippy", allow(identity_conversion))]
                return Ok(stats.f_bavail.saturating_mul(u64::from(stats.f_frsize)));
            }
            errno = *__errno_location();
        }
    }

    Err(errno)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libc::ENOENT;
    use std::process::Command;

    #[test]
    #[ignore]
    fn same_as_df() {
        let free_bytes = get_free_disk_space(".").expect("failed to get free disk space");
        let df_free_bytes = String::from_utf8(
            Command::new("df")
                .args(&["--output=avail", "--block-size=1", "."])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        println!("get_free_disk_space reports {}", free_bytes);
        println!("df reports {}", df_free_bytes);
        assert!(df_free_bytes.trim().ends_with(&format!("{}", free_bytes)));
    }

    #[test]
    fn invalid_nul() {
        assert_eq!(get_free_disk_space("./\0"), Err(EINVAL));
    }

    #[test]
    fn no_such_path() {
        assert_eq!(
            get_free_disk_space("/this/path/should/not/exist"),
            Err(ENOENT)
        );
    }
}
