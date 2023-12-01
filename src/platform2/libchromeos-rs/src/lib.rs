// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Re-export for CrOS.
pub use crosvm_base as sys;
pub use crosvm_base::unix::panic_handler;

// Exports dependencies which are locked to `crosvm_base` versions. This allows us to have a single
// point of declaration for these, rather than N.
pub mod sys_deps {
    pub use zerocopy;
}

#[cfg(feature = "chromeos-module")]
pub mod chromeos;

// Fallback dev-mode check if vboot_reference is not available.
#[cfg(not(feature = "chromeos-module"))]
pub mod chromeos {
    use std::fs::read_to_string;
    use std::io;
    use std::path::Path;

    use thiserror::Error as ThisError;

    #[derive(ThisError, Debug)]
    pub enum Error {
        #[error("failed to get kernel command line: {0}")]
        ReadError(io::Error),
    }

    pub type Result<R> = std::result::Result<R, Error>;

    pub fn is_dev_mode() -> Result<bool> {
        let contents = read_to_string(Path::new("/proc/cmdline")).map_err(Error::ReadError)?;
        Ok(contents.split(' ').any(|token| token == "cros_debug"))
    }
}

pub mod deprecated;
pub mod rand;
pub mod scoped_path;
pub mod secure_blob;
pub mod syslog;

use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixDatagram;

use libc::{socketpair, AF_UNIX, FIOCLEX, SOCK_SEQPACKET};
use sys::unix::ioctl;

pub fn new_seqpacket_pair() -> sys::Result<(UnixDatagram, UnixDatagram)> {
    let mut fds = [0, 0];
    // Safe because fds is owned and the return value is checked.
    let ret = unsafe { socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds.as_mut_ptr()) };
    if ret != 0 {
        return Err(sys::Error::last());
    }

    // Safe because the file descriptors aren't owned yet.
    let first = unsafe { UnixDatagram::from_raw_fd(fds[0]) };
    let second = unsafe { UnixDatagram::from_raw_fd(fds[1]) };

    // Set FD_CLOEXEC. Safe because this will not fail since the fds are valid.
    unsafe {
        ioctl(&first, FIOCLEX);
        ioctl(&second, FIOCLEX);
    }

    Ok((first, second))
}
