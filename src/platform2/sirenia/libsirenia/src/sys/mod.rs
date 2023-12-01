// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides abstraction for needed libc functionality that isn't included in
//! crosvm-base. Generally Sirenia code outside of this module shouldn't directly
//! interact with the libc package.

use std::fmt::Debug;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::stdin;
use std::io::BufRead;
use std::io::Cursor;
use std::io::Write;
use std::mem::MaybeUninit;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::RawFd;
use std::process::Command;
use std::ptr::null_mut;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use libc::c_int;
use libc::isatty;
use libc::sigfillset;
use libc::sigprocmask;
use libc::sigset_t;
use libc::wait;
use libc::ECHILD;
use libc::SIG_BLOCK;
use libc::SIG_UNBLOCK;
use libchromeos::sys::add_fd_flags;
use libchromeos::sys::handle_eintr;
use libchromeos::sys::Terminal;
use log::error;

use crate::linux::poll::PollContext;
use crate::linux::poll::WatchingEvents;

const CBMEM_CMD: &str = "cbmem";

pub struct ScopedRaw {}

impl ScopedRaw {
    pub fn new() -> Result<Self, libchromeos::sys::Error> {
        stdin().set_raw_mode().map(|_| ScopedRaw {})
    }
}

impl Drop for ScopedRaw {
    fn drop(&mut self) {
        if let Err(err) = stdin().set_canon_mode() {
            error!("Failed exit raw stdin: {}", err);
        }
    }
}

pub fn errno() -> c_int {
    io::Error::last_os_error().raw_os_error().unwrap()
}

pub fn wait_for_child() -> bool {
    let mut ret: c_int = 0;
    // This is safe because it merely blocks execution until a process
    // life-cycle event occurs, or there are no child processes to wait on.
    if unsafe { wait(&mut ret) } == -1 && errno() == ECHILD {
        return false;
    }

    true
}

pub fn block_all_signals() {
    let mut signal_set: sigset_t;
    // This is safe as long as nothing else is depending on receiving a signal
    // to guarantee safety.
    unsafe {
        signal_set = MaybeUninit::zeroed().assume_init();
        // Block signals since init should not die or return.
        sigfillset(&mut signal_set);
        sigprocmask(SIG_BLOCK, &signal_set, null_mut());
    }
}

pub fn unblock_all_signals() {
    let mut signal_set: sigset_t;
    // This is safe because it doesn't allocate or free any structures.
    unsafe {
        signal_set = MaybeUninit::zeroed().assume_init();
        // Block signals since init should not die or return.
        sigfillset(&mut signal_set);
        sigprocmask(SIG_UNBLOCK, &signal_set, null_mut());
    }
}

/// Forks the process and returns the child pid or 0 for the child process.
///
/// # Safety
///
/// This is only safe if the open file descriptors are intended to be cloned
/// into the child process. The child should explicitly close any file
/// descriptors that are not intended to be kept open.
pub unsafe fn fork() -> Result<i32, io::Error> {
    // Safe if the conditions for calling the outer function are met.
    let ret: c_int = unsafe { libc::fork() };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Light wrapper over the dup syscall.
///
/// Provides safety by ensuring the resulting file descriptor is owned.
pub fn dup<F: FromRawFd>(fd: RawFd) -> Result<F, io::Error> {
    // Safe because this doesn't modify any memory and we check the return value
    // and take ownership of the resulting file descriptor in an `F`.
    let dup_fd: c_int = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if dup_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { F::from_raw_fd(dup_fd as RawFd) })
}

pub fn is_a_tty(fd: RawFd) -> bool {
    // This is trivially safe.
    unsafe { isatty(fd) != 0 }
}

pub fn get_a_pty() -> Result<(File, File), anyhow::Error> {
    let main: RawFd = unsafe { libc::getpt() };
    if main < 0 {
        Err(io::Error::last_os_error()).context("bad pty")?;
    }

    let main = unsafe { File::from_raw_fd(main) };

    if unsafe { libc::grantpt(main.as_raw_fd()) } < 0 {
        Err(io::Error::last_os_error()).context("grantpt")?;
    }

    if unsafe { libc::unlockpt(main.as_raw_fd()) } < 0 {
        Err(io::Error::last_os_error()).context("unlockpt")?;
    }

    let name = unsafe { libc::ptsname(main.as_raw_fd()) };
    if name.is_null() {
        Err(io::Error::last_os_error()).context("ptsname")?;
    }

    let client: RawFd = unsafe { libc::open(name, libc::O_RDWR) };
    if client < 0 {
        Err(io::Error::last_os_error()).context("failed to open pty client")?;
    }
    let client = unsafe { File::from_raw_fd(client) };
    Ok((main, client))
}

pub fn dev_null() -> Result<File, io::Error> {
    OpenOptions::new().write(true).read(true).open("/dev/null")
}

/// Halts the system.
pub fn halt() -> Result<(), io::Error> {
    // Safe because sync is called prior to reboot and the error code is checked.
    let ret: c_int = unsafe {
        libc::sync();
        libc::reboot(libc::LINUX_REBOOT_CMD_HALT)
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        // This should never happen.
        Ok(())
    }
}

/// Reboots the system.
pub fn power_off() -> Result<(), io::Error> {
    // Safe because sync is called prior to reboot and the error code is checked.
    let ret: c_int = unsafe {
        libc::sync();
        libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF)
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        // This should never happen.
        Ok(())
    }
}

/// Powers off the system.
pub fn reboot() -> Result<(), io::Error> {
    // Safe because sync is called prior to reboot and the error code is checked.
    let ret: c_int = unsafe {
        libc::sync();
        libc::reboot(libc::LINUX_REBOOT_CMD_RESTART)
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        // This should never happen.
        Ok(())
    }
}

pub fn set_nonblocking(fd: RawFd) -> Result<(), libchromeos::sys::Error> {
    add_fd_flags(fd, libc::O_NONBLOCK)
}

pub fn eagain_is_ok<T>(ret: Result<T, io::Error>) -> Result<Option<T>, io::Error> {
    Ok(match ret {
        Ok(v) => Some(v),
        Err(err) => {
            if matches!(err.raw_os_error(), Some(libc::EAGAIN)) {
                None
            } else {
                return Err(err);
            }
        }
    })
}

pub fn write_all_blocking<W: Write + AsRawFd>(write: &mut W, buf: &[u8]) -> Result<(), io::Error> {
    let mut poll: Option<PollContext<()>> = None;
    let mut offset = 0usize;
    while offset < buf.len() {
        match handle_eintr!(write.write(&buf[offset..])) {
            Ok(written) => {
                offset += written;
            }
            Err(err) => {
                if matches!(err.raw_os_error(), Some(libc::EAGAIN)) {
                    // Lazy initialization is used to avoid getting a poll fd if it is not needed.
                    let poll = match &mut poll {
                        Some(p) => p,
                        None => {
                            let p = PollContext::new()?;
                            let events = WatchingEvents::empty().set_write();
                            p.add_fd_with_events(write, events, ())?;
                            poll = Some(p);
                            poll.as_mut().unwrap()
                        }
                    };
                    poll.wait()?;
                } else {
                    return Err(err);
                }
            }
        }
    }
    Ok(())
}

// Coreboot uses the CBMEM memory area to dynamically allocate data structures
// that remain resident. For example, console log, boot timestamps, etc.
#[derive(Debug, PartialEq)]
pub struct CbmemEntry {
    pub name: String,
    pub id: String,
    pub start: u64,
    pub size: usize,
}

impl CbmemEntry {
    fn parse_cmd_output_line(line: &str) -> Result<CbmemEntry> {
        // Example line:
        //     NAME        ID        START      LENGTH
        //  3. RW MCACHE   574d5346  76adc000   0000043c
        let parts: Vec<&str> = line.split_ascii_whitespace().collect();
        let nparts = parts.len();
        if nparts < 5 {
            bail!("Invalid line: {}", line);
        }
        let name = parts[1..nparts - 3].join(" ");
        let id = parts[nparts - 3].to_string();
        let size = usize::from_str_radix(parts[nparts - 1], 16)
            .map_err(|_| anyhow!("Invalid length: {}", line))?;
        let start = u64::from_str_radix(parts[nparts - 2], 16)
            .map_err(|_| anyhow!("Invalid start address: {}", line))?;
        Ok(CbmemEntry {
            name,
            id,
            start,
            size,
        })
    }

    fn parse_cmd_output<E: Debug, R: Iterator<Item = Result<String, E>>>(
        mut reader: R,
    ) -> Result<Vec<CbmemEntry>> {
        // The first two lines are headers
        reader.next();
        reader.next();
        let mut entries = Vec::new();
        for line in reader {
            entries.push(CbmemEntry::parse_cmd_output_line(&line.unwrap())?);
        }
        Ok(entries)
    }
}

// Returns the CBMEM table of contents. Equivalent to "cbmem -l"
pub fn get_cbmem_toc() -> Result<Vec<CbmemEntry>> {
    let output = Command::new(CBMEM_CMD)
        .arg("-l")
        .output()
        .expect("failed to execute cbmem");
    if !output.status.success() {
        bail!(
            "cbmem failed: {} out={:?} err={:?}",
            output.status,
            output.stdout,
            output.stderr
        );
    }
    CbmemEntry::parse_cmd_output(Cursor::new(output.stdout).lines())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_cbmem_line() {
        assert_eq!(
            CbmemEntry::parse_cmd_output_line(" 0. FSP MEMORY  46535052  76afe000   00500000\n")
                .unwrap(),
            CbmemEntry {
                name: "FSP MEMORY".to_string(),
                id: "46535052".to_string(),
                start: 0x76afe000,
                size: 0x500000,
            }
        );
        assert_eq!(
            CbmemEntry::parse_cmd_output_line(" 1. CONSOLE     434f4e53  76ade000   00020000\n")
                .unwrap(),
            CbmemEntry {
                name: "CONSOLE".to_string(),
                id: "434f4e53".to_string(),
                start: 0x76ade000,
                size: 0x20000,
            }
        );
        assert_eq!(
            CbmemEntry::parse_cmd_output_line(
                "12. CHROMEOS NVS        434e5653  76a31000   00000f00\n"
            )
            .unwrap(),
            CbmemEntry {
                name: "CHROMEOS NVS".to_string(),
                id: "434e5653".to_string(),
                start: 0x76a31000,
                size: 0xf00,
            }
        );
        assert_eq!(
            CbmemEntry::parse_cmd_output_line("25. a b d c  e WEIRD_ID  76ffeae0   0000000c")
                .unwrap(),
            CbmemEntry {
                name: "a b d c e".to_string(),
                id: "WEIRD_ID".to_string(),
                start: 0x76ffeae0,
                size: 0xc,
            }
        );
        assert_eq!(
            CbmemEntry::parse_cmd_output_line("1 n i 0 1").unwrap(),
            CbmemEntry {
                name: "n".to_string(),
                id: "i".to_string(),
                start: 0,
                size: 1,
            }
        );
        assert!(CbmemEntry::parse_cmd_output_line("").is_err());
        assert!(CbmemEntry::parse_cmd_output_line("a b c d").is_err());
        assert!(CbmemEntry::parse_cmd_output_line("1 n i vv 0").is_err());
        assert!(CbmemEntry::parse_cmd_output_line("1 n i 0 vv").is_err());
    }

    #[test]
    fn parse_cbmem_list() {
        let cbmem_out = b"CBMEM table of contents:
   NAME          ID           START      LENGTH
0. FSP MEMORY  46535052  76afe000   00500000
1. CONSOLE     434f4e53  76ade000   00020000
2. VPD         56504420  76add000   000003ba
3. RW MCACHE   574d5346  76adc000   0000043c";
        assert_eq!(
            CbmemEntry::parse_cmd_output(Cursor::new(cbmem_out).lines()).unwrap(),
            vec![
                CbmemEntry {
                    name: "FSP MEMORY".to_string(),
                    id: "46535052".to_string(),
                    start: 0x76afe000,
                    size: 0x500000,
                },
                CbmemEntry {
                    name: "CONSOLE".to_string(),
                    id: "434f4e53".to_string(),
                    start: 0x76ade000,
                    size: 0x20000,
                },
                CbmemEntry {
                    name: "VPD".to_string(),
                    id: "56504420".to_string(),
                    start: 0x76add000,
                    size: 0x000003ba,
                },
                CbmemEntry {
                    name: "RW MCACHE".to_string(),
                    id: "574d5346".to_string(),
                    start: 0x76adc000,
                    size: 0x0000043c,
                },
            ]
        );
    }
}
