// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Utilities from reading from and writing to /dev/kmsg.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use std::rc::Rc;
use std::str::FromStr;

use anyhow::Result;
use chrono::Local;
use libchromeos::sys::handle_eintr;

use crate::linux::events::EventSource;
use crate::linux::events::Mutator;
use crate::linux::events::RemoveFdMutator;
use crate::linux::syslog::Facility;
use crate::linux::syslog::Priority;

pub const KMSG_PATH: &str = "/dev/kmsg";
const MAX_KMSG_RECORD: usize = 4096;

pub trait SyslogForwarder {
    fn forward(&self, data: Vec<u8>);
}

pub trait SyslogForwarderMut {
    fn forward(&mut self, data: Vec<u8>);
}

impl<R: SyslogForwarderMut> SyslogForwarder for RefCell<R> {
    fn forward(&self, data: Vec<u8>) {
        self.borrow_mut().forward(data);
    }
}

pub struct KmsgReader {
    kmsg: File,
    fwd: Rc<dyn SyslogForwarder>,
}

impl KmsgReader {
    pub fn new(kmsg_path: &str, fwd: Rc<dyn SyslogForwarder>) -> Result<Self, io::Error> {
        Ok(KmsgReader {
            kmsg: File::open(kmsg_path)?,
            fwd,
        })
    }

    fn handle_record(&mut self, data: &[u8]) {
        let raw = String::from_utf8_lossy(data);
        let rec = KmsgRecord::from(raw.as_ref());
        let priority = match &rec {
            KmsgRecord::NoPrefix(_) => Priority::Error as u8,
            KmsgRecord::BadPrefix(_, _) => Priority::Error as u8,
            KmsgRecord::Valid(prefix, _) => {
                let prifac = u8::from_str(prefix.prifac).unwrap_or(0);
                let pri = prifac & 7;
                let fac = prifac & (!7);
                // Skip user messages as they've already been forwarded.
                if fac == (Facility::User as u8) {
                    return;
                }
                pri
            }
        };
        // We use the LOG_LOCAL0 syslog facility since only the kernel is
        // allowed to use LOG_KERNEL, and as far as rsyslog is concerned these
        // messages are coming from a user process. The priority is passed
        // through unchanged.
        let prifac: u8 = (Facility::Local0 as u8) & priority;
        let ts = Local::now().format("%b %d %H:%M:%S").to_string();

        // This format seems totally undocumented. It is subtly different from
        // the RFC 5424 format used for logging over TCP/UDP.
        self.fwd.forward(
            format!("<{}>{} hypervisor[0]: {}", prifac, ts, rec)
                .as_bytes()
                .to_vec(),
        );
    }
}

impl Debug for KmsgReader {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KmsgReader")
            .field("kmsg", &self.kmsg)
            .finish()
    }
}

impl AsRawFd for KmsgReader {
    fn as_raw_fd(&self) -> RawFd {
        self.kmsg.as_raw_fd()
    }
}

impl EventSource for KmsgReader {
    fn on_event(&mut self) -> Result<Option<Box<dyn Mutator>>, String> {
        let mut buffer: [u8; MAX_KMSG_RECORD] = [0; MAX_KMSG_RECORD];
        Ok(match handle_eintr!(self.kmsg.read(&mut buffer)) {
            Ok(len) => {
                self.handle_record(&buffer[..len].to_vec());
                None
            }
            // handle EPIPE: we missed some messages
            // Err(EPIPE) => self.fwd.forward("buffer[..len].to_vec());,
            Err(_) => Some(Box::new(RemoveFdMutator(self.as_raw_fd()))),
        })
    }
}

// Format a microsecond timestamp the same way as the kernel.
// See the test for examples of expected output.
fn format_kernel_ts(micros: &str) -> String {
    if micros.len() <= 6 {
        format!("[    0.{:0>6}]", micros)
    } else {
        let pt = micros.len() - 6; // Location of decimal point
        let (secs, micros) = micros.split_at(pt);
        format!("[{:>5}.{}]", secs, micros)
    }
}

#[allow(dead_code)]
struct KmsgPrefix<'a> {
    prifac: &'a str,
    seq: &'a str,
    timestamp_us: &'a str,
    flags: &'a str,
}

enum KmsgRecord<'a> {
    Valid(KmsgPrefix<'a>, &'a str),
    BadPrefix(&'a str, &'a str),
    NoPrefix(&'a str),
}

impl<'a> From<&'a str> for KmsgRecord<'a> {
    fn from(raw: &'a str) -> Self {
        // Data consists of "prefix;message".
        // Prefix consists of "priority+facility,seq,timestamp_us,flags".
        // Ref: https://www.kernel.org/doc/Documentation/ABI/testing/dev-kmsg
        match raw.split_once(';') {
            None => KmsgRecord::NoPrefix(raw),
            Some((prefix, msg)) => {
                let parts: Vec<&str> = prefix.split(',').collect();
                match parts.len() {
                    4 => KmsgRecord::Valid(
                        KmsgPrefix {
                            prifac: parts[0],
                            seq: parts[1],
                            timestamp_us: parts[2],
                            flags: parts[3],
                        },
                        msg,
                    ),
                    _ => KmsgRecord::BadPrefix(prefix, msg),
                }
            }
        }
    }
}

impl fmt::Display for KmsgRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Produce something reasonable, even if the message cant be parsed.
        match self {
            KmsgRecord::NoPrefix(s) => write!(f, "[nopfx] {}", escape(s)),
            KmsgRecord::BadPrefix(s, msg) => write!(f, "[{}] {}", escape(s), escape(msg)),
            KmsgRecord::Valid(prefix, msg) => {
                write!(
                    f,
                    "{} {}",
                    format_kernel_ts(prefix.timestamp_us),
                    escape(msg)
                )
            }
        }
    }
}

/// Escape strings for logging.
///
/// Replace ASCII control characters and non-ASCII characters with escape
/// sequences using char::escape_default(). Also remove one trailing newline.
/// Note: Even though kmesg docs claim that the kernel escapes unprintable
/// characters, that does not seem to be true in practice.
pub fn escape(line: &str) -> String {
    let mut result = String::with_capacity(line.len() + 10);
    for c in line.strip_suffix('\n').unwrap_or(line).chars() {
        if c.is_ascii() && !c.is_ascii_control() {
            result.push(c);
        } else {
            result.extend(c.escape_default());
        }
    }
    result
}

pub fn kmsg_tail(nbytes: usize) -> Result<VecDeque<String>> {
    // Estimate number of lines based on 80 chars per line.
    let mut lines: VecDeque<String> = VecDeque::with_capacity(nbytes / 80);
    let mut size: usize = 0;
    let mut buffer: [u8; MAX_KMSG_RECORD] = [0; MAX_KMSG_RECORD];
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(KMSG_PATH)?;
    while let Ok(n) = handle_eintr!(f.read(&mut buffer)) {
        let data = String::from_utf8_lossy(&buffer[..n]);
        let msg = format!("{}", KmsgRecord::from(data.as_ref()));
        size += msg.len();
        lines.push_back(msg);
        while size > nbytes {
            size -= lines.front().unwrap().len();
            lines.pop_front();
        }
    }
    Ok(lines)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[rustfmt::skip]
    fn format_timestamp() {
        assert_eq!(format_kernel_ts("0"),             "[    0.000000]");
        assert_eq!(format_kernel_ts("1"),             "[    0.000001]");
        assert_eq!(format_kernel_ts("123"),           "[    0.000123]");
        assert_eq!(format_kernel_ts("123456"),        "[    0.123456]");
        assert_eq!(format_kernel_ts("1234567"),       "[    1.234567]");
        assert_eq!(format_kernel_ts("123456789"),     "[  123.456789]");
        assert_eq!(format_kernel_ts("123456123456"), "[123456.123456]");
    }

    #[test]
    fn log_escape() {
        assert_eq!(escape("Hello, World!\n"), "Hello, World!");
        assert_eq!(
            escape("I said, \"It wasn't me.\""),
            "I said, \"It wasn't me.\""
        );
        assert_eq!(
            escape("So... tabs(\t) or spaces(\u{20})?"),
            "So... tabs(\\t) or spaces( )?"
        );
        assert_eq!(
            escape("When is a \0 not a NULL?\n\n"),
            "When is a \\u{0} not a NULL?\\n"
        );
        assert_eq!(escape("α is for Alpha"), "\\u{3b1} is for Alpha");
        assert_eq!(escape("♥"), "\\u{2665}");
    }
}
