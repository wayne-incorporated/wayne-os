// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Log backend for the installer. This backend outputs logs to:
//!
//! - The syslog.
//!
//! - A file log that only includes the current run. This is used to
//!   send back the install log via dbus signal when an error occurs.

use std::fs;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Error};
use chrono::{DateTime, Local};
use lazy_static::lazy_static;
use libchromeos::deprecated::syslog;
use log::{error, Level, Log, Metadata, Record};

const LOG_NAME: &str = "os_install_service.log";

const MAX_LEVEL: Level = Level::Debug;

/// Format a local time and record.
///
/// Example output:
///
///    [2020-12-11 13:02:27.435] src/file.rs:123 ERROR: some message
///
/// (With a newline at the end.)
fn format_time_and_record(when: DateTime<Local>, record: &Record) -> String {
    // Substitute '?' for file and line if they are not set.
    let file = record.file().unwrap_or("?");
    let line = record
        .line()
        .map(|l| l.to_string())
        .unwrap_or_else(|| "?".to_string());

    format!(
        "[{}] {}:{} {}: {}\n",
        when.format("%Y-%m-%-d %H:%M:%S%.3f"),
        file,
        line,
        record.level(),
        record.args()
    )
}

struct Inner {
    /// The instance log includes only logs from the current
    /// run of the installer.
    file_log: File,

    /// Directory containing the log file.
    dir: PathBuf,
}

impl Inner {
    fn open(dir: &Path) -> Result<Self, Error> {
        let log_path = dir.join(LOG_NAME);
        Ok(Self {
            file_log: File::create(&log_path)
                .context(format!("failed to create {}", log_path.display()))?,
            dir: dir.into(),
        })
    }

    fn write(&mut self, record: &Record) {
        let syslog_priority = match record.level() {
            Level::Error => syslog::Priority::Error,
            Level::Warn => syslog::Priority::Warning,
            Level::Info => syslog::Priority::Info,
            Level::Debug => syslog::Priority::Debug,
            // Send trace to debug as well.
            Level::Trace => syslog::Priority::Debug,
        };

        syslog::log(
            syslog_priority,
            syslog::Facility::User,
            Some((record.file().unwrap_or("?"), record.line().unwrap_or(0))),
            *record.args(),
        );

        let line = format_time_and_record(Local::now(), record);
        let _ = self.file_log.write_all(line.as_bytes());
    }

    /// Flush the log file.
    fn flush(&mut self) {
        let _ = self.file_log.flush();
    }

    fn read_file_log(&mut self) -> Result<String, io::Error> {
        // Make sure the contents are written out.
        let _ = self.file_log.flush();

        let path = self.dir.join(LOG_NAME);

        // Read as bytes, then do a lossy convert to UTF-8 just in
        // case there's any weird data in the log.
        let log = fs::read(path)?;
        Ok(String::from_utf8_lossy(&log).into())
    }

    fn reset_file_log(&mut self) -> Result<(), io::Error> {
        self.file_log = File::create(self.dir.join(LOG_NAME))?;
        Ok(())
    }
}

#[derive(Default)]
struct InstallLogger {
    inner: Arc<Mutex<Option<Inner>>>,
}

impl InstallLogger {
    fn open(&self, dir: &Path) -> Result<(), Error> {
        let mut guard = self.inner.lock().unwrap();

        *guard = Some(Inner::open(dir)?);

        Ok(())
    }

    fn read_file_log(&self) -> Result<String, Error> {
        let mut guard = self.inner.lock().unwrap();

        let inner = guard
            .as_mut()
            .ok_or_else(|| anyhow!("logger not initialized"))?;

        Ok(inner.read_file_log()?)
    }
}

impl Log for InstallLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= MAX_LEVEL
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let mut guard = self.inner.lock().unwrap();
        if let Some(inner) = guard.as_mut() {
            inner.write(record);
        }
    }

    fn flush(&self) {
        let mut guard = self.inner.lock().unwrap();
        if let Some(inner) = guard.as_mut() {
            inner.flush();
        }
    }
}

lazy_static! {
    static ref LOGGER: InstallLogger = InstallLogger::default();
}

pub fn init(dir: &Path) -> Result<(), Error> {
    syslog::init().unwrap();

    let logger = &*LOGGER;

    logger.open(dir)?;

    log::set_logger(logger)?;
    log::set_max_level(MAX_LEVEL.to_level_filter());
    Ok(())
}

pub fn read_file_log() -> String {
    LOGGER
        .read_file_log()
        .unwrap_or_else(|err| format!("failed to read install log: {}", err))
}

pub fn reset_file_log() {
    let mut guard = LOGGER.inner.lock().unwrap();
    if let Some(inner) = guard.as_mut() {
        if let Err(err) = inner.reset_file_log() {
            error!("failed to reset file log: {}", err);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use chrono::{Duration, TimeZone};

    use super::*;

    #[test]
    fn test_format() {
        let when =
            Local.with_ymd_and_hms(2020, 12, 11, 13, 2, 27).unwrap() + Duration::milliseconds(435);
        let record = Record::builder()
            .args(format_args!("some message"))
            .level(Level::Error)
            .line(Some(123))
            .file(Some("src/file.rs"))
            .build();
        assert_eq!(
            format_time_and_record(when, &record),
            "[2020-12-11 13:02:27.435] src/file.rs:123 ERROR: some message\n"
        );

        // Test behavior if file or line is empty
        let record = Record::builder()
            .args(format_args!("some message"))
            .level(Level::Error)
            .line(None)
            .file(None)
            .build();
        assert_eq!(
            format_time_and_record(when, &record),
            "[2020-12-11 13:02:27.435] ?:? ERROR: some message\n"
        );
    }

    /// Get the message parts of each log line.
    fn parse_log(path: &Path) -> Result<Vec<String>, Error> {
        let mut messages = Vec::new();
        let log = fs::read_to_string(path)?;
        for line in log.lines() {
            if let Some(msg) = line.splitn(5, ' ').nth(4) {
                messages.push(msg.to_string());
            } else {
                return Err(anyhow!("invalid log line"));
            }
        }
        Ok(messages)
    }

    /// Test the file logger.
    ///
    /// Note: this test directly works with InstallLogger rather than
    /// registering it with the `log` crate and using the log
    /// macros. This is necessary because Rust runs tests in parallel,
    /// and while there are ways to serialize a set of tests with
    /// respect to each other, this doesn't work well with a log
    /// global that might get written to by other tests at any time.
    #[test]
    fn test_logger() -> Result<(), Error> {
        let tmpdir = tempfile::TempDir::new()?;
        let instance = tmpdir.path().join(LOG_NAME);

        // Initialize logger.
        let logger = InstallLogger::default();
        logger.open(tmpdir.path())?;

        let log = |msg| {
            logger.log(&Record::builder().args(format_args!("{}", msg)).build());
        };

        // Write out some logs.
        log("log1");
        log("log2");
        logger.flush();

        // Verify the logs show up in both files.
        assert_eq!(parse_log(&instance)?, ["log1", "log2"]);

        // Simulate a second installation.
        logger.open(tmpdir.path())?;

        // Write out a new log.
        log("log3");
        logger.flush();

        // Verify the new log shows up in both files, but the old logs
        // are gone from the instance log.
        assert_eq!(parse_log(&instance)?, ["log3"]);

        Ok(())
    }
}
