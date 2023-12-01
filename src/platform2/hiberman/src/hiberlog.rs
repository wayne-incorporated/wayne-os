// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implement consistent logging across the hibernate and resume transition.
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Cursor;
use std::io::Read;
use std::io::Write;
use std::mem;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::str;
use std::sync::MutexGuard;
use std::time::Instant;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use log::debug;
use log::warn;
use log::Level;
use log::LevelFilter;
use log::Log;
use log::Metadata;
use log::Record;
use once_cell::sync::OnceCell;
use sync::Mutex;
use syslog::BasicLogger;
use syslog::Facility;
use syslog::Formatter3164;

use crate::files::HIBERMETA_DIR;
use crate::hiberutil::HibernateStage;

/// Define the path to kmsg, used to send log lines into the kernel buffer in
/// case a crash occurs.
const KMSG_PATH: &str = "/dev/kmsg";
/// Define the prefix to go on log messages.
const LOG_PREFIX: &str = "hiberman";

/// Define the name of the resume log file.
const RESUME_LOG_FILE_NAME: &str = "resume_log";
/// Define the name of the suspend log file.
const SUSPEND_LOG_FILE_NAME: &str = "suspend_log";

static STATE: OnceCell<Mutex<Hiberlog>> = OnceCell::new();

fn get_state() -> Result<&'static Mutex<Hiberlog>> {
    STATE.get_or_try_init(|| Hiberlog::new().map(Mutex::new))
}

fn lock() -> Result<MutexGuard<'static, Hiberlog>> {
    get_state().map(Mutex::lock)
}

/// Initialize the syslog connection and internal variables.
pub fn init() -> Result<()> {
    // Warm up to initialize the state.
    let _ = get_state()?;
    log::set_boxed_logger(Box::new(HiberLogger::new()))
        .map(|()| log::set_max_level(LevelFilter::Debug))?;
    Ok(())
}

// Attempts to lock and retrieve the state. Returns from the function silently on failure.
macro_rules! lock {
    () => {
        match lock() {
            Ok(s) => s,
            _ => return,
        }
    };
}

/// Define the instance that gets handed to the logging crate.
struct HiberLogger {}

impl HiberLogger {
    pub fn new() -> Self {
        HiberLogger {}
    }
}

impl Log for HiberLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let mut state = lock!();
        state.log_record(record)
    }

    fn flush(&self) {
        // nothing to do with O_SYNC files.
    }
}

/// Define the possibilities as to where to route log lines to.
pub enum HiberlogOut {
    /// Don't push log lines anywhere for now, just keep them in memory.
    BufferInMemory,
    /// Push log lines to the syslogger.
    Syslog,
    /// Push log lines to a File-like object.
    File(Box<dyn Write + Send>),
}

/// Define the (singleton) hibernate logger state.
struct Hiberlog {
    kmsg: File,
    start: Instant,
    pending: Vec<Vec<u8>>,
    pending_size: usize,
    to_kmsg: bool,
    out: HiberlogOut,
    pid: u32,
    syslogger: BasicLogger,
    is_empty: bool,
}

impl Hiberlog {
    pub fn new() -> Result<Self> {
        let kmsg = OpenOptions::new()
            .read(true)
            .write(true)
            .open(KMSG_PATH)
            .context("Failed to open kernel message logger")?;

        let syslogger = create_syslogger();
        Ok(Hiberlog {
            kmsg,
            start: Instant::now(),
            pending: vec![],
            pending_size: 0,
            to_kmsg: false,
            out: HiberlogOut::Syslog,
            pid: std::process::id(),
            syslogger,
            is_empty: true,
        })
    }

    /// Log a record.
    fn log_record(&mut self, record: &Record) {
        let mut buf = [0u8; 1024];
        self.is_empty = false;

        // If sending to the syslog, just forward there and exit.
        if matches!(self.out, HiberlogOut::Syslog) {
            self.syslogger.log(record);
            return;
        }

        let res = {
            let mut buf_cursor = Cursor::new(&mut buf[..]);
            let facprio = priority_from_level(record.level()) + (Facility::LOG_USER as usize);
            if let Some(file) = record.file() {
                let duration = self.start.elapsed();
                write!(
                    &mut buf_cursor,
                    "<{}>{}: {}.{:03} {} [{}:{}] ",
                    facprio,
                    LOG_PREFIX,
                    duration.as_secs(),
                    duration.subsec_millis(),
                    self.pid,
                    file,
                    record.line().unwrap_or(0)
                )
            } else {
                write!(&mut buf_cursor, "<{}>{}: ", facprio, LOG_PREFIX)
            }
            .and_then(|()| writeln!(&mut buf_cursor, "{}", record.args()))
            .map(|()| buf_cursor.position() as usize)
        };

        if let Ok(len) = &res {
            if self.to_kmsg {
                let _ = self.kmsg.write_all(&buf[..*len]);
            }

            if let HiberlogOut::File(f) = &mut self.out {
                let _ = f.write_all(&buf[..*len]);
            } else {
                self.pending.push(buf[..*len].to_vec());
                self.pending_size += *len;
            }
        }
    }

    /// Write any ending lines to the file.
    fn flush_to_file(&mut self) {
        if let HiberlogOut::File(f) = &mut self.out {
            flush_to_backend(&self.pending, |s| {
                f.write_all(s.as_bytes()).unwrap();
                f.write_all(&[b'\n']).unwrap();
            });

            self.reset();
        } else {
            panic!("current log backend is not a file");
        }
    }

    /// Push any pending lines to the syslog.
    fn flush_to_syslog(&mut self) {
        flush_to_backend(&self.pending, |s| {
            replay_line(&self.syslogger, "M", s.to_string());
        });

        self.reset();
    }

    /// Empty the pending log buffer, discarding any unwritten messages. This is
    /// used after a successful resume to avoid replaying what look like
    /// unflushed logs from when the snapshot was taken. In reality these logs
    /// got flushed after the snapshot was taken, just before the machine shut
    /// down.
    pub fn reset(&mut self) {
        self.pending_size = 0;
        self.pending = vec![];
        self.is_empty = true;
    }
}

fn flush_to_backend<F>(line_data: &Vec<Vec<u8>>, mut write_func: F)
where
    F: FnMut(&str),
{
    for line_vec in line_data {
        let mut len = line_vec.len();
        if len == 0 {
            continue;
        }

        len -= 1;
        let s = match str::from_utf8(&line_vec[0..len]) {
            Ok(v) => v,
            Err(_) => continue,
        };

        write_func(s);
    }
}

/// Struct with associated functions for creating and opening hibernate
/// log files.
pub struct LogFile {}

impl LogFile {
    /// Create the log file with the given path, truncate the file if it already
    /// exists. The file is opened with O_SYNC to make sure data from writes
    /// isn't buffered by the kernel but submitted to storage immediately.
    pub fn create<P: AsRef<Path>>(path: P) -> Result<File> {
        let opts = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .custom_flags(libc::O_SYNC)
            .clone();

        Self::open_file(path, &opts)
    }

    /// Open an existing log file at the given path. The file is opened with
    /// O_SYNC to make sure data from writes isn't buffered by the kernel but
    /// submitted to storage immediately.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<File> {
        Self::open_file(
            path,
            OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_SYNC),
        )
    }

    /// Get the path of the log file for a given hibernate stage.
    pub fn get_path(stage: HibernateStage) -> PathBuf {
        let name = match stage {
            HibernateStage::Suspend => SUSPEND_LOG_FILE_NAME,
            HibernateStage::Resume => RESUME_LOG_FILE_NAME,
        };

        Path::new(HIBERMETA_DIR).join(name)
    }

    fn open_file<P: AsRef<Path>>(path: P, open_options: &OpenOptions) -> Result<File> {
        match open_options.open(&path) {
            Ok(f) => Ok(f),
            Err(e) => Err(anyhow!(e).context(format!(
                "Failed to open log file '{}'",
                path.as_ref().display()
            ))),
        }
    }
}

/// Helper struct that redirects the hibernate logs to a buffer in memory
/// when the struct goes out of scope.
///
/// The struct is used during the suspend and resume process to ensure
/// that an open log file is always closed before unmounting 'hibermeta'
/// (which hosts the log file).
pub struct LogRedirectGuard {}

impl LogRedirectGuard {}

impl Drop for LogRedirectGuard {
    fn drop(&mut self) {
        redirect_log(HiberlogOut::BufferInMemory);
    }
}

/// Divert the log to a new output. If the log was previously pointing to syslog
/// or a file, those messages are flushed. If the log was previously being
/// stored in memory, those messages will naturally flush to the given new
/// destination.
pub fn redirect_log(out: HiberlogOut) {
    log::logger().flush();
    let mut state = lock!();
    state.to_kmsg = false;

    let prev_out_was_memory = matches!(state.out, HiberlogOut::BufferInMemory);

    state.out = out;

    match state.out {
        HiberlogOut::Syslog => state.flush_to_syslog(),
        HiberlogOut::File(_) => {
            // Any time we're redirecting to a file, also send to kmsg as a
            // message in a bottle, in case we never get a chance to replay our
            // own file logs. This shouldn't produce duplicate messages on
            // success because when we're logging to a file we're also
            // barrelling towards a kexec or shutdown.
            state.to_kmsg = true;

            if prev_out_was_memory {
                state.flush_to_file();
            }
        }
        _ => {}
    }
}

/// Divert the log to a file. If the log was previously pointing to syslog
/// those messages are flushed.
pub fn redirect_log_to_file(log_file: File) -> LogRedirectGuard {
    redirect_log(HiberlogOut::File(Box::new(log_file)));

    LogRedirectGuard {}
}

/// Discard any buffered but unsent logging data.
pub fn reset_log() {
    let mut state = lock!();
    state.reset();
}

/// Replay the suspend (and maybe resume) logs to the syslogger.
pub fn replay_logs(push_resume_logs: bool, clear: bool) {
    // Push the hibernate logs that were taken after the snapshot (and
    // therefore after syslog became frozen) back into the syslog now.
    // These should be there on both success and failure cases.
    replay_log(HibernateStage::Suspend, clear);

    // If successfully resumed from hibernate, or in the bootstrapping kernel
    // after a failed resume attempt, also gather the resume logs
    // saved by the bootstrapping kernel.
    if push_resume_logs {
        replay_log(HibernateStage::Resume, clear);
    }
}

/// Helper function to replay the suspend or resume log to the syslogger, and
/// potentially zero out the log as well.
fn replay_log(stage: HibernateStage, clear: bool) {
    let (name, prefix) = match stage {
        HibernateStage::Suspend => ("suspend log", "S"),
        HibernateStage::Resume => ("resume log", "R"),
    };

    let path = LogFile::get_path(stage);
    if !path.exists() {
        return;
    }

    let mut opened_log = match LogFile::open(&path) {
        Ok(f) => f,
        Err(e) => {
            warn!("{}", e);
            return;
        }
    };

    replay_log_file(&mut opened_log, prefix, name);

    if clear {
        mem::drop(opened_log);
        if let Err(e) = fs::remove_file(&path) {
            warn!("Failed to remove {}: {}", path.display(), e);
        }
    }
}

/// Replay a generic log file to the syslogger.
fn replay_log_file(file: &mut dyn Read, prefix: &str, name: &str) {
    let reader = BufReader::new(file);

    let syslogger = create_syslogger();
    syslogger.log(
        &Record::builder()
            .args(format_args!("Replaying {}:", name))
            .level(Level::Info)
            .build(),
    );

    for line in reader.lines() {
        if let Ok(line) = line {
            replay_line(&syslogger, prefix, line);
        } else {
            warn!("Invalid line in log file!");
        }
    }

    syslogger.log(
        &Record::builder()
            .args(format_args!("Done replaying {}", name))
            .level(Level::Info)
            .build(),
    );
}

/// Replay a single log line to the syslogger.
fn replay_line(syslogger: &BasicLogger, prefix: &str, line: String) {
    // The log lines are in kmsg format, like:
    // <11>hiberman: R [src/hiberman.rs:529] Hello 2004
    // Trim off the first colon, everything after is line contents.
    if line.is_empty() {
        return;
    }

    let mut elements = line.splitn(2, ": ");
    let header = elements.next().unwrap();
    let contents = match elements.next() {
        Some(c) => c,
        None => {
            warn!(
                "Failed to split on colon: header: {}, line {:x?}, len {}",
                header,
                line.as_bytes(),
                line.len()
            );
            return;
        }
    };

    // Now trim <11>hiberman into <11, and parse 11 out of the combined
    // priority + facility.
    let facprio_string = header.split_once('>').map_or(header, |x| x.0);
    let facprio: u8 = match facprio_string[1..].parse() {
        Ok(i) => i,
        Err(_) => {
            warn!("Failed to parse facprio for next line, using debug");
            debug!("{}", contents);
            return;
        }
    };

    let level = level_from_u8(facprio & 7);
    syslogger.log(
        &Record::builder()
            .args(format_args!("{} {}", prefix, contents))
            .level(level)
            .build(),
    );
}

fn level_from_u8(value: u8) -> Level {
    match value {
        0 => Level::Error,
        1 => Level::Error,
        2 => Level::Error,
        3 => Level::Error,
        4 => Level::Warn,
        5 => Level::Info,
        6 => Level::Info,
        7 => Level::Debug,
        _ => Level::Debug,
    }
}

fn priority_from_level(level: Level) -> usize {
    match level {
        Level::Error => 3,
        Level::Warn => 4,
        Level::Info => 6,
        Level::Debug => 7,
        Level::Trace => 7,
    }
}

fn create_syslogger() -> BasicLogger {
    let formatter = Formatter3164 {
        facility: Facility::LOG_USER,
        hostname: None,
        process: "hiberman".into(),
        pid: std::process::id(),
    };

    let logger = syslog::unix(formatter).expect("Could not connect to syslog");
    BasicLogger::new(logger)
}
