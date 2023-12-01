// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// This program collects fine-grained memory stats around events of interest
// (such as browser tab discards) and saves them in a queue of "clip files",
// to be uploaded with other logs.
//
// The program has two modes: slow and fast poll.  In slow-poll mode, the
// program occasionally checks (every 2 seconds right now) whether it should go
// into fast-poll mode, because interesting events become possible.  When in
// fast-poll mode, the program collects memory stats frequently (every 0.1
// seconds right now) and stores them in a circular buffer.  When "interesting"
// events occur, the stats around each event are saved into a "clip" file.
// These files are also maintained as a queue, so only the latest N clips are
// available (N = 20 right now).

extern crate chrono;
extern crate dbus;
extern crate env_logger;
extern crate libc;
#[macro_use]
extern crate log;
extern crate syslog;
extern crate tempfile;

extern crate protobuf; // needed by proto_include.rs
include!(concat!(env!("OUT_DIR"), "/proto_include.rs"));

use chrono::prelude::*;
use {libc::__errno_location, libc::c_void};

#[cfg(not(test))]
use dbus::{BusType, Connection, WatchEvent};
#[cfg(not(test))]
use protobuf::Message;

use std::cmp::max;
use std::fmt;
use std::fs::{create_dir, File, OpenOptions};
use std::io::prelude::*;
use std::mem::{self, MaybeUninit};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
#[cfg(not(test))]
use std::thread;
use std::{io, str};
// Not to be confused with chrono::Duration or the deprecated time::Duration.
use std::time::Duration;

use tempfile::TempDir;

#[cfg(test)]
mod test;

const PAGE_SIZE: usize = 4096; // old friend

const LOG_DIRECTORY: &str = "/var/log/memd";
const STATIC_PARAMETERS_LOG: &str = "memd.parameters";
const LOW_MEM_SYSFS: &str = "/sys/kernel/mm/chromeos-low_mem";
const LOW_MEM_DEVICE: &str = "/dev/chromeos-low-mem";
const MAX_CLIP_COUNT: usize = 20;

const COLLECTION_DELAY_MS: i64 = 5_000; // Wait after event of interest.
const CLIP_COLLECTION_SPAN_MS: i64 = 10_000; // ms worth of samples in a clip.
const SAMPLES_PER_SECOND: i64 = 10; // Rate of fast sample collection.
const SAMPLING_PERIOD_MS: i64 = 1000 / SAMPLES_PER_SECOND;
// Danger threshold.  When the distance between "available" and "margin" is
// greater than LOW_MEM_DANGER_THRESHOLD_MB, we assume that there's no danger
// of "interesting" events (such as a discard) happening in the next
// SLOW_POLL_PERIOD_DURATION.  In other words, we expect that an allocation of
// more than LOW_MEM_DANGER_THRESHOLD_MB in a SLOW_POLL_PERIOD_DURATION will be
// rare.
const LOW_MEM_DANGER_THRESHOLD_MB: u32 = 600; // Poll fast when closer to margin than this.
const SLOW_POLL_PERIOD_DURATION: Duration = Duration::from_secs(2); // Sleep in slow-poll mode.
const FAST_POLL_PERIOD_DURATION: Duration = Duration::from_millis(SAMPLING_PERIOD_MS as u64); // Sleep duration in fast-poll mode.

// Print a warning if the fast-poll select lasts a lot longer than expected
// (which might happen because of huge load average and swap activity).
const UNREASONABLY_LONG_SLEEP: i64 = 10 * SAMPLING_PERIOD_MS;

// Size of sample queue.  The queue contains mostly timer events, in the amount
// determined by the clip span and the sampling rate.  It also contains other
// events, such as OOM kills etc., whose amount is expected to be smaller than
// the former.  Generously double the number of timer events to leave room for
// non-timer events.
const SAMPLE_QUEUE_LENGTH: usize =
    (CLIP_COLLECTION_SPAN_MS / 1000 * SAMPLES_PER_SECOND * 2) as usize;

// The names of fields of interest in /proc/vmstat.  They must be listed in
// the order in which they appear in /proc/vmstat.  When parsing the file,
// if a mandatory field is missing, the program panics.  A missing optional
// field (for instance, pgmajfault_f for some kernels) results in a value
// of 0. (BAD: This works only for the last field.)
//
// For fields with |accumulate| = true, use the name as a prefix, and add up
// all values with that prefix in consecutive lines.
const VMSTAT_VALUES_COUNT: usize = 5; // Number of vmstat values we're tracking.
#[rustfmt::skip]
const VMSTATS: [(&str, bool, bool); VMSTAT_VALUES_COUNT] = [
    // name                 mandatory   accumulate
    ("pswpin",              true,       false),
    ("pswpout",             true,       false),
    ("pgalloc",             true,       true),   // pgalloc_dma, pgalloc_normal, etc.
    ("pgmajfault",          true,       false),
    ("pgmajfault_f",        false,      false),
];
// The only difference from x86_64 is pgalloc_dma vs. pgalloc_dma32.

#[derive(Debug)]
pub enum Error {
    LowMemFileError(Box<dyn std::error::Error>),
    VmstatFileError(Box<std::io::Error>),
    RunnablesFileError(Box<std::io::Error>),
    AvailableFileError(Box<dyn std::error::Error>),
    CreateLogDirError(Box<std::io::Error>),
    StartingClipCounterMissingError(Box<dyn std::error::Error>),
    LogStaticParametersError(Box<dyn std::error::Error>),
    DbusWatchError(Box<dyn std::error::Error>),
    LowMemFDWatchError(Box<dyn std::error::Error>),
    LowMemWatcherError(Box<dyn std::error::Error>),
    InitSyslogError(Box<dyn std::error::Error>),
}

impl std::error::Error for Error {
    // This function is "soft-deprecated" so
    // we use the fmt() function from Display below.
    fn description(&self) -> &str {
        "memd_error"
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::LowMemFileError(ref e) => write!(f, "cannot opening low-mem file: {}", e),
            Error::VmstatFileError(ref e) => write!(f, "cannot open vmstat: {}", e),
            Error::RunnablesFileError(ref e) => write!(f, "cannot open loadavg: {}", e),
            Error::AvailableFileError(ref e) => write!(f, "cannot open available file: {}", e),
            Error::CreateLogDirError(ref e) => write!(f, "cannot create log directory: {}", e),
            Error::StartingClipCounterMissingError(ref e) => {
                write!(f, "cannot find starting clip counter: {}", e)
            }
            Error::LogStaticParametersError(ref e) => {
                write!(f, "cannot log static parameters: {}", e)
            }
            Error::DbusWatchError(ref e) => write!(f, "cannot watch dbus fd: {}", e),
            Error::LowMemFDWatchError(ref e) => write!(f, "cannot watch low-mem fd: {}", e),
            Error::LowMemWatcherError(ref e) => write!(f, "cannot set low-mem watcher: {}", e),
            Error::InitSyslogError(ref e) => write!(f, "cannot init syslog: {}", e),
        }
    }
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn errno() -> i32 {
    // _errno_location() is trivially safe to call and dereferencing the
    // returned pointer is always safe because it's guaranteed to be valid and
    // point to thread-local data.  (Thanks to Zach for this comment.)
    unsafe { *__errno_location() }
}

// Returns the string for posix error number |err|.
fn strerror(err: i32) -> String {
    let mut buffer = vec![0u8; 128];
    // |err| is valid because it is the libc errno at all call sites.  |buffer|
    // is converted to a valid address, and |buffer.len()| is a valid length.
    let ret = unsafe {
        libc::strerror_r(
            err,
            &mut buffer[0] as *mut u8 as *mut libc::c_char,
            buffer.len(),
        )
    };
    if ret != 0 {
        panic!(
            "strerror_r failed with '{}'; the original error number was '{}'",
            ret, err
        );
    }
    buffer.resize(
        buffer
            .iter()
            .position(|&a| a == 0u8)
            .unwrap_or(buffer.len()),
        0u8,
    );
    match String::from_utf8(buffer) {
        Ok(s) => s,
        Err(e) => {
            // Ouch---an error while trying to process another error.
            // Very unlikely so we just panic.
            panic!("error {:?} converting to UTF8", e);
        }
    }
}

// Opens a file if it exists, otherwise returns none.
fn open_maybe(path: &Path) -> Result<Option<File>> {
    if !path.exists() {
        Ok(None)
    } else {
        Ok(Some(File::open(path)?))
    }
}

// Opens a file with mode flags.  If the file does not exist, returns None.
fn open_with_flags_maybe(path: &Path, options: &OpenOptions) -> Result<Option<File>> {
    if !path.exists() {
        Ok(None)
    } else {
        Ok(Some(options.open(&path)?))
    }
}

// Converts the result of an integer expression |e| to modulo |n|. |e| may be
// negative. This differs from plain "%" in that the result of this function
// is always be between 0 and n-1.
fn modulo(e: isize, n: usize) -> usize {
    let nn = n as isize;
    let x = e % nn;
    (if x >= 0 { x } else { x + nn }) as usize
}

// Reads a string from the file named by |path|, representing a u32, and
// returns the value the strings it represents. If there are multiple ints
// in the file, then it returns the first one.
fn read_int(path: &Path) -> Result<u32> {
    let mut file = File::open(path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content
        .split_whitespace()
        .into_iter()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty file"))?
        .parse::<u32>()?)
}

// The Timer trait allows us to mock time for testing.
trait Timer {
    // A wrapper for libc::select() with only ready-to-read fds.
    fn select(
        &mut self,
        nfds: libc::c_int,
        fds: &mut libc::fd_set,
        timeout: &Duration,
    ) -> libc::c_int;
    fn sleep(&mut self, sleep_time: &Duration);
    fn now(&self) -> i64;
    fn quit_request(&self) -> bool;
}

#[cfg(not(test))]
struct GenuineTimer {}

#[cfg(not(test))]
impl Timer for GenuineTimer {
    // Returns current uptime (active time since boot, in milliseconds)
    fn now(&self) -> i64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // clock_gettime is safe when passed a valid address and a valid enum.
        let result =
            unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts as *mut libc::timespec) };
        assert_eq!(result, 0, "clock_gettime() failed!");
        // Safe because the value was initialized by clock_gettime.
        ts.tv_sec as i64 * 1000 + ts.tv_nsec as i64 / 1_000_000
    }

    // Always returns false, unless testing (see MockTimer).
    fn quit_request(&self) -> bool {
        false
    }

    fn sleep(&mut self, sleep_time: &Duration) {
        thread::sleep(*sleep_time);
    }

    fn select(
        &mut self,
        high_fd: i32,
        inout_read_fds: &mut libc::fd_set,
        timeout: &Duration,
    ) -> i32 {
        let mut libc_timeout = libc::timeval {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_usec: timeout.subsec_micros() as libc::suseconds_t,
        };
        let null = std::ptr::null_mut();
        // Safe because we're passing valid values and addresses.
        unsafe {
            libc::select(
                high_fd,
                inout_read_fds,
                null,
                null,
                &mut libc_timeout as *mut libc::timeval,
            )
        }
    }
}

fn default_fd_set() -> libc::fd_set {
    let mut m = MaybeUninit::<libc::fd_set>::uninit();
    // The fd set don't need to be initialized to known values because
    // they are cleared by the following FD_ZERO calls, which are safe
    // because we're passing libc::fd_sets to them.
    unsafe {
        libc::FD_ZERO(m.as_mut_ptr());
        m.assume_init()
    }
}

struct FileWatcher {
    read_fds: libc::fd_set,
    inout_read_fds: libc::fd_set,
    max_fd: i32,
}

// Interface to the select(2) system call, for ready-to-read only.
impl FileWatcher {
    fn new() -> FileWatcher {
        let read_fds = default_fd_set();
        let inout_read_fds = default_fd_set();
        FileWatcher {
            read_fds,
            inout_read_fds,
            max_fd: -1,
        }
    }

    fn set(&mut self, f: &File) -> Result<()> {
        self.set_fd(f.as_raw_fd())
    }

    // The ..._fd functions exist because other APIs (e.g. dbus) return RawFds
    // instead of Files.
    fn set_fd(&mut self, fd: RawFd) -> Result<()> {
        if fd >= libc::FD_SETSIZE as i32 {
            return Err("set_fd: fd too large".into());
        }
        // see comment for |set()|
        unsafe {
            libc::FD_SET(fd, &mut self.read_fds);
        }
        self.max_fd = max(self.max_fd, fd);
        Ok(())
    }

    fn clear_fd(&mut self, fd: RawFd) -> Result<()> {
        if fd >= libc::FD_SETSIZE as i32 {
            return Err("clear_fd: fd is too large".into());
        }
        // see comment for |set()|
        unsafe {
            libc::FD_CLR(fd, &mut self.read_fds);
        }
        Ok(())
    }

    // Mut self here and below are required (unnecessarily) by FD_ISSET.
    fn has_fired(&mut self, f: &File) -> Result<bool> {
        self.has_fired_fd(f.as_raw_fd())
    }

    fn has_fired_fd(&mut self, fd: RawFd) -> Result<bool> {
        if fd >= libc::FD_SETSIZE as i32 {
            return Err("has_fired_fd: fd is too large".into());
        }
        // see comment for |set()|
        Ok(unsafe { libc::FD_ISSET(fd, &self.inout_read_fds) })
    }

    fn watch(&mut self, timeout: &Duration, timer: &mut dyn Timer) -> Result<usize> {
        self.inout_read_fds = self.read_fds;
        let n = timer.select(self.max_fd + 1, &mut self.inout_read_fds, timeout);
        match n {
            // into() puts the io::Error in a Box.
            -1 => Err(io::Error::last_os_error().into()),
            n => {
                if n < 0 {
                    Err(format!("unexpected return value {} from select", n).into())
                } else {
                    Ok(n as usize)
                }
            }
        }
    }
}

#[derive(Clone, Copy, Default)]
struct Sample {
    uptime: i64, // system uptime in ms
    sample_type: SampleType,
    info: Sysinfo,
    runnables: u32, // number of runnable processes
    available: u32, // available RAM from low-mem notifier
    vmstat_values: [u64; VMSTAT_VALUES_COUNT],
}

impl Sample {
    // Outputs a sample.
    fn output(&self, out: &mut File) -> Result<()> {
        writeln!(
            out,
            "{}.{:02} {:6} {} {} {} {} {} {} {} {} {} {} {}",
            self.uptime / 1000,
            self.uptime % 1000 / 10,
            self.sample_type,
            self.info.0.loads[0],
            self.info.0.freeram,
            self.info.0.freeswap,
            self.info.0.procs,
            self.runnables,
            self.available,
            self.vmstat_values[0],
            self.vmstat_values[1],
            self.vmstat_values[2],
            self.vmstat_values[3],
            self.vmstat_values[4],
        )?;
        Ok(())
    }
}

#[derive(Copy, Clone)]
struct Sysinfo(libc::sysinfo);

// Wrapper for sysinfo syscall.
fn sysinfo() -> Result<Sysinfo> {
    let mut info: Sysinfo = Default::default();
    // sysinfo() is always safe when passed a valid pointer
    match unsafe { libc::sysinfo(&mut info.0 as *mut libc::sysinfo) } {
        0 => Ok(info),
        _ => Err(format!("sysinfo: {}", strerror(errno())).into()),
    }
}

impl Sysinfo {
    // Fakes sysinfo system call, for testing.
    fn fake_sysinfo() -> Result<Sysinfo> {
        let mut info: Sysinfo = Default::default();
        // Any numbers will do.
        info.0.loads[0] = 5;
        info.0.freeram = 42_000_000;
        info.0.freeswap = 84_000_000;
        info.0.procs = 1234;
        Ok(info)
    }
}

impl Default for Sysinfo {
    fn default() -> Sysinfo {
        // safe because sysinfo contains only numbers
        unsafe { mem::zeroed() }
    }
}

struct SampleQueue {
    samples: [Sample; SAMPLE_QUEUE_LENGTH],
    head: usize,  // points to latest entry
    count: usize, // count of valid entries (min=0, max=SAMPLE_QUEUE_LENGTH)
}

impl SampleQueue {
    fn new() -> SampleQueue {
        let s: Sample = Default::default();
        SampleQueue {
            samples: [s; SAMPLE_QUEUE_LENGTH],
            head: 0,
            count: 0,
        }
    }

    // Returns self.head as isize, to make index calculations behave correctly
    // on underflow.
    fn ihead(&self) -> isize {
        self.head as isize
    }

    fn reset(&mut self) {
        self.head = 0;
        self.count = 0;
    }

    // Returns the next slot in the queue.  Always succeeds, since on overflow
    // it discards the LRU slot.
    fn next_slot(&mut self) -> &mut Sample {
        let slot = self.head;
        self.head = modulo(self.ihead() + 1, SAMPLE_QUEUE_LENGTH) as usize;
        if self.count < SAMPLE_QUEUE_LENGTH {
            self.count += 1;
        }
        &mut self.samples[slot]
    }

    fn sample(&self, i: isize) -> &Sample {
        assert!(i >= 0);
        // Subtract 1 because head points to the next free slot.
        assert!(
            modulo(self.ihead() - 1 - i, SAMPLE_QUEUE_LENGTH) <= self.count,
            "bad queue index: i {}, head {}, count {}, queue len {}",
            i,
            self.head,
            self.count,
            SAMPLE_QUEUE_LENGTH
        );
        &self.samples[i as usize]
    }

    // Outputs to file |f| samples from |start_time| to the head.  Uses a start
    // time rather than a start index because when we start a clip we have to
    // do a time-based search anyway.
    fn output_from_time(&self, f: &mut File, start_time: i64) -> Result<()> {
        // For now just do a linear search. ;)
        let mut start_index = modulo(self.ihead() - 1, SAMPLE_QUEUE_LENGTH);
        debug!(
            "output_from_time: start_time {}, head {}",
            start_time, start_index
        );
        loop {
            let sample = self.samples[start_index];
            // Ignore samples from external sources because their time stamp may be off.
            if sample.uptime <= start_time && sample.sample_type.has_internal_timestamp() {
                break;
            }
            debug!(
                "output_from_time: seeking uptime {}, index {}",
                sample.uptime, start_index
            );
            start_index = modulo(start_index as isize - 1, SAMPLE_QUEUE_LENGTH);
            if modulo(self.ihead() - 1 - start_index as isize, SAMPLE_QUEUE_LENGTH) > self.count {
                warn!("too many events in requested interval");
                break;
            }
        }

        let mut index = modulo(start_index as isize + 1, SAMPLE_QUEUE_LENGTH) as isize;
        while index != self.ihead() {
            debug!("output_from_time: outputting index {}", index);
            self.sample(index).output(f)?;
            index = modulo(index + 1, SAMPLE_QUEUE_LENGTH) as isize;
        }
        Ok(())
    }
}

// Returns number of tasks in the run queue as reported in /proc/loadavg, which
// must be accessible via runnables_file.
pub fn get_runnables(runnables_file: &File) -> Result<u32> {
    let content = pread(runnables_file)?;
    // Example: "0.81 0.66 0.86 22/3873 7043" (22 runnables here).
    let slash_pos = content.find('/').ok_or("cannot find '/'")?;
    let space_pos = &content[..slash_pos].rfind(' ').ok_or("cannot find ' '")?;
    let (value, _) = parse_int_prefix(&content[space_pos + 1..])?;
    Ok(value)
}

// Converts the initial digit characters of |s| to the value of the number they
// represent.  Returns the number of characters scanned.
fn parse_int_prefix(s: &str) -> Result<(u32, usize)> {
    let mut result = 0;
    let mut count = 0;
    // Skip whitespace first.
    for c in s.trim_start().chars() {
        let x = c.to_digit(10);
        match x {
            Some(d) => {
                result = result * 10 + d;
                count += 1;
            }
            None => {
                break;
            }
        }
    }
    if count == 0 {
        Err(format!("parse_int_prefix: not an int: {}", s).into())
    } else {
        Ok((result, count))
    }
}

// Reads selected values from |file| (which should be opened to /proc/vmstat)
// as specified in |VMSTATS|, and stores them in |vmstat_values|.  The format of
// the vmstat file is (<name> <integer-value>\n)+.
fn get_vmstats(file: &File, vmstat_values: &mut [u64]) -> Result<()> {
    let content = pread(file)?;
    let mut lines = content.split('\n');
    let mut targets = VMSTATS.iter().enumerate();
    let mut line = None;
    let mut target = None;
    let mut advance_line = true;
    let mut advance_target = true;
    for item in vmstat_values.iter_mut() {
        *item = 0;
    }
    loop {
        if advance_target {
            target = targets.next();
            if target == None {
                break;
            }
        }
        if advance_line {
            line = lines.next();
            // Special case: empty last line.
            if line.is_some() && line.unwrap() == "" {
                line = None;
            }
            if line.is_none() {
                break;
            }
        }

        // The default is to advance the line and keep the same target.  When a
        // target is found in a line, the target is advanced, unless it's an
        // accumulated target, which adds up the values from consecutive
        // matching lines.
        advance_line = true;
        advance_target = false;

        let (i, &(wanted_name, mandatory, accumulate)) = target.unwrap();
        match line {
            Some(string) => {
                let mut pair = string.split(' ');
                let found_name = pair.next().ok_or("missing name in vmstat")?;
                let found_value = pair.next().ok_or("missing value in vmstat")?;
                // First check accumulative targets.
                if accumulate {
                    if found_name.starts_with(wanted_name) {
                        vmstat_values[i] += found_value.parse::<u64>()?;
                        advance_line = true;
                        advance_target = false;
                    } else {
                        // Try the next target, but don't consume the line.
                        advance_line = false;
                        advance_target = true;
                    }
                    continue;
                }
                // Then check for single-shot (not accumulated) fields.
                if found_name == wanted_name {
                    vmstat_values[i] = found_value.parse::<u64>()?;
                    advance_line = true;
                    advance_target = true;
                    continue;
                }
            }
            None => {
                if mandatory {
                    return Err(format!("vmstat: missing value: {}", wanted_name).into());
                } else {
                    vmstat_values[i] = 0;
                }
            }
        }
    }
    Ok(())
}

fn pread_u32(f: &File) -> Result<u32> {
    let mut buffer: [u8; 20] = [0; 20];
    // pread is safe to call with valid addresses and buffer length.
    let length = unsafe {
        libc::pread(
            f.as_raw_fd(),
            &mut buffer[0] as *mut u8 as *mut c_void,
            buffer.len(),
            0,
        )
    };
    if length < 0 {
        return Err("bad pread_u32".into());
    }
    if length == 0 {
        return Err("empty pread_u32".into());
    }
    Ok(String::from_utf8_lossy(&buffer[..length as usize])
        .trim()
        .parse::<u32>()?)
}

// Reads the content of file |f| starting at offset 0, up to PAGE_SIZE and
// returns it as a string.
fn pread(f: &File) -> Result<String> {
    let mut buffer = vec![0u8; PAGE_SIZE];
    // pread is safe to call with valid addresses and buffer length.
    let length = unsafe {
        libc::pread(
            f.as_raw_fd(),
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len(),
            0,
        )
    };
    if length == 0 {
        return Err("unexpected null pread".into());
    }
    if length < 0 {
        return Err(format!("pread failed: {}", strerror(errno())).into());
    }
    buffer.resize(length as usize, 0u8);

    // Sysfs files contain only single-byte characters, so from_utf8_unchecked
    // would be safe for those files.  However, there's no guarantee that this
    // is only called on sysfs files.
    Ok(String::from_utf8(buffer)?)
}

struct Watermarks {
    min: u32,
    low: u32,
    high: u32,
}

struct ZoneinfoFile(File);

impl ZoneinfoFile {
    // Computes and returns the watermark values from /proc/zoneinfo.
    fn read_watermarks(&mut self) -> Result<Watermarks> {
        let mut min = 0;
        let mut low = 0;
        let mut high = 0;
        let mut content = String::new();
        self.0.read_to_string(&mut content)?;
        for line in content.lines() {
            let items = line.split_whitespace().collect::<Vec<_>>();
            match items[0] {
                "min" => min += items[1].parse::<u32>()?,
                "low" => low += items[1].parse::<u32>()?,
                "high" => high += items[1].parse::<u32>()?,
                _ => {}
            }
        }
        Ok(Watermarks { min, low, high })
    }
}

trait Dbus {
    // Returns a vector of file descriptors that can be registered with a
    // Watcher.
    fn get_fds(&self) -> &Vec<RawFd>;
    // Processes incoming dbus events as indicated by |watcher|.  Returns
    // vectors of tab discards reported by chrome, and OOM kills reported by
    // the anomaly detector.
    fn process_dbus_events(&mut self, watcher: &mut FileWatcher)
        -> Result<Vec<(event::Type, i64)>>;
}

#[cfg(not(test))]
struct GenuineDbus {
    connection: dbus::Connection,
    fds: Vec<RawFd>,
}

#[cfg(not(test))]
impl Dbus for GenuineDbus {
    fn get_fds(&self) -> &Vec<RawFd> {
        &self.fds
    }

    // Called if any of the dbus file descriptors fired.  Receives metrics
    // event signals, and return a vector of pairs, each pair containing the
    // event type and time stamp of each incoming event.
    //
    // Debugging example:
    //
    // INTERFACE=org.chromium.MetricsEventServiceInterface
    // dbus-monitor --system type=signal,interface=$INTERFACE
    // PAYLOAD=array:byte:0x10,0xa8,0xa2,0xc5,0x51
    // dbus-send --system --type=signal / $INTERFACE.ChromeEvent $PAYLOAD
    //
    fn process_dbus_events(
        &mut self,
        watcher: &mut FileWatcher,
    ) -> Result<Vec<(event::Type, i64)>> {
        let mut events: Vec<(event::Type, i64)> = Vec::new();
        for &fd in self.fds.iter() {
            if !watcher.has_fired_fd(fd)? {
                continue;
            }
            let handle = self
                .connection
                .watch_handle(fd, WatchEvent::Readable as libc::c_uint);
            for connection_item in handle {
                // Only consider signals.
                if let dbus::ConnectionItem::Signal(ref message) = connection_item {
                    // Only consider signals with "ChromeEvent" or
                    // "AnomalyEvent" members.
                    if let Some(member) = message.member() {
                        if &*member != "ChromeEvent" && &*member != "AnomalyEvent" {
                            // Do not report spurious "NameAcquired" signal to avoid spam.
                            if &*member != "NameAcquired" {
                                warn!("unexpected dbus signal member {}", &*member);
                            }
                            continue;
                        }
                    }
                    // Read first item in signal message as byte blob and
                    // parse blob into protobuf.
                    let raw_buffer: Vec<u8> = message.read1()?;
                    let mut protobuf = Event::new();
                    protobuf.merge_from_bytes(&raw_buffer)?;

                    let event_type = protobuf.type_.enum_value_or_default();
                    let time_stamp = protobuf.timestamp;
                    events.push((event_type, time_stamp))
                }
            }
        }
        Ok(events)
    }
}

#[cfg(not(test))]
impl GenuineDbus {
    // A GenuineDbus object contains a D-Bus connection used to receive
    // information from Chrome about events of interest (e.g. tab discards).
    fn new() -> Result<GenuineDbus> {
        let connection = Connection::get_private(BusType::System)?;
        let _m = connection.add_match(concat!(
            "type='signal',",
            "interface='org.chromium.AnomalyEventServiceInterface',",
            "member='AnomalyEvent'"
        ));
        let _m = connection.add_match(concat!(
            "type='signal',",
            "interface='org.chromium.MetricsEventServiceInterface',",
            "member='ChromeEvent'"
        ));
        let fds = connection.watch_fds().iter().map(|w| w.fd()).collect();
        Ok(GenuineDbus { connection, fds })
    }
}

// The main object.
struct Sampler<'a> {
    always_poll_fast: bool,       // When true, program stays in fast poll mode.
    paths: &'a Paths,             // Paths of files used by the program.
    dbus: Box<dyn Dbus>,          // Used to receive Chrome event notifications.
    low_mem_margin: u32, // Low-memory notification margin, assumed to remain constant in a boot session.
    sample_header: String, // The text at the beginning of each clip file.
    files: Files,        // Files kept open by the program.
    watcher: FileWatcher, // Maintains a set of files being watched for select().
    low_mem_watcher: FileWatcher, // A watcher for the low-mem device.
    clip_counter: usize, // Index of next clip file (also part of file name).
    sample_queue: SampleQueue, // A running queue of samples of vm quantities.
    current_available: u32, // Amount of "available" memory (in MB) at last reading.
    current_time: i64,   // Wall clock in ms at last reading.
    collecting: bool,    // True if we're in the middle of collecting a clip.
    timer: Box<dyn Timer>, // Real or mock timer.
    quit_request: bool,  // Signals a quit-and-restart request when testing.
}

impl<'a> Sampler<'a> {
    fn new(
        always_poll_fast: bool,
        paths: &'a Paths,
        timer: Box<dyn Timer>,
        dbus: Box<dyn Dbus>,
    ) -> Result<Sampler> {
        let mut low_mem_file_flags = OpenOptions::new();
        low_mem_file_flags.custom_flags(libc::O_NONBLOCK);
        low_mem_file_flags.read(true);
        let low_mem_file_option = open_with_flags_maybe(&paths.low_mem_device, &low_mem_file_flags)
            .map_err(|e| Error::LowMemFileError(e))?;
        if low_mem_file_option.is_none() {
            warn!("low-mem device: cannot open and will not use");
        }

        let mut watcher = FileWatcher::new();
        let mut low_mem_watcher = FileWatcher::new();

        if let Some(low_mem_file) = low_mem_file_option.as_ref() {
            watcher
                .set(low_mem_file)
                .map_err(|e| Error::LowMemFDWatchError(e))?;
            low_mem_watcher
                .set(low_mem_file)
                .map_err(|e| Error::LowMemWatcherError(e))?;
        }
        for fd in dbus.get_fds().iter().by_ref() {
            watcher.set_fd(*fd).map_err(|e| Error::DbusWatchError(e))?;
        }

        let files = Files {
            vmstat_file: File::open(&paths.vmstat)
                .map_err(|e| Error::VmstatFileError(Box::new(e)))?,
            runnables_file: File::open(&paths.runnables)
                .map_err(|e| Error::RunnablesFileError(Box::new(e)))?,
            available_file_option: open_maybe(&paths.available)
                .map_err(|e| Error::AvailableFileError(e))?,
            low_mem_file_option,
        };

        let sample_header = build_sample_header();

        let mut sampler = Sampler {
            always_poll_fast,
            dbus,
            low_mem_margin: read_int(&paths.low_mem_margin).unwrap_or(0),
            paths,
            sample_header,
            files,
            watcher,
            low_mem_watcher,
            sample_queue: SampleQueue::new(),
            clip_counter: 0,
            collecting: false,
            current_available: 0,
            current_time: 0,
            timer,
            quit_request: false,
        };
        sampler
            .find_starting_clip_counter()
            .map_err(|e| Error::StartingClipCounterMissingError(e))?;
        sampler
            .log_static_parameters()
            .map_err(|e| Error::LogStaticParametersError(e))?;
        Ok(sampler)
    }

    // Refresh cached time.  This should be called after system calls, which
    // can potentially block, but not if current_time is unused before the next call.
    fn refresh_time(&mut self) {
        self.current_time = self.timer.now();
    }

    // Collect a sample using the latest time snapshot.
    fn enqueue_sample(&mut self, sample_type: SampleType) -> Result<()> {
        let time = self.current_time; // to pacify the borrow checker
        self.enqueue_sample_at_time(sample_type, time)
    }

    // Collect a sample with an externally-generated time stamp.
    fn enqueue_sample_external(&mut self, sample_type: SampleType, time: i64) -> Result<()> {
        assert!(!sample_type.has_internal_timestamp());
        self.enqueue_sample_at_time(sample_type, time)
    }

    // Collects a sample of memory manager stats and adds it to the sample
    // queue, possibly overwriting an old value.  |sample_type| indicates the
    // type of sample, and |time| the system uptime at the time the sample was
    // collected.
    fn enqueue_sample_at_time(&mut self, sample_type: SampleType, time: i64) -> Result<()> {
        {
            let sample: &mut Sample = self.sample_queue.next_slot();
            sample.uptime = time;
            sample.sample_type = sample_type;
            sample.available = self.current_available;
            sample.runnables = get_runnables(&self.files.runnables_file)?;
            sample.info = if cfg!(test) {
                Sysinfo::fake_sysinfo()?
            } else {
                sysinfo()?
            };
            get_vmstats(&self.files.vmstat_file, &mut sample.vmstat_values)?;
        }
        self.refresh_time();
        Ok(())
    }

    // Creates or overwrites a file in the memd log directory containing
    // quantities of interest.
    fn log_static_parameters(&self) -> Result<()> {
        let out = &mut OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.paths.static_parameters)?;
        fprint_datetime(out)?;
        let low_mem_margin = read_int(&self.paths.low_mem_margin).unwrap_or(0);
        writeln!(out, "margin {}", low_mem_margin)?;

        let psv = &self.paths.procsysvm;
        log_from_procfs(out, psv, "min_filelist_kbytes")?;
        log_from_procfs(out, psv, "min_free_kbytes")?;
        log_from_procfs(out, psv, "extra_free_kbytes")?;

        let mut zoneinfo = ZoneinfoFile(File::open(&self.paths.zoneinfo)?);
        let watermarks = zoneinfo.read_watermarks()?;
        writeln!(out, "min_water_mark_kbytes {}", watermarks.min * 4)?;
        writeln!(out, "low_water_mark_kbytes {}", watermarks.low * 4)?;
        writeln!(out, "high_water_mark_kbytes {}", watermarks.high * 4)?;
        Ok(())
    }

    // Returns true if the program should go back to slow-polling mode (or stay
    // in that mode).  Returns false otherwise.  Relies on |self.collecting|
    // and |self.current_available| being up-to-date.  If the kernel does not
    // have the cros low-mem notifier, "margin" and "available" are both 0, and
    // this always returns false. (XXX should use a different way of detecting
    // medium pressure, but it's not critical since all cros devices have a
    // low-mem device.)
    fn should_poll_slowly(&self) -> bool {
        !self.collecting
            && !self.always_poll_fast
            && self.low_mem_margin > 0
            && self.current_available > self.low_mem_margin + LOW_MEM_DANGER_THRESHOLD_MB
    }

    // Sits mostly idle and checks available RAM at low frequency.  Returns
    // when available memory gets "close enough" to the tab discard margin.
    fn slow_poll(&mut self) -> Result<()> {
        debug!("entering slow poll at {}", self.current_time);
        // Idiom for do ... while.
        while {
            let fired_count = {
                let watcher = &mut self.watcher;
                watcher.watch(&SLOW_POLL_PERIOD_DURATION, &mut *self.timer)?
            };
            debug!("fired count: {} at {}", fired_count, self.timer.now());
            self.quit_request = self.timer.quit_request();
            if let Some(available_file) = self.files.available_file_option.as_ref() {
                self.current_available = pread_u32(available_file)?;
            }
            self.refresh_time();
            self.should_poll_slowly() && !self.quit_request && fired_count == 0
        } {}
        Ok(())
    }

    // Collects timer samples at fast rate.  Also collects event samples.
    // Samples contain various system stats related to kernel memory
    // management.  The samples are placed in a circular buffer.  When
    // something "interesting" happens, (for instance a tab discard, or a
    // kernel OOM-kill) the samples around that event are saved into a "clip
    // file".
    fn fast_poll(&mut self) -> Result<()> {
        let mut earliest_start_time = self.current_time;
        debug!("entering fast poll at {}", earliest_start_time);

        // Collect the first timer sample immediately upon entering.
        self.enqueue_sample(SampleType::Timer)?;
        // Keep track if we're in a low-mem state.  Initially assume we are
        // not.
        let mut in_low_mem = false;
        // |clip_{start,end}_time| are the collection start and end time for
        // the current clip.  Their value is valid only when |self.collecting|
        // is true.
        let mut clip_start_time = self.current_time;
        let mut clip_end_time = self.current_time;
        // |final_collection_time| indicates when we should stop collecting
        // samples for any clip (either the current one, or the next one).  Its
        // value is valid only when |self.collecting| is true.
        let mut final_collection_time = self.current_time;
        let null_duration = Duration::from_secs(0);

        // |self.collecting| is true when we're in the middle of collecting a clip
        // because something interesting has happened.
        self.collecting = false;

        // Poll/select loop.
        loop {
            // Assume event is not interesting (since most events
            // aren't). Change this to true for some event types.
            let mut event_is_interesting = false;

            let watch_start_time = self.current_time;
            let fired_count = {
                let watcher = &mut self.watcher;
                watcher.watch(&FAST_POLL_PERIOD_DURATION, &mut *self.timer)?
            };
            self.quit_request = self.timer.quit_request();
            if let Some(available_file) = self.files.available_file_option.as_ref() {
                self.current_available = pread_u32(available_file)?;
            }
            self.refresh_time();

            // Record a sample when we sleep too long.  Such samples are
            // somewhat redundant as they could be deduced from the log, but we
            // wish to make it easier to detect such (rare, we hope)
            // occurrences.
            if watch_start_time > self.current_time + UNREASONABLY_LONG_SLEEP {
                warn!(
                    "woke up at {} after unreasonable {} sleep",
                    self.current_time,
                    self.current_time - watch_start_time
                );
                self.enqueue_sample(SampleType::Sleeper)?;
            }

            // The low_mem file is level-triggered, not edge-triggered (my bad)
            // so we don't watch it when memory stays low, because it would
            // fire continuously.  Instead we poll it at every event, and when
            // we detect a low-to-high transition we start watching it again.
            // Unfortunately this requires an extra select() call: however we
            // don't expect to spend too much time in this state (and when we
            // do, this is the least of our worries).
            if in_low_mem
                && self
                    .low_mem_watcher
                    .watch(&null_duration, &mut *self.timer)?
                    == 0
            {
                // Refresh time since we may have blocked.  (That should
                // not happen often because currently the run times between
                // sleeps are well below the minimum timeslice.)
                self.current_time = self.timer.now();
                debug!("leaving low mem at {}", self.current_time);
                in_low_mem = false;
                self.enqueue_sample(SampleType::LeaveLowMem)?;
                self.watcher
                    .set(self.files.low_mem_file_option.as_ref().unwrap())?;
            }

            if fired_count == 0 {
                // Timer event.
                self.enqueue_sample(SampleType::Timer)?;
            } else {
                // See comment above about watching low_mem.
                let low_mem_has_fired = !in_low_mem
                    && match self.files.low_mem_file_option {
                        Some(ref low_mem_file) => self.watcher.has_fired(low_mem_file)?,
                        _ => false,
                    };
                if low_mem_has_fired {
                    debug!("entering low mem at {}", self.current_time);
                    in_low_mem = true;
                    self.enqueue_sample(SampleType::EnterLowMem)?;
                    let fd = self.files.low_mem_file_option.as_ref().unwrap().as_raw_fd();
                    self.watcher.clear_fd(fd)?;
                    // Make this interesting at least until chrome events are
                    // plumbed, maybe permanently.
                    event_is_interesting = true;
                }

                // Check for dbus events.
                let events = self.dbus.process_dbus_events(&mut self.watcher)?;
                if !events.is_empty() {
                    debug!("dbus events at {}: {:?}", self.current_time, events);
                    event_is_interesting = true;
                }
                for event in events {
                    let sample_type = match event.0 {
                        event::Type::TAB_DISCARD => SampleType::TabDiscard,
                        event::Type::OOM_KILL => SampleType::OomKillBrowser,
                        event::Type::OOM_KILL_KERNEL => SampleType::OomKillKernel,
                        _ => {
                            warn!("unknown event type {:?}", event.0);
                            continue;
                        }
                    };
                    debug!("enqueue {:?}, {:?}", sample_type, event.1);
                    self.enqueue_sample_external(sample_type, event.1)?;
                }
            }

            // Arrange future saving of samples around interesting events.
            if event_is_interesting {
                // Update the time intervals to ensure we include all samples
                // of interest in a clip.  If we're not in the middle of
                // collecting a clip, start one.  If we're in the middle of
                // collecting a clip which can be extended, do that.
                final_collection_time = self.current_time + COLLECTION_DELAY_MS;
                if self.collecting {
                    // Check if the current clip can be extended.
                    if clip_end_time < clip_start_time + CLIP_COLLECTION_SPAN_MS {
                        clip_end_time =
                            final_collection_time.min(clip_start_time + CLIP_COLLECTION_SPAN_MS);
                        debug!("extending clip to {}", clip_end_time);
                    }
                } else {
                    // Start the clip collection.
                    self.collecting = true;
                    clip_start_time =
                        earliest_start_time.max(self.current_time - COLLECTION_DELAY_MS);
                    clip_end_time = self.current_time + COLLECTION_DELAY_MS;
                    debug!(
                        "starting new clip from {} to {}",
                        clip_start_time, clip_end_time
                    );
                }
            }

            // Check if it is time to save the samples into a file.
            if self.collecting && self.current_time > clip_end_time - SAMPLING_PERIOD_MS {
                // Save the clip to disk.
                debug!(
                    "[{}] saving clip: ({} ... {}), final {}",
                    self.current_time, clip_start_time, clip_end_time, final_collection_time
                );
                let res = self.save_clip(clip_start_time);
                // Don't panic if there's an error writing to disk, log it instead.
                if res.is_err() {
                    warn!("Error saving clip: {:?}", res);
                }
                self.collecting = false;
                earliest_start_time = clip_end_time;
                // Need to schedule another collection?
                if final_collection_time > clip_end_time {
                    // Continue collecting by starting a new clip.  Note that
                    // the clip length may be less than CLIP_COLLECTION_SPAN.
                    // This happens when event spans overlap, and also if we
                    // started fast sample collection just recently.
                    assert!(final_collection_time <= clip_end_time + CLIP_COLLECTION_SPAN_MS);
                    clip_start_time = clip_end_time;
                    clip_end_time = final_collection_time;
                    self.collecting = true;
                    debug!(
                        "continue collecting with new clip ({} {})",
                        clip_start_time, clip_end_time
                    );
                    // If we got stuck in the select() for a very long time
                    // because of system slowdown, it may be time to collect
                    // this second clip as well.  But we don't bother, since
                    // this is unlikely, and we can collect next time around.
                    if self.current_time > clip_end_time {
                        debug!(
                            "heavy slowdown: postponing collection of ({}, {})",
                            clip_start_time, clip_end_time
                        );
                    }
                }
            }
            if self.should_poll_slowly() || (self.quit_request && !self.collecting) {
                break;
            }
        }
        Ok(())
    }

    // Returns the clip file pathname to be used after the current one,
    // and advances the clip counter.
    fn next_clip_path(&mut self) -> PathBuf {
        let name = format!("memd.clip{:03}.log", self.clip_counter);
        self.clip_counter = modulo(self.clip_counter as isize + 1, MAX_CLIP_COUNT);
        self.paths.log_directory.join(name)
    }

    // Finds and sets the starting value for the clip counter in this session.
    // The goal is to preserve the most recent clips (if any) from previous
    // sessions.
    fn find_starting_clip_counter(&mut self) -> Result<()> {
        self.clip_counter = 0;
        let mut previous_time = std::time::UNIX_EPOCH;
        loop {
            let path = self.next_clip_path();
            if !path.exists() {
                break;
            }
            let md = std::fs::metadata(path)?;
            let time = md.modified()?;
            if time < previous_time {
                break;
            } else {
                previous_time = time;
            }
        }
        // We found the starting point, but the counter has already advanced so we
        // need to backtrack one step.
        self.clip_counter = modulo(self.clip_counter as isize - 1, MAX_CLIP_COUNT);
        Ok(())
    }

    // Stores samples of interest in a new clip log, and remove those samples
    // from the queue.
    fn save_clip(&mut self, start_time: i64) -> Result<()> {
        let path = self.next_clip_path();
        let out = &mut OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;

        // Print courtesy header.  The first line is the current time.  The
        // second line lists the names of the variables in the following lines,
        // in the same order.
        fprint_datetime(out)?;
        out.write_all(self.sample_header.as_bytes())?;
        // Output samples from |start_time| to the head.
        self.sample_queue.output_from_time(out, start_time)?;
        // The queue is now empty.
        self.sample_queue.reset();
        Ok(())
    }
}

// Prints |name| and value of entry /pros/sys/vm/|name| (or 0, if the entry is
// missing) to file |out|.
fn log_from_procfs(out: &mut File, dir: &Path, name: &str) -> Result<()> {
    let procfs_path = dir.join(name);
    let value = read_int(&procfs_path).unwrap_or(0);
    writeln!(out, "{} {}", name, value)?;
    Ok(())
}

// Outputs readable date and time to file |out|.
fn fprint_datetime(out: &mut File) -> Result<()> {
    let local: DateTime<Local> = Local::now();
    writeln!(out, "{}", local)?;
    Ok(())
}

#[derive(Copy, Clone, Debug)]
enum SampleType {
    EnterLowMem,    // Entering low-memory state, from the kernel low-mem notifier.
    LeaveLowMem,    // Leaving low-memory state, from the kernel low-mem notifier.
    OomKillBrowser, // Chrome browser letting us know it detected OOM kill.
    OomKillKernel,  // Anomaly detector letting us know it detected OOM kill.
    Sleeper,        // Memd was not running for a long time.
    TabDiscard,     // Chrome browser letting us know about a tab discard.
    Timer,          // Event was produced after FAST_POLL_PERIOD_DURATION with no other events.
    Uninitialized,  // Internal use.
}

impl Default for SampleType {
    fn default() -> SampleType {
        SampleType::Uninitialized
    }
}

impl fmt::Display for SampleType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl SampleType {
    // Returns true if the timestamp for this sample type is generated
    // internally.  This knowledge is used in outputting samples to clip files,
    // because the timestamps of samples generated externally may be skewed.
    fn has_internal_timestamp(&self) -> bool {
        match self {
            &SampleType::TabDiscard | &SampleType::OomKillBrowser | &SampleType::OomKillKernel => {
                false
            }
            _ => true,
        }
    }
}

impl SampleType {
    // Returns the 6-character(max) identifier for a sample type.
    fn name(&self) -> &'static str {
        match *self {
            SampleType::EnterLowMem => "lowmem",
            SampleType::LeaveLowMem => "lealow",
            SampleType::OomKillBrowser => "oomkll", // OOM from chrome
            SampleType::OomKillKernel => "keroom",  // OOM from kernel
            SampleType::Sleeper => "sleepr",
            SampleType::TabDiscard => "discrd",
            SampleType::Timer => "timer",
            SampleType::Uninitialized => "UNINIT",
        }
    }
}

// Path names of various system files, mostly in /proc, /sys, and /dev.  They
// are collected into this struct because they get special values when testing.
#[derive(Clone)]
pub struct Paths {
    vmstat: PathBuf,
    available: PathBuf,
    runnables: PathBuf,
    low_mem_margin: PathBuf,
    low_mem_device: PathBuf,
    log_directory: PathBuf,
    static_parameters: PathBuf,
    zoneinfo: PathBuf,
    procsysvm: PathBuf,
    testing_root: PathBuf,
}

// Returns a file name that replaces |name| when testing.
fn test_filename(testing: bool, testing_root: &str, name: &str) -> String {
    if testing {
        testing_root.to_string() + name
    } else {
        name.to_owned()
    }
}

// This macro constructs a "normal" Paths object when |testing| is false, and
// one that mimics a root filesystem in a temporary directory when |testing| is
// true.
macro_rules! make_paths {
    ($testing:expr, $root:expr,
     $($name:ident : $e:expr,)*
    ) => (
        Paths {
            testing_root: PathBuf::from($root),
            $($name: PathBuf::from(test_filename($testing, $root, &($e).to_string()))),*
        }
    )
}

// All files that are to be left open go here.  We keep them open to reduce the
// number of syscalls.  They are mostly files in /proc and /sys.
struct Files {
    vmstat_file: File,
    runnables_file: File,
    // These files might not exist.
    available_file_option: Option<File>,
    low_mem_file_option: Option<File>,
}

fn build_sample_header() -> String {
    let mut s = "uptime type load freeram freeswap procs runnables available".to_string();
    for vmstat in VMSTATS.iter() {
        s = s + " " + vmstat.0;
    }
    s + "\n"
}

fn main() -> Result<()> {
    let mut always_poll_fast = false;
    let mut debug_log = false;

    libchromeos::panic_handler::install_memfd_handler();
    let args: Vec<String> = std::env::args().collect();
    for arg in &args[1..] {
        match arg.as_ref() {
            "always-poll-fast" => always_poll_fast = true,
            "debug-log" => debug_log = true,
            _ => panic!("usage: memd [always-poll-fast|debug-log]*"),
        }
    }

    let log_level = if debug_log {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Warn
    };
    syslog::init_unix(syslog::Facility::LOG_USER, log_level)
        .map_err(|e| Error::InitSyslogError(Box::new(e)))?;

    // Unlike log!(), warn!() etc., panic!() is not redirected by the syslog
    // facility, instead always goes to stderr, which can get lost.  Here we
    // provide our own panic hook to make sure that the panic message goes to
    // the syslog as well.
    let default_panic = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        error!("memd: {}", panic_info);
        default_panic(panic_info);
    }));

    warn!("memd started");
    run_memory_daemon(always_poll_fast)
}

// Creates a directory for testing, if testing.  Otherwise
// returns None
fn make_testing_dir() -> Option<TempDir> {
    if cfg!(test) {
        Some(TempDir::new().expect("cannot create temp dir"))
    } else {
        None
    }
}

#[test]
fn memory_daemon_test() {
    env_logger::init();
    run_memory_daemon(false).expect("run_memory_daemon error");
}

#[test]
fn read_loadavg_test() {
    test::read_loadavg();
}

#[test]
fn read_vmstat_test() {
    let testing_dir_option = make_testing_dir();
    let paths = get_paths(testing_dir_option);
    test::read_vmstat(&paths);
}

/// Regression test for https://crbug.com/1058463. Ensures that output_from_time doesn't read
/// samples outside of the valid range.
#[test]
fn queue_loop_test() {
    test::queue_loop();
}

fn get_paths(root: Option<TempDir>) -> Paths {
    // make_paths! returns a Paths object initializer with these fields.
    let testing_root = match root {
        Some(tmpdir) => tmpdir.path().to_str().unwrap().to_string(),
        None => "/".to_string(),
    };
    make_paths!(
        cfg!(test),
        &testing_root,
        vmstat:            "/proc/vmstat",
        available:         LOW_MEM_SYSFS.to_string() + "/available",
        runnables:         "/proc/loadavg",
        low_mem_margin:    LOW_MEM_SYSFS.to_string() + "/margin",
        low_mem_device:    LOW_MEM_DEVICE,
        log_directory:     LOG_DIRECTORY,
        static_parameters: LOG_DIRECTORY.to_string() + "/" + STATIC_PARAMETERS_LOG,
        zoneinfo:          "/proc/zoneinfo",
        procsysvm:         "/proc/sys/vm",
    )
}

fn run_memory_daemon(always_poll_fast: bool) -> Result<()> {
    let test_dir_option = make_testing_dir();
    let paths = get_paths(test_dir_option);
    debug!("Using root: {}", paths.testing_root.display());

    #[cfg(test)]
    {
        test::setup_test_environment(&paths);
        let var_log = &paths.log_directory.parent().unwrap();
        std::fs::create_dir_all(var_log).map_err(|e| Error::CreateLogDirError(Box::new(e)))?;
    }

    // Make sure /var/log/memd exists.  Create it if not.  Assume /var/log
    // exists.  Panic on errors.
    if !paths.log_directory.exists() {
        create_dir(&paths.log_directory).map_err(|e| Error::CreateLogDirError(Box::new(e)))?
    }

    #[cfg(test)]
    {
        test::test_loop(always_poll_fast, &paths);
        test::teardown_test_environment(&paths);
        Ok(())
    }

    #[cfg(not(test))]
    {
        let timer = Box::new(GenuineTimer {});
        let dbus = Box::new(GenuineDbus::new()?);
        let mut sampler = Sampler::new(always_poll_fast, &paths, timer, dbus)?;
        loop {
            // Run forever, alternating between slow and fast poll.
            sampler.slow_poll()?;
            sampler.fast_poll()?;
        }
    }
}
