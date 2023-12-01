// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Test code for memd.

include!(concat!(env!("OUT_DIR"), "/proto_include.rs"));

use libc;
use std;
use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::str;
use std::time::Duration;

// Imported from main program
use errno;
use get_runnables;
use get_vmstats;
use strerror;
use Dbus;
use FileWatcher;
use Paths;
use Result;
use Sample;
use SampleQueue;
use SampleType;
use Sampler;
use Timer;
use PAGE_SIZE;
use SAMPLE_QUEUE_LENGTH;
use VMSTAT_VALUES_COUNT;

// Different levels of emulated available RAM in MB.
const LOW_MEM_LOW_AVAILABLE: usize = 150;
const LOW_MEM_MEDIUM_AVAILABLE: usize = 300;
const LOW_MEM_HIGH_AVAILABLE: usize = 1000;
const LOW_MEM_MARGIN: usize = 200;
const MOCK_DBUS_FIFO_NAME: &str = "mock-dbus-fifo";

macro_rules! print_to_path {
    ($path:expr, $format:expr $(, $arg:expr)*) => {{
        let r = OpenOptions::new().write(true).create(true).open($path);
        match r {
            Err(e) => Err(e),
            Ok(mut f) => f.write_all(format!($format $(, $arg)*).as_bytes())
        }
    }}
}

fn duration_to_millis(duration: &Duration) -> i64 {
    duration.as_secs() as i64 * 1000 + duration.subsec_nanos() as i64 / 1_000_000
}

// Writes |string| to file |path|.  If |append| is true, seeks to end first.
// If |append| is false, truncates the file first.
fn write_string(string: &str, path: &Path, append: bool) -> Result<()> {
    let mut f = OpenOptions::new().write(true).append(append).open(&path)?;
    if !append {
        f.set_len(0)?;
    }
    f.write_all(string.as_bytes())?;
    Ok(())
}

fn read_nonblocking_pipe(file: &mut File, buf: &mut [u8]) -> Result<usize> {
    let status = file.read(buf);
    let read_bytes = match status {
        Ok(n) => n,
        Err(_) if errno() == libc::EAGAIN => 0,
        Err(_) => return Err("cannot read pipe".into()),
    };
    Ok(read_bytes)
}

fn non_blocking_select(high_fd: i32, inout_read_fds: &mut libc::fd_set) -> i32 {
    #[allow(clippy::unnecessary_cast)]
    let mut null_timeout = libc::timeval {
        tv_sec: 0 as libc::time_t,
        tv_usec: 0 as libc::suseconds_t,
    };
    let null = std::ptr::null_mut();
    // Safe because we're passing valid values and addresses.
    let n = unsafe {
        libc::select(
            high_fd,
            inout_read_fds,
            null,
            null,
            &mut null_timeout as *mut libc::timeval,
        )
    };
    if n < 0 {
        panic!("select: {}", strerror(errno()));
    }
    n
}

fn mkfifo(path: &Path) -> Result<()> {
    let path_name = path.to_str().unwrap();
    let c_path = std::ffi::CString::new(path_name).unwrap();
    // Safe because c_path points to a valid C string.
    let status = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
    if status < 0 {
        Err(format!("mkfifo: {}: {}", path_name, strerror(errno())).into())
    } else {
        Ok(())
    }
}

// The types of events which are generated internally for testing.  They
// simulate state changes (for instance, change in the memory pressure level),
// chrome events, and kernel events.
#[derive(Clone, Copy, Debug, PartialEq)]
enum TestEventType {
    EnterHighPressure,   // enter low available RAM (below margin) state
    EnterLowPressure,    // enter high available RAM state
    EnterMediumPressure, // set enough memory pressure to trigger fast sampling
    OomKillBrowser,      // fake browser report of OOM kill
    TabDiscard,          // fake browser report of tab discard
}

// Internally generated event for testing.
#[derive(Debug)]
struct TestEvent {
    time: i64,
    event_type: TestEventType,
}

impl TestEvent {
    fn deliver(&self, paths: &Paths, dbus_fifo: &mut File, low_mem_device: &mut File, time: i64) {
        debug!("delivering {:?}", self);
        match self.event_type {
            TestEventType::EnterLowPressure => {
                self.low_mem_notify(LOW_MEM_HIGH_AVAILABLE, paths, low_mem_device)
            }
            TestEventType::EnterMediumPressure => {
                self.low_mem_notify(LOW_MEM_MEDIUM_AVAILABLE, paths, low_mem_device)
            }
            TestEventType::EnterHighPressure => {
                self.low_mem_notify(LOW_MEM_LOW_AVAILABLE, paths, low_mem_device)
            }
            TestEventType::OomKillBrowser => self.send_signal("oom-kill", time, dbus_fifo),
            TestEventType::TabDiscard => self.send_signal("tab-discard", time, dbus_fifo),
        }
    }

    fn low_mem_notify(&self, amount: usize, paths: &Paths, low_mem_device: &mut File) {
        write_string(&amount.to_string(), &paths.available, false)
            .expect("available file: write failed");
        if amount == LOW_MEM_LOW_AVAILABLE {
            debug!("making low-mem device ready to read");
            // Make low-mem device ready-to-read.
            write!(low_mem_device, ".").expect("low-mem-device: write failed");
        } else {
            debug!("clearing low-mem device");
            let mut buf = [0; PAGE_SIZE];
            read_nonblocking_pipe(low_mem_device, &mut buf).expect("low-mem-device: clear failed");
        }
    }

    fn send_signal(&self, signal: &str, time: i64, dbus_fifo: &mut File) {
        writeln!(dbus_fifo, "{} {}", signal, time).expect("mock dbus: write failed");
    }
}

// Real time mock, for testing only.  It removes time races (for better or
// worse) and makes it possible to run the test on build machines which may be
// heavily loaded.
//
// Time is mocked by assuming that CPU speed is infinite and time passes only
// when the program is asleep. Time advances in discrete jumps when we call
// either sleep() or select() with a timeout.

struct MockTimer {
    current_time: i64,           // the current time
    test_events: Vec<TestEvent>, // list events to be delivered
    event_index: usize,          // index of next event to be delivered
    paths: Paths,                // for event delivery
    dbus_fifo_out: File,         // for mock dbus event delivery
    low_mem_device: File,        // for delivery of low-mem notifications
    quit_request: bool,          // for termination
}

impl MockTimer {
    fn new(test_events: Vec<TestEvent>, paths: Paths, dbus_fifo_out: File) -> MockTimer {
        let low_mem_device = OpenOptions::new()
            .custom_flags(libc::O_NONBLOCK)
            .read(true)
            .write(true)
            .open(&paths.low_mem_device)
            .expect("low-mem-device: cannot setup");
        MockTimer {
            current_time: 0,
            test_events,
            event_index: 0,
            paths,
            dbus_fifo_out,
            low_mem_device,
            quit_request: false,
        }
    }
}

impl Timer for MockTimer {
    fn now(&self) -> i64 {
        self.current_time
    }

    fn quit_request(&self) -> bool {
        self.quit_request
    }

    // Mock select first checks if any events are pending, then produces events
    // that would happen during its sleeping time, and checks if those events
    // are delivered.
    fn select(
        &mut self,
        high_fd: i32,
        inout_read_fds: &mut libc::fd_set,
        timeout: &Duration,
    ) -> i32 {
        // First check for existing active fds (for instance, the low-mem
        // device).  We must save the original fd_set because when
        // non_blocking_select returns 0, the fd_set is cleared.
        let saved_inout_read_fds = *inout_read_fds;
        let n = non_blocking_select(high_fd, inout_read_fds);
        if n != 0 {
            return n;
        }
        let timeout_ms = duration_to_millis(timeout);
        let end_time = self.current_time + timeout_ms;
        // Assume no events occur and we hit the timeout.  Fix later as needed.
        self.current_time = end_time;
        loop {
            if self.event_index == self.test_events.len() {
                // No more events to deliver, so no need for further select() calls.
                self.quit_request = true;
                return 0;
            }
            // There are still event to be delivered.
            let first_event_time = self.test_events[self.event_index].time;
            // We interpret the event time to be event.time + epsilon.  Thus if
            // |first_event_time| is equal to |end_time|, we time out.
            if first_event_time >= end_time {
                // No event to deliver before the timeout.
                debug!("returning because fev = {}", first_event_time);
                return 0;
            }
            // Deliver all events with the time stamp of the first event.  (There
            // is at least one.)
            while {
                self.test_events[self.event_index].deliver(
                    &self.paths,
                    &mut self.dbus_fifo_out,
                    &mut self.low_mem_device,
                    first_event_time,
                );
                self.event_index += 1;
                self.event_index < self.test_events.len()
                    && self.test_events[self.event_index].time == first_event_time
            } {}
            // One or more events were delivered, and some of them may fire a
            // select.  First restore the original fd_set.
            *inout_read_fds = saved_inout_read_fds;
            let n = non_blocking_select(high_fd, inout_read_fds);
            if n > 0 {
                debug!("returning at {} with {} events", first_event_time, n);
                self.current_time = first_event_time;
                return n;
            }
        }
    }

    // Mock sleep produces all events that would happen during that sleep, then
    // updates the time.
    fn sleep(&mut self, sleep_time: &Duration) {
        let start_time = self.current_time;
        let end_time = start_time + duration_to_millis(sleep_time);
        while self.event_index < self.test_events.len()
            && self.test_events[self.event_index].time <= end_time
        {
            self.test_events[self.event_index].deliver(
                &self.paths,
                &mut self.dbus_fifo_out,
                &mut self.low_mem_device,
                self.current_time,
            );
            self.event_index += 1;
        }
        if self.event_index == self.test_events.len() {
            self.quit_request = true;
        }
        self.current_time = end_time;
    }
}

struct MockDbus {
    fds: Vec<RawFd>,
    fifo_in: File,
    fifo_out: Option<File>, // using Option merely to use take()
}

impl Dbus for MockDbus {
    fn get_fds(&self) -> &Vec<RawFd> {
        &self.fds
    }

    // Processes any mock chrome events.  Events are strings separated by
    // newlines sent to the event pipe.  We could check if the pipe fired in
    // the watcher, but it's less code to just do a non-blocking read.
    fn process_dbus_events(
        &mut self,
        _watcher: &mut FileWatcher,
    ) -> Result<Vec<(event::Type, i64)>> {
        let mut events: Vec<(event::Type, i64)> = Vec::new();
        let mut buf = [0u8; 4096];
        let read_bytes = read_nonblocking_pipe(&mut self.fifo_in, &mut buf)?;
        let mock_events = str::from_utf8(&buf[..read_bytes])?.lines();
        for mock_event in mock_events {
            let mut split_iterator = mock_event.split_whitespace();
            let event_type = split_iterator.next().unwrap();
            let event_time_string = split_iterator.next().unwrap();
            let event_time = event_time_string.parse::<i64>()?;
            match event_type {
                "tab-discard" => events.push((event::Type::TAB_DISCARD, event_time)),
                "oom-kill" => events.push((event::Type::OOM_KILL, event_time)),
                other => return Err(format!("unexpected mock event {:?}", other).into()),
            };
        }
        Ok(events)
    }
}

impl MockDbus {
    fn new(fifo_path: &Path) -> Result<MockDbus> {
        let fifo_in = OpenOptions::new()
            .custom_flags(libc::O_NONBLOCK)
            .read(true)
            .open(&fifo_path)?;
        let fds = vec![fifo_in.as_raw_fd()];
        let fifo_out = OpenOptions::new()
            .custom_flags(libc::O_NONBLOCK)
            .write(true)
            .open(&fifo_path)?;
        Ok(MockDbus {
            fds,
            fifo_in,
            fifo_out: Some(fifo_out),
        })
    }
}

pub fn test_loop(_always_poll_fast: bool, paths: &Paths) {
    for test_desc in TEST_DESCRIPTORS.iter() {
        // Every test run requires a (mock) restart of the daemon.
        println!("\n--------------\nrunning test:\n{}", test_desc);
        // Clean up log directory.
        std::fs::remove_dir_all(&paths.log_directory).expect("cannot remove /var/log/memd");
        std::fs::create_dir_all(&paths.log_directory).expect("cannot create /var/log/memd");

        let events = events_from_test_descriptor(test_desc);
        let mut dbus = Box::new(
            MockDbus::new(&paths.testing_root.join(MOCK_DBUS_FIFO_NAME))
                .expect("cannot create mock dbus"),
        );
        let timer = Box::new(MockTimer::new(
            events,
            paths.clone(),
            dbus.fifo_out.take().unwrap(),
        ));
        let mut sampler = Sampler::new(false, paths, timer, dbus).expect("sampler creation error");
        loop {
            // Alternate between slow and fast poll.
            sampler.slow_poll().expect("slow poll error");
            if sampler.quit_request {
                break;
            }
            sampler.fast_poll().expect("fast poll error");
            if sampler.quit_request {
                break;
            }
        }
        verify_test_results(test_desc, &paths.log_directory)
            .unwrap_or_else(|_| panic!("test:{}failed.", test_desc));
        println!("test succeeded\n--------------");
    }
}

// ================
// Test Descriptors
// ================
//
// Define events and expected result using "ASCII graphics".
//
// The top lines of the test descriptor (all lines except the last one) define
// sequences of events.  The last line describes the expected result.
//
// Events are single characters:
//
// M = start medium pressure (fast poll)
// H = start high pressure (low-mem notification)
// L = start low pressure (slow poll)
// <digit> = tab discard
// K = kernel OOM kill
// k = chrome notification of OOM kill
// ' ', . = nop (just wait 1 second)
// | = ignored (no delay), cosmetic only
//
// - each character indicates a 1-second slot
// - events (if any) happen at the beginning of their slot
// - multiple events in the same slot are stacked vertically
//
// Example:
//
// ..H.1..L
//     2
//
// means:
//  - wait 2 seconds
//  - signal high-memory pressure, wait 1 second
//  - wait 1 second
//  - signal two tab discard events (named 1 and 2), wait 1 second
//  - wait 2 more seconds
//  - return to low-memory pressure
//
// The last line describes the expected clip logs.  Each log is identified by
// one digit: 0 for memd.clip000.log, 1 for memd.clip001.log etc.  The positions
// of the digits correspond to the time span covered by each clip.  So a clip
// file whose description is 5 characters long is supposed to contain 5 seconds
// worth of samples.
//
// For readability, the descriptor must start and end with newlines, which are
// removed.  Also, indentation (common all-space prefixes) is removed.

#[rustfmt::skip]
const TEST_DESCRIPTORS: &[&str] = &[

    // Very simple test: go from slow poll to fast poll and back.  No clips
    // are collected.
    "
    .M.L.
    .....
    ",

    // Simple test: start fast poll, signal low-mem, signal tab discard.
    "
    .M...H..1.....L
    ..00000000001..
    ",

    // Two full disjoint clips.  Also tests kernel-reported and chrome-reported OOM
    // kills.
    "
    .M......k.............k.....
    ...0000000000....1111111111.
    ",

    // Test that clip collection continues for the time span of interest even if
    // memory pressure returns quickly to a low level.  Note that the
    // medium-pressure event (M) is at t = 1s, but the fast poll starts at 2s
    // (multiple of 2s slow-poll period).
    "
    .MH1L.....
    ..000000..
    ",

    // Several discards, which result in three consecutive clips.  Tab discards 1
    // and 2 produce an 8-second clip because the first two seconds of data are
    // missing.  Also see the note above regarding fast poll start.
    "
    ...M.H12..|...3...6..|.7.....L
              |   4      |
              |   5      |
    ....000000|0011111111|112222..
    ",

    // Enter low-mem, then exit, then enter it again.
    "
    .MHM......|......H...|...L
    ..00000...|.111111111|1...
    ",

    // Discard a tab in slow-poll mode.
    "
    ....1.......
    ....00000...
    ",

];

fn trim_descriptor(descriptor: &str) -> Vec<Vec<u8>> {
    // Remove vertical bars.  Don't check for consistent use because it's easy
    // enough to notice visually.
    let barless_descriptor: String = descriptor.chars().filter(|c| *c != '|').collect();
    // Split string into lines.
    let all_lines: Vec<String> = barless_descriptor.split('\n').map(String::from).collect();
    // A test descriptor must start and end with empty lines, and have at least
    // one line of events, and exactly one line to describe the clip files.
    assert!(all_lines.len() >= 4, "invalid test descriptor format");
    // Remove first and last line.
    let valid_lines = all_lines[1..all_lines.len() - 1].to_vec();
    // Find indentation amount.  Unwrap() cannot fail because of previous assert.
    let indent = valid_lines
        .iter()
        .map(|s| s.len() - s.trim_start().len())
        .min()
        .unwrap();
    // Remove indentation.
    let trimmed_lines: Vec<Vec<u8>> = valid_lines
        .iter()
        .map(|s| s[indent..].to_string().into_bytes())
        .collect();
    trimmed_lines
}

fn events_from_test_descriptor(descriptor: &str) -> Vec<TestEvent> {
    let all_descriptors = trim_descriptor(descriptor);
    let event_sequences = &all_descriptors[..all_descriptors.len() - 1];
    let max_length = event_sequences.iter().map(|d| d.len()).max().unwrap();
    let mut events = vec![];
    for i in 0..max_length {
        for seq in event_sequences {
            // Each character represents one second.  Time unit is milliseconds.
            let mut opt_type = None;
            if i < seq.len() {
                match seq[i] {
                    b'0' | b'1' | b'2' | b'3' | b'4' | b'5' | b'6' | b'7' | b'8' | b'9' => {
                        opt_type = Some(TestEventType::TabDiscard)
                    }
                    b'H' => opt_type = Some(TestEventType::EnterHighPressure),
                    b'M' => opt_type = Some(TestEventType::EnterMediumPressure),
                    b'L' => opt_type = Some(TestEventType::EnterLowPressure),
                    b'k' => opt_type = Some(TestEventType::OomKillBrowser),
                    b'.' | b' ' | b'|' => {}
                    x => panic!("unexpected character {} in descriptor '{}'", &x, descriptor),
                }
            }
            if let Some(t) = opt_type {
                events.push(TestEvent {
                    time: i as i64 * 1000,
                    event_type: t,
                });
            }
        }
    }
    events
}

// Given a descriptor string for the expected clips, returns a vector of start
// and end time of each clip.
fn expected_clips(descriptor: &[u8]) -> Vec<(i64, i64)> {
    let mut time = 0;
    let mut clip_start_time = 0;
    let mut previous_clip = b'0' - 1;
    let mut previous_char = 0u8;
    let mut clips = vec![];

    for &c in descriptor {
        if c != previous_char {
            if (previous_char as char).is_ascii_digit() {
                // End of clip.
                clips.push((clip_start_time, time));
            }
            if (c as char).is_ascii_digit() {
                // Start of clip.
                clip_start_time = time;
                assert_eq!(c, previous_clip + 1, "malformed clip descriptor");
                previous_clip = c;
            }
        }
        previous_char = c;
        time += 1000;
    }
    clips
}

// Converts a string starting with a timestamp in seconds (#####.##, with two
// decimal digits) to a timestamp in milliseconds.
fn time_from_sample_string(line: &str) -> Result<i64> {
    let mut tokens = line.split(|c: char| !c.is_ascii_digit());
    let seconds = match tokens.next() {
        Some(digits) => digits.parse::<i64>().unwrap(),
        None => return Err("no digits in string".into()),
    };
    let centiseconds = match tokens.next() {
        Some(digits) => {
            if digits.len() == 2 {
                digits.parse::<i64>().unwrap()
            } else {
                return Err("expecting 2 decimals".into());
            }
        }
        None => return Err("expecting at least two groups of digits".into()),
    };
    Ok(seconds * 1000 + centiseconds * 10)
}

macro_rules! assert_approx_eq {
    ($actual:expr, $expected: expr, $tolerance: expr, $format:expr $(, $arg:expr)*) => {{
        let actual = $actual;
        let expected = $expected;
        let tolerance = $tolerance;
        let expected_min = expected - tolerance;
        let expected_max = expected + tolerance;
        assert!(actual < expected_max && actual > expected_min,
                concat!("(expected: {}, actual: {}) ", $format), expected, actual $(, $arg)*);
    }}
}

fn check_clip(clip_times: (i64, i64), clip_path: PathBuf, events: &[TestEvent]) -> Result<()> {
    let clip_name = clip_path.to_string_lossy();
    let mut clip_file = File::open(&clip_path)?;
    let mut file_content = String::new();
    clip_file.read_to_string(&mut file_content)?;
    debug!("clip {}:\n{}", clip_name, file_content);
    let lines = file_content.lines().collect::<Vec<&str>>();
    // First line is time stamp.  Second line is field names.  Check count of
    // field names and field values in the third line (don't bother to check
    // the other lines).
    let name_count = lines[1].split_whitespace().count();
    let value_count = lines[2].split_whitespace().count();
    assert_eq!(name_count, value_count);

    // Check first and last time stamps.
    let start_time = time_from_sample_string(lines[2]).expect("cannot parse first timestamp");
    let end_time =
        time_from_sample_string(lines[lines.len() - 1]).expect("cannot parse last timestamp");
    let expected_start_time = clip_times.0;
    let expected_end_time = clip_times.1;
    // Milliseconds of slack allowed on start/stop times.  We allow one full
    // fast poll period to take care of edge cases.  The specs don't need to be
    // tight here because it doesn't matter if we collect one fewer sample (or
    // an extra one) at each end.
    let slack_ms = 101i64;
    assert_approx_eq!(
        start_time,
        expected_start_time,
        slack_ms,
        "unexpected start time for {}",
        clip_name
    );
    assert_approx_eq!(
        end_time,
        expected_end_time,
        slack_ms,
        "unexpected end time for {}",
        clip_name
    );

    // Check sample count.  Must keep track of low_mem -> not low_mem transitions.
    let mut in_low_mem = false;
    let expected_sample_count_from_events: usize = events
        .iter()
        .map(|e| {
            let sample_count_for_event = if e.time <= start_time || e.time > end_time {
                0
            } else {
                match e.event_type {
                    // These generate 1 sample only when moving out of high pressure.
                    TestEventType::EnterLowPressure | TestEventType::EnterMediumPressure => {
                        if in_low_mem {
                            1
                        } else {
                            0
                        }
                    }
                    _ => 1,
                }
            };
            match e.event_type {
                TestEventType::EnterHighPressure => in_low_mem = true,
                TestEventType::EnterLowPressure | TestEventType::EnterMediumPressure => {
                    in_low_mem = false
                }
                _ => {}
            }
            sample_count_for_event
        })
        .sum();

    // We include samples both at the beginning and end of the range, so we
    // need to add 1.  Note that here we use the actual sample times, not the
    // expected times.
    let expected_sample_count_from_timer = ((end_time - start_time) / 100) as usize + 1;
    let expected_sample_count =
        expected_sample_count_from_events + expected_sample_count_from_timer;
    let sample_count = lines.len() - 2;
    assert_eq!(
        sample_count, expected_sample_count,
        "unexpected sample count for {}",
        clip_name
    );
    Ok(())
}

fn verify_test_results(descriptor: &str, log_directory: &Path) -> Result<()> {
    let all_descriptors = trim_descriptor(descriptor);
    let result_descriptor = &all_descriptors[all_descriptors.len() - 1];
    let clips = expected_clips(result_descriptor);
    let events = events_from_test_descriptor(descriptor);

    // Check that there are no more clips than expected.
    let files_count = std::fs::read_dir(log_directory)?.count();
    // Subtract one for the memd.parameters file.
    assert_eq!(clips.len(), files_count - 1, "wrong number of clip files");

    for (clip_number, clip) in clips.iter().enumerate() {
        let clip_path = log_directory.join(format!("memd.clip{:03}.log", clip_number));
        check_clip(*clip, clip_path, &events)?;
    }
    Ok(())
}

fn create_dir_all(path: &Path) -> Result<()> {
    let result = std::fs::create_dir_all(path);
    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("create_dir_all: {}: {:?}", path.to_string_lossy(), e).into()),
    }
}

pub fn teardown_test_environment(paths: &Paths) {
    std::fs::remove_dir_all(&paths.testing_root).unwrap_or_else(|_| {
        panic!(
            "teardown: could not remove {}",
            paths.testing_root.to_str().unwrap()
        )
    });
}

pub fn setup_test_environment(paths: &Paths) {
    std::fs::create_dir(&paths.testing_root)
        .unwrap_or_else(|_| panic!("cannot create {}", paths.testing_root.to_str().unwrap()));
    mkfifo(&paths.testing_root.join(MOCK_DBUS_FIFO_NAME)).expect("failed to make mock dbus fifo");
    create_dir_all(paths.vmstat.parent().unwrap()).expect("cannot create /proc");
    create_dir_all(paths.available.parent().unwrap()).expect("cannot create ../chromeos-low-mem");
    let sys_vm = paths.testing_root.join("proc/sys/vm");
    create_dir_all(&sys_vm).expect("cannot create /proc/sys/vm");
    create_dir_all(paths.low_mem_device.parent().unwrap()).expect("cannot create /dev");

    let vmstat_content = include_str!("vmstat_content");
    let zoneinfo_content = include_str!("zoneinfo_content");
    print_to_path!(&paths.vmstat, "{}", vmstat_content).expect("cannot initialize vmstat");
    print_to_path!(&paths.zoneinfo, "{}", zoneinfo_content).expect("cannot initialize zoneinfo");
    print_to_path!(&paths.available, "{}\n", LOW_MEM_HIGH_AVAILABLE)
        .expect("cannot initialize available");
    print_to_path!(&paths.runnables, "0.16 0.18 0.22 4/981 8504")
        .expect("cannot initialize runnables");
    print_to_path!(
        &paths.low_mem_margin,
        "{} {}",
        LOW_MEM_MARGIN,
        LOW_MEM_MARGIN * 2
    )
    .expect("cannot initialize low_mem_margin");

    print_to_path!(sys_vm.join("min_filelist_kbytes"), "100000\n")
        .expect("cannot initialize min_filelist_kbytes");
    print_to_path!(sys_vm.join("min_free_kbytes"), "80000\n")
        .expect("cannot initialize min_free_kbytes");
    print_to_path!(sys_vm.join("extra_free_kbytes"), "60000\n")
        .expect("cannot initialize extra_free_kbytes");

    mkfifo(&paths.low_mem_device).expect("could not make mock low-mem device");
}

pub fn read_loadavg() {
    // Calling getpid() is always safe.
    let temp_file_name = format!("/tmp/memd-loadavg-{}", unsafe { libc::getpid() });
    let mut temp_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&temp_file_name)
        .expect("cannot create");
    // Unlink file immediately for more reliable cleanup.
    std::fs::remove_file(&temp_file_name).expect("cannot remove");

    temp_file
        .write_all("0.42 0.31 1.50 44/1234 56789".as_bytes())
        .expect("cannot write");
    temp_file
        .seek(std::io::SeekFrom::Start(0))
        .expect("cannot seek");
    assert_eq!(get_runnables(&temp_file).unwrap(), 44);
    temp_file
        .seek(std::io::SeekFrom::Start(0))
        .expect("cannot seek");
    temp_file
        .write_all("1122.12 25.87 19.51 33/1234 56789".as_bytes())
        .expect("cannot write");
    temp_file
        .seek(std::io::SeekFrom::Start(0))
        .expect("cannot seek");
    assert_eq!(get_runnables(&temp_file).unwrap(), 33);
}

pub fn queue_loop() {
    let mut sq = SampleQueue::new();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(false)
        .open("/dev/null")
        .unwrap();
    // We'll compare this uptime against the start_time of 0 in |output_from_time|, to ensure that
    // we don't stop looping in the array due to uptime.
    let s = Sample {
        uptime: 1,
        sample_type: SampleType::EnterLowMem,
        ..Default::default()
    };

    sq.samples = [s; SAMPLE_QUEUE_LENGTH];
    sq.head = 30;
    sq.count = 30;
    sq.output_from_time(&mut file, /*start_time=*/ 0).unwrap();
}

pub fn read_vmstat(paths: &Paths) {
    setup_test_environment(paths);
    let mut vmstat_values: [u64; VMSTAT_VALUES_COUNT] = [0, 0, 0, 0, 0];
    get_vmstats(
        &File::open(&paths.vmstat).expect("cannot open vmstat"),
        &mut vmstat_values,
    )
    .expect("get_vmstats failure");
    // Check one simple and one accumulated value.
    assert_eq!(vmstat_values[1], 678);
    assert_eq!(vmstat_values[2], 66);
    teardown_test_environment(paths);
}
