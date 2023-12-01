// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides the ability to monitor and control a memcg's memory usage.

use std::cell::RefCell;
use std::ffi::CString;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::mem;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::path::PathBuf;
use std::ptr::null_mut;
use std::rc::Rc;
use std::result::Result as StdResult;
use std::string::String;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use libc::c_void;
use libc::inotify_add_watch;
use libc::inotify_event;
use libc::inotify_init1;
use libc::itimerspec;
use libc::time_t;
use libc::timerfd_create;
use libc::timerfd_settime;
use libc::CLOCK_MONOTONIC;
use libc::IN_MODIFY;
use libc::O_NONBLOCK;
use libc::TFD_CLOEXEC;
use libchromeos::sys::unix::round_up_to_page_size;
use libsirenia::linux::events::EventMultiplexer;
use libsirenia::linux::events::EventSource;
use libsirenia::linux::events::Mutator;
use libsirenia::linux::events::RemoveFdMutator;
use libsirenia::sys;
use log::error;
use log::info;
use log::warn;

/// Trait which should respond to memory limit changes.
pub trait MemcgController {
    /// Called when the memcg's memory allocation should be changed. |delta| is the
    /// requested change in bytes, and this function should return the actual amount
    /// to change.
    ///
    /// When |delta| is negative, this is called after the memcg's limits have been
    /// adjusted. When |delta| is positive, this is called before the memcg's limits
    /// get adjusted.
    fn on_allocation_change(&self, delta: i64) -> i64;
}

struct MemcgGroup {
    // Path to the memcg directory
    path: PathBuf,

    // Various files from the memcg directory
    high_limit: File,
    max_limit: File,
    cur_bytes: File,
    events: File,

    // The current max limit of the memcg
    max_limit_bytes: u64,

    // High watermark event count used to detect and filter out other memcg events.
    high_watermark_event_count: u64,

    // Counts the number of times we've checked to see if the limit can
    // decrease without seeing the high limit being breached. Used for
    // backoff in the timer and to progressively tighten the limits.
    no_increase_count: u32,

    // Timerfd used for polling to decrease memory limits
    timer: File,
}

// The relationship between the high and max limits is:
//
//   max_limit = max(high_limit + 8MiB, high_limit * 1.08)
//
// This ensures that it takes >10 seconds between breaching the high
// limit and breaching the max limit, which should give enough time
// to inflate the balloon and reclaim memory before a memcg OOM.
fn compute_max_limit_from_high_limit(val: u64) -> u64 {
    if val > 100 * 1024 * 1024 {
        (val as f64 * 1.08) as u64
    } else {
        val + 8 * 1024 * 1024
    }
}

fn compute_high_limit_from_max_limit(val: u64) -> u64 {
    if val > 108 * 1024 * 1024 {
        (val as f64 / 1.08) as u64
    } else {
        val - 8 * 1024 * 1024
    }
}

// Computes the next limit from the given limit. The relation is:
//
//   next_limit = max(cur_limit * 1.1, cur_limit + 10MiB)
//
// The gap between the current and next limit provides slack before the
// limit needs to be increased again, at the cost of potentially reserving
// more memory than the memcg will actually use. The current formula was
// picked somewhat arbitrarily to provide a reasonable trade-off here.
fn compute_next_max_limit(val: u64) -> u64 {
    ((val as f64 * 1.1) as u64).max(val + (10 * 1024 * 1024))
}

impl MemcgGroup {
    fn new(name: &str, initial_max_limit_bytes: u64) -> Result<Self> {
        let cgroup = Path::new("/sys/kernel/cgroup").join(name);
        let mut events = File::open(cgroup.join("memory.events"))?;
        let high_limit = OpenOptions::new()
            .read(true)
            .write(true)
            .open(cgroup.join("memory.high"))?;
        let max_limit = OpenOptions::new()
            .read(true)
            .write(true)
            .open(cgroup.join("memory.max"))?;

        // Safe because we check the return value.
        let timer_fd = unsafe { timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC) };
        if timer_fd < 0 {
            bail!("Failed to create timer fd: {}", sys::errno());
        }
        // Safe since we own the fd
        let timer = unsafe { File::from_raw_fd(timer_fd) };

        let mut memcg = MemcgGroup {
            path: cgroup.clone(),

            high_watermark_event_count: read_watermark_event_count(&mut events, "high")?,
            max_limit_bytes: 0,
            no_increase_count: 0,
            timer,

            high_limit,
            max_limit,
            cur_bytes: File::open(cgroup.join("memory.current"))?,
            events,
        };

        memcg.set_max_limit_bytes(initial_max_limit_bytes)?;
        Ok(memcg)
    }

    // Sets |memory.max| to the given value, and sets |memory.high| to the
    // corresponding value to ensure the monitor has sufficient time to respond to
    // allocations.
    fn set_max_limit_bytes(&mut self, max_limit: u64) -> Result<()> {
        let high_limit = compute_high_limit_from_max_limit(max_limit);

        write_memcg_limit_file(&mut self.max_limit, max_limit)
            .context("failed to update max limit")?;
        write_memcg_limit_file(&mut self.high_limit, high_limit)
            .context("failed to update high limit")?;

        self.max_limit_bytes = max_limit;
        Ok(())
    }

    fn round_delta(delta: u64) -> u64 {
        round_up_to_page_size(delta as usize) as u64
    }

    fn get_cur_bytes(&mut self) -> Result<u64> {
        read_memcg_single_value_file(&mut self.cur_bytes)
    }

    // Gets the target |memory.max| to use when increasing memory limits.
    fn target_max_limit_increase(&self) -> u64 {
        Self::round_delta(compute_next_max_limit(self.max_limit_bytes) - self.max_limit_bytes)
    }

    // Gets the target |memory.max| to use when decreasing memory limits.
    fn target_max_limit_decrease(&mut self) -> Result<u64> {
        // Calculate the target max limit by assuming the current bytes
        // will become the new high limit. To prevent oscillation of the
        // limit, add an extra margin based on how long it's been since
        // the memcg has breached its high limit (i.e. since it's allocated
        // a significant amount of memory).
        let cur_bytes = self.get_cur_bytes()?;
        let test_max_limit = compute_max_limit_from_high_limit(cur_bytes);
        let target_max_limit = {
            let extra_margin_fraction = if self.no_increase_count == 0 {
                1.0
            } else {
                (1.0 / (self.no_increase_count as f64)).max(0.1)
            };
            let extra_max_limit = compute_next_max_limit(test_max_limit);
            let extra_margin = (extra_max_limit - test_max_limit) as f64 * extra_margin_fraction;
            test_max_limit + (extra_margin as u64)
        };
        Ok(Self::round_delta(
            self.max_limit_bytes - target_max_limit.min(self.max_limit_bytes),
        ))
    }

    fn update_limits(&mut self, delta: i64) -> Result<()> {
        let new_limit = if delta > 0 {
            self.max_limit_bytes + delta as u64
        } else {
            self.max_limit_bytes - delta.unsigned_abs()
        };
        self.set_max_limit_bytes(new_limit)
    }

    fn set_next_timer(&mut self) -> Result<()> {
        let timeout_sec = 2_u64
            .checked_pow(self.no_increase_count)
            .unwrap_or(60)
            .min(60);

        // Safe since spec is a c struct where all-zeros is valid
        let mut spec: itimerspec = unsafe { mem::zeroed() };
        spec.it_value.tv_sec = timeout_sec as time_t;

        // Safe because it doesn't modify memory and we check the return value.
        let ret = unsafe { timerfd_settime(self.timer.as_raw_fd(), 0, &spec, null_mut()) };
        if ret < 0 {
            Err(anyhow!("Failed to arm timer fd: {}", sys::errno()))
        } else {
            Ok(())
        }
    }
}

fn read_watermark_event_count(events: &mut File, name: &str) -> Result<u64> {
    events
        .seek(SeekFrom::Start(0))
        .context("failed to reset events position")?;

    let mut buf = Vec::new();
    events
        .read_to_end(&mut buf)
        .context("failed to read events")?;
    for line in String::from_utf8_lossy(&buf).split('\n') {
        if line.contains(name) {
            return Ok(line.split_at(name.len()).1.trim().parse::<u64>().unwrap());
        }
    }

    Err(anyhow!("failed to find high event count"))
}

fn read_memcg_single_value_file(file: &mut File) -> Result<u64> {
    file.seek(SeekFrom::Start(0))
        .context("failed to reset position")?;

    let mut buf = Vec::new();
    file.read_to_end(&mut buf).context("failed to read")?;

    Ok(String::from_utf8_lossy(&buf)
        .trim()
        .parse::<u64>()
        .unwrap_or(u64::MAX))
}

fn write_memcg_limit_file(file: &mut File, limit: u64) -> Result<()> {
    file.seek(SeekFrom::Start(0))
        .context("failed to reset position")?;
    file.write(limit.to_string().as_bytes())
        .context(format!("failed to write to {}", file.as_raw_fd()))?;
    Ok(())
}

// Monitors for modifications to a memcg's event file.
struct InotifyMonitor {
    state: Rc<RefCell<MemcgGroup>>,
    inotify: File,
    controller: Rc<dyn MemcgController>,
}

impl InotifyMonitor {
    fn new(
        state: Rc<RefCell<MemcgGroup>>,
        controller: Rc<dyn MemcgController>,
    ) -> Result<InotifyMonitor> {
        // Safe because it doesn't modify memory and we check the return value.
        let inotify_fd = unsafe { inotify_init1(O_NONBLOCK) };
        if inotify_fd < 0 {
            bail!("Failed to create fd: {}", sys::errno());
        }
        // Safe because we own the fd.
        let inotify = unsafe { File::from_raw_fd(inotify_fd) };

        let path = CString::new(
            state
                .borrow()
                .path
                .join("memory.events")
                .to_string_lossy()
                .as_bytes(),
        )
        .context("failed to construct event path string")?;
        // Safe because it doesn't modify memory and we check the return value.
        let ret = unsafe { inotify_add_watch(inotify.as_raw_fd(), path.as_ptr(), IN_MODIFY) };
        if ret < 0 {
            bail!("Failed to add inotify watch: {}", sys::errno());
        }

        Ok(InotifyMonitor {
            state,
            inotify,
            controller,
        })
    }
}

impl AsRawFd for InotifyMonitor {
    fn as_raw_fd(&self) -> RawFd {
        self.inotify.as_raw_fd()
    }
}

impl Debug for InotifyMonitor {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InotifyMonitor")
            .field("path", &self.state.borrow().path)
            .finish()
    }
}

// Reads from the inotify file, returning whether or not there was a pending event.
fn read_inotify(inotify: &File) -> Result<bool> {
    //Safe because event is a c-struct where all zeros is valid.
    let mut event: inotify_event = unsafe { mem::zeroed() };
    // Safe because we check the return value and the kernel will only write to |event|.
    let len = unsafe {
        libc::read(
            inotify.as_raw_fd(),
            &mut event as *mut inotify_event as *mut c_void,
            mem::size_of::<inotify_event>(),
        )
    };
    if len > 0 || sys::errno() == libc::EAGAIN {
        Ok(len > 0)
    } else {
        Err(anyhow!("Failed to read from inotify fd: {}", sys::errno()))
    }
}

impl EventSource for InotifyMonitor {
    fn on_event(&mut self) -> StdResult<Option<Box<dyn Mutator>>, String> {
        // Drain all pending inotify events
        while read_inotify(&self.inotify).map_err(|e| format!("{:?}", e))? {}

        let mut state = self.state.borrow_mut();

        let new_high_count = read_watermark_event_count(&mut state.events, "high")
            .map_err(|e| format!("{:?}", e))?;
        if new_high_count == state.high_watermark_event_count {
            for evt in ["max", "oom", "oom_kill"] {
                if let Ok(val) = read_watermark_event_count(&mut state.events, evt) {
                    if val != 0 {
                        info!("Memcg {} event for {:?}, count {}", evt, state.path, val);
                    }
                }
            }
            return Ok(None);
        }
        state.high_watermark_event_count = new_high_count;

        let target_increase = state.target_max_limit_increase();
        if target_increase > 0 {
            let actual_delta = self.controller.on_allocation_change(target_increase as i64);
            state
                .update_limits(actual_delta)
                .map_err(|e| format!("{:?}", e))?;
        }
        state.no_increase_count = 0;
        state.set_next_timer().map_err(|e| format!("{:?}", e))?;

        Ok(None)
    }
}

// Polls a memcg's memory consumption to release unused memory.
struct MemcgSlackMonitor {
    state: Rc<RefCell<MemcgGroup>>,
    controller: Rc<dyn MemcgController>,
}

impl MemcgSlackMonitor {
    fn new(
        state: Rc<RefCell<MemcgGroup>>,
        controller: Rc<dyn MemcgController>,
    ) -> Result<MemcgSlackMonitor> {
        let monitor = MemcgSlackMonitor { state, controller };
        monitor.state.borrow_mut().set_next_timer()?;
        Ok(monitor)
    }
}

impl AsRawFd for MemcgSlackMonitor {
    fn as_raw_fd(&self) -> RawFd {
        self.state.borrow().timer.as_raw_fd()
    }
}

impl Debug for MemcgSlackMonitor {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemcgSlackMonitor")
            .field("path", &self.state.borrow().path)
            .finish()
    }
}

impl EventSource for MemcgSlackMonitor {
    fn on_event(&mut self) -> StdResult<Option<Box<dyn Mutator>>, String> {
        let mut state = self.state.borrow_mut();
        let mut buf: [u8; 8] = [0; 8];
        if let Err(e) = state.timer.read(&mut buf) {
            error!("Failed to reset timer {}", e);
            drop(state);
            return Ok(Some(Box::new(RemoveFdMutator(self.as_raw_fd()))));
        }

        let target_decrease = state
            .target_max_limit_decrease()
            .map_err(|e| format!("{:?}", e))?;
        if target_decrease > 0 {
            // Update the limits before changing the allocation, to ensure the app
            // doesn't OOM while we're releasing memory.
            let delta = -(target_decrease as i64);
            state.update_limits(delta).map_err(|e| format!("{:?}", e))?;

            let actual_delta = self.controller.on_allocation_change(delta);

            if actual_delta != delta {
                warn!(
                    "unexpected allocation change: expected={} actual={}",
                    delta, actual_delta
                );
                state
                    .update_limits(actual_delta - delta)
                    .map_err(|e| format!("{:?}", e))?;
            }
        }
        state.no_increase_count += 1;
        state.set_next_timer().map_err(|e| format!("{:?}", e))?;

        Ok(None)
    }
}

/// Start monitor the memcg |name|. Set it's initial memory limit to |initial_max_limit_bytes|.
pub fn monitor_memcg(
    name: &str,
    ctx: &mut EventMultiplexer,
    controller: Rc<dyn MemcgController>,
    initial_max_limit_bytes: u64,
) -> Result<()> {
    let state = Rc::new(RefCell::new(MemcgGroup::new(
        name,
        initial_max_limit_bytes,
    )?));

    ctx.add_event(Box::new(InotifyMonitor::new(
        state.clone(),
        controller.clone(),
    )?))
    .context("failed to add inotify monitor")?;

    ctx.add_event(Box::new(MemcgSlackMonitor::new(state, controller.clone())?))
        .context("failed to add slack monitor")?;

    Ok(())
}
