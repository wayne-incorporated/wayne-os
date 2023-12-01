// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This is a rework of crosvm/devices/src/utils/event_loop.rs for single threaded use.
// Notable changes:
//   * FailHandles were removed
//   * The Weak references to callbacks were upgraded to ownership. This enables functionality
//     like socket servers where the callback struct is owned by the event_loop and is dropped when
//     the fd is removed from the event loop.
//   * EventLoop::start(...) was split into EventMultiplexer::new() and
//     EventMultiplexer::run_once(). The initialization was put in EventMultiplexer::new(), and the
//     thread and loop were removed replaced with a single wait call in
//     EventMultiplexer::run_once().
//   * To make this work with a single thread without mutexes, Mutators were introduced as the
//     return type for on_event(). The mutator enables actions like removing a fd from the
//     EventMultiplexer on a recoverable error, or adding a new EventSource when a Listener accepts
//     a new stream.

use std::boxed::Box;
use std::cmp::max;
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use std::result::Result as StdResult;

use libchromeos::sys::Error as SysError;
use log::error;
use log::warn;
use thiserror::Error as ThisError;

use crate::linux::poll::PollContext;
use crate::linux::poll::PollToken;
use crate::linux::poll::WatchingEvents;
use crate::sys::eagain_is_ok;
use crate::sys::set_nonblocking;
use crate::sys::write_all_blocking;
use crate::transport::TransportRead;
use crate::transport::TransportWrite;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("failed to create poll context: {0}")]
    CreatePollContext(#[source] SysError),
    #[error("failed to add fd to poll context: {0}")]
    PollContextAddFd(#[source] SysError),
    #[error("failed to delete fd from poll context: {0}")]
    PollContextDeleteFd(#[source] SysError),
    #[error("failed to wait for events using the poll context: {0}")]
    PollContextWait(#[source] SysError),
    #[error("event failed: {0}")]
    OnEvent(String),
    #[error("hangup failed: {0}")]
    OnHangUp(String),
    #[error("mutate failed: {0}")]
    OnMutate(String),
    #[error("failed to set nonblocking: {0}")]
    SetNonBlocking(#[source] SysError),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Fd is a wrapper of RawFd. It implements AsRawFd trait and PollToken trait for RawFd.
/// It does not own the fd, thus won't close the fd when dropped.
struct Fd(pub RawFd);
impl AsRawFd for Fd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl PollToken for Fd {
    fn as_raw_token(&self) -> u64 {
        self.0 as u64
    }

    fn from_raw_token(data: u64) -> Self {
        Fd(data as RawFd)
    }
}

/// Additional abstraction on top of PollContext to make it possible to multiplex listeners,
/// streams, (anything with AsRawFd) on a single thread.
pub struct EventMultiplexer {
    poll_ctx: PollContext<Fd>,
    handlers: BTreeMap<RawFd, Box<dyn EventSource>>,
}

/// A trait that represents an object that can mutate an EventMultiplexer.
pub trait Mutator: Debug {
    fn mutate(&mut self, event_loop: &mut EventMultiplexer) -> std::result::Result<(), String>;
}

/// Interface for event handler.
pub trait EventSource: AsRawFd + Debug {
    /// Provide the events to watch. EPOLLHUP, EPOLLRDHUP, and read are covered by default.
    fn get_events(&self) -> WatchingEvents {
        WatchingEvents::new(libc::EPOLLRDHUP as u32).set_read()
    }

    /// Callback to be executed when the event loop encounters an event for this handler.
    fn on_event(&mut self) -> std::result::Result<Option<Box<dyn Mutator>>, String> {
        Ok(None)
    }

    /// Callback to be executed when either EPOLLHUP or EPOLLRDHUP are received.
    fn on_hangup(&mut self) -> std::result::Result<Option<Box<dyn Mutator>>, String> {
        Ok(None)
    }
}

impl EventMultiplexer {
    /// Initialize the EventMultiplexer.
    pub fn new() -> Result<EventMultiplexer> {
        let handlers: BTreeMap<RawFd, Box<dyn EventSource>> = BTreeMap::new();
        let poll_ctx: PollContext<Fd> = PollContext::new().map_err(Error::CreatePollContext)?;

        Ok(EventMultiplexer { poll_ctx, handlers })
    }

    /// Wait until there are events to process. Then, process them. If an error is returned, there
    /// may still events to process.
    pub fn run_once(&mut self) -> Result<()> {
        let mut to_hang_up: Vec<RawFd> = Vec::new();
        let mut to_read: Vec<RawFd> = Vec::new();
        for event in self.poll_ctx.wait().map_err(Error::PollContextWait)?.iter() {
            let fd = event.token().as_raw_fd();
            if event.readable() {
                to_read.push(fd);
            }
            if event.hungup() {
                to_hang_up.push(fd);
            }
            if !(event.readable() || event.hungup()) {
                warn!("unattributed event for {}", fd);
                to_hang_up.push(fd);
            }
        }

        for fd in to_read {
            let mutator: Option<Box<dyn Mutator>> = match self.handlers.get_mut(&fd) {
                Some(cb) => cb.on_event().map_err(Error::OnEvent)?,
                None => {
                    warn!("callback for fd {} already removed", fd);
                    continue;
                }
            };

            if let Some(mut m) = mutator {
                m.mutate(self).map_err(Error::OnMutate)?;
            }
        }

        for &fd in &to_hang_up {
            let mutator: Option<Box<dyn Mutator>> = match self.handlers.get_mut(&fd) {
                Some(cb) => cb.on_hangup().map_err(Error::OnHangUp)?,
                None => {
                    continue;
                }
            };

            if let Some(mut m) = mutator {
                m.mutate(self).map_err(Error::OnMutate)?;
            }
        }

        for fd in to_hang_up {
            // The fd might have already been removed. If so, do not remove it again.
            if !self.handlers.contains_key(&fd) {
                continue;
            }

            self.remove_event_for_fd(&Fd(fd))
                .map_err(|err| {
                    error!("failed to remove event fd: {:?}", err);
                })
                .ok();
        }

        Ok(())
    }

    /// Return true if the specified fd is tracked by the EventMultiplexer.
    pub fn has_fd(&self, fd: RawFd) -> bool {
        self.handlers.contains_key(&fd)
    }

    /// Add a new event to multiplexer. The handler will be invoked when `event` happens on `fd`.
    pub fn add_event(&mut self, handler: Box<dyn EventSource>) -> Result<()> {
        let events = handler.get_events();
        let fd = handler.as_raw_fd();
        self.handlers.insert(fd, handler);
        // This might fail due to epoll syscall. Check epoll_ctl(2).
        self.poll_ctx
            .add_fd_with_events(&Fd(fd), events, Fd(fd))
            .map_err(Error::PollContextAddFd)
    }

    /// Stops listening for events for this `fd`. This function returns an error if it fails, or the
    /// removed EventSource if it succeeds.
    ///
    /// EventMultiplexer does not guarantee all events for `fd` is handled.
    pub fn remove_event_for_fd(&mut self, fd: &dyn AsRawFd) -> Result<Box<dyn EventSource>> {
        // This might fail due to epoll syscall. Check epoll_ctl(2).
        let ret = self.poll_ctx.delete(fd).map_err(Error::PollContextDeleteFd);
        let handler = self.handlers.remove(&fd.as_raw_fd());
        ret?;
        Ok(handler.unwrap())
    }

    /// Returns true if there are no event sources registered.
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    /// Returns the number of handlers.
    pub fn len(&self) -> usize {
        self.handlers.len()
    }
}

/// Mutator which combines other mutators into one.
pub struct ComboMutator<I: Iterator<Item = Box<dyn Mutator>>>(I);

impl<I: Iterator<Item = Box<dyn Mutator>>> From<I> for ComboMutator<I> {
    fn from(mutators: I) -> Self {
        ComboMutator(mutators)
    }
}

impl<I: Iterator<Item = Box<dyn Mutator>>> Debug for ComboMutator<I> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComboMutator").finish()
    }
}

impl<I: Iterator<Item = Box<dyn Mutator>>> Mutator for ComboMutator<I> {
    fn mutate(&mut self, event_loop: &mut EventMultiplexer) -> StdResult<(), String> {
        let mut ret = StdResult::<(), String>::Ok(());
        for mut mutator in &mut self.0 {
            if let Err(msg) = mutator.as_mut().mutate(event_loop) {
                if let Err(ret_msg) = ret.as_mut() {
                    ret_msg.push('\n');
                    ret_msg.push_str(&msg);
                } else {
                    ret = Err(msg);
                }
            }
        }
        ret
    }
}

#[derive(Debug)]
/// Adds the specified EventSource from the EventMultiplexer when the mutator is executed.
pub struct AddEventSourceMutator(Option<Box<dyn EventSource>>);

impl<E: 'static + EventSource> From<E> for AddEventSourceMutator {
    fn from(event_source: E) -> Self {
        AddEventSourceMutator(Some(Box::new(event_source)))
    }
}

impl Mutator for AddEventSourceMutator {
    fn mutate(&mut self, event_loop: &mut EventMultiplexer) -> StdResult<(), String> {
        match std::mem::replace(&mut self.0, None) {
            Some(b) => event_loop
                .add_event(b)
                .map_err(|e| format!("failed to add fd: {:?}", e)),
            None => Err("AddHandlerMutator::mutate called for empty fd".to_string()),
        }
    }
}

#[derive(Debug)]
/// Removes the specified RawFd from the EventMultiplexer when the mutator is executed.
pub struct RemoveFdMutator(pub RawFd);

impl Mutator for RemoveFdMutator {
    fn mutate(&mut self, event_loop: &mut EventMultiplexer) -> StdResult<(), String> {
        if !event_loop.has_fd(self.as_raw_fd()) {
            return Ok(());
        }
        match event_loop.remove_event_for_fd(self) {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("failed to remove fd: {:?}", e)),
        }
    }
}

impl AsRawFd for RemoveFdMutator {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

#[derive(Debug)]
/// Tool for copying from a source to a sink. It should be used along with a HangupListener for the
/// sink.
pub struct CopyFdEventSource {
    input: Box<dyn TransportRead>,
    output: Box<dyn TransportWrite>,
}

impl CopyFdEventSource {
    /// Return a CopyFdEventSource and associated HangupListener.
    pub fn new(
        input: Box<dyn TransportRead>,
        output: Box<dyn TransportWrite>,
    ) -> Result<(Self, HangupListener)> {
        set_nonblocking(input.as_raw_fd()).map_err(Error::SetNonBlocking)?;
        let copy = CopyFdEventSource { input, output };
        let hang_up = HangupListener::new(copy.output.as_raw_fd(), copy.create_removal_mutator());
        Ok((copy, hang_up))
    }

    fn create_removal_mutator(&self) -> Box<dyn Mutator> {
        // Since the CopyFdEventSource owns the fd for the HangupListener, we need
        // to remove the HangupListener first to avoid an EBADF when unregistering
        // the HangupListener.
        Box::new(ComboMutator::from(IntoIterator::into_iter([
            Box::new(RemoveFdMutator(self.output.as_raw_fd())) as Box<dyn Mutator>,
            Box::new(RemoveFdMutator(self.input.as_raw_fd())) as Box<dyn Mutator>,
        ])))
    }
}

impl AsRawFd for CopyFdEventSource {
    fn as_raw_fd(&self) -> RawFd {
        self.input.as_raw_fd()
    }
}

impl EventSource for CopyFdEventSource {
    fn on_event(&mut self) -> StdResult<Option<Box<dyn Mutator>>, String> {
        let mut buf = [0u8; 1024];
        loop {
            match eagain_is_ok(self.input.read(&mut buf)) {
                Ok(Some(0)) | Err(_) => break,
                Ok(Some(size)) => {
                    // This is somewhat hacky, but it is used here because serial is only
                    // used by developers for debugging and so this isn't performance
                    // critical.
                    if write_all_blocking(&mut self.output, &buf[..size]).is_err() {
                        break;
                    }
                }
                Ok(None) => return Ok(None),
            }
        }
        Ok(Some(self.create_removal_mutator()))
    }

    fn on_hangup(&mut self) -> StdResult<Option<Box<dyn Mutator>>, String> {
        Ok(Some(Box::new(RemoveFdMutator(self.output.as_raw_fd()))))
    }
}

#[derive(Debug)]
/// Tool for logging lines from a source.
pub struct LogFromFdEventSource {
    proc_name: String,
    input: Box<dyn TransportRead>,
    line_buffer: VecDeque<u8>,
}

impl LogFromFdEventSource {
    /// Return a LogFromFdEventSource from the specific input with the specific label.
    pub fn new(proc_name: String, input: Box<dyn TransportRead>) -> Result<Self> {
        set_nonblocking(input.as_raw_fd()).map_err(Error::SetNonBlocking)?;
        Ok(LogFromFdEventSource {
            proc_name,
            input,
            line_buffer: VecDeque::with_capacity(1024),
        })
    }

    pub fn flush(&mut self) {
        let buffer = self.line_buffer.make_contiguous();
        let mut begin = 0usize;
        for at in 0..buffer.len() {
            if buffer[at] == b'\n' {
                error!(
                    "{}: {}",
                    &self.proc_name,
                    String::from_utf8_lossy(&buffer[begin..at])
                );
                begin = at + 1;
            }
        }
        self.line_buffer.drain(..begin);
    }
}

impl AsRawFd for LogFromFdEventSource {
    fn as_raw_fd(&self) -> RawFd {
        self.input.as_raw_fd()
    }
}

impl EventSource for LogFromFdEventSource {
    fn on_event(&mut self) -> StdResult<Option<Box<dyn Mutator>>, String> {
        loop {
            let used = self.line_buffer.len();
            self.line_buffer
                .resize(max(used + 1024, self.line_buffer.capacity()), 0u8);
            let buffer = self.line_buffer.make_contiguous();

            match eagain_is_ok(self.input.read(&mut buffer[used..])) {
                Ok(Some(0)) | Err(_) => break,
                Ok(Some(size)) => {
                    self.line_buffer.resize(used + size, 0u8);
                    self.flush()
                }
                Ok(None) => return Ok(None),
            }
        }
        error!(
            "{}: {}",
            &self.proc_name,
            String::from_utf8_lossy(self.line_buffer.make_contiguous())
        );
        self.line_buffer.clear();
        Ok(Some(Box::new(RemoveFdMutator(self.as_raw_fd()))))
    }
}

#[derive(Debug)]
/// Executes a mutator when a specified file descriptor is closed. This is particularly useful for
/// detecting when a writer closes.
pub struct HangupListener {
    fd: RawFd,
    mutator: Option<Box<dyn Mutator>>,
}

impl HangupListener {
    pub fn new(fd: RawFd, mutator: Box<dyn Mutator>) -> Self {
        HangupListener {
            fd,
            mutator: Some(mutator),
        }
    }
}

impl AsRawFd for HangupListener {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl EventSource for HangupListener {
    fn get_events(&self) -> WatchingEvents {
        // We are only interested in the hang-up.
        WatchingEvents::new(libc::EPOLLRDHUP as u32)
    }

    fn on_hangup(&mut self) -> StdResult<Option<Box<dyn Mutator>>, String> {
        Ok(std::mem::replace(&mut self.mutator, None))
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::fs::File;
    use std::io::Read;
    use std::io::Write;
    use std::rc::Rc;

    use libchromeos::deprecated::EventFd;
    use libchromeos::sys::unix::pipe;

    use super::*;

    #[derive(Debug)]
    struct EventMultiplexerTestHandler {
        val: Rc<RefCell<u8>>,
        evt: File,
    }

    impl AsRawFd for EventMultiplexerTestHandler {
        fn as_raw_fd(&self) -> i32 {
            self.evt.as_raw_fd()
        }
    }

    impl EventSource for EventMultiplexerTestHandler {
        fn on_event(&mut self) -> std::result::Result<Option<Box<dyn Mutator>>, String> {
            let mut buf: [u8; 1] = [0; 1];
            self.evt.read_exact(&mut buf).unwrap();
            *self.val.borrow_mut() += 1;
            Ok(None)
        }
    }

    #[test]
    fn event_multiplexer_test() {
        let mut l = EventMultiplexer::new().unwrap();
        let (r, mut w) = pipe(false /*close_on_exec*/).unwrap();
        let counter: Rc<RefCell<u8>> = Rc::new(RefCell::new(0));
        let h = EventMultiplexerTestHandler {
            val: Rc::clone(&counter),
            evt: r,
        };
        l.add_event(Box::new(h)).unwrap();

        // Check write.
        let buf: [u8; 1] = [1; 1];
        w.write_all(&buf).unwrap();
        l.run_once().unwrap();
        assert_eq!(*counter.borrow(), 1);

        // Check hangup.
        drop(w);
        l.run_once().unwrap();
        assert!(l.handlers.is_empty());
    }

    #[derive(Debug)]
    struct MutatorTestHandler(EventFd);

    impl AsRawFd for MutatorTestHandler {
        fn as_raw_fd(&self) -> i32 {
            self.0.as_raw_fd()
        }
    }

    impl EventSource for MutatorTestHandler {
        fn on_event(&mut self) -> std::result::Result<Option<Box<dyn Mutator>>, String> {
            Ok(None)
        }
    }

    #[test]
    fn add_event_source_mutator_test() {
        let mut l = EventMultiplexer::new().unwrap();
        let h = MutatorTestHandler(EventFd::new().unwrap());

        assert!(l.handlers.is_empty());
        AddEventSourceMutator(Some(Box::new(h)))
            .mutate(&mut l)
            .unwrap();
        assert!(!l.handlers.is_empty());
    }

    #[test]
    fn remove_fd_mutator_test() {
        let mut l = EventMultiplexer::new().unwrap();
        let h = MutatorTestHandler(EventFd::new().unwrap());
        let mut m = RemoveFdMutator(h.as_raw_fd());
        l.add_event(Box::new(h)).unwrap();

        assert!(!l.handlers.is_empty());
        m.mutate(&mut l).unwrap();
        assert!(l.handlers.is_empty());
    }
}
