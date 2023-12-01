// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A syslog server interface for use with EventMultiplexer.

use std::boxed::Box;
use std::cell::RefCell;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fs::remove_file;
use std::io;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;

use libchromeos::scoped_path::get_temp_path;
use libchromeos::sys::getpid;
use libchromeos::sys::gettid;
use libchromeos::sys::handle_eintr;

use super::events::EventSource;
use super::events::Mutator;
use super::events::RemoveFdMutator;

pub const SYSLOG_PATH: &str = "/dev/log";

/// The maximum buffer size for a partial message.
pub const MAX_MESSAGE: usize = 4096;

/// The priority (i.e. severity) of a syslog message.
///
/// See syslog man pages for information on their semantics.
pub enum Priority {
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
    Debug = 7,
}

/// The facility of a syslog message.
///
/// See syslog man pages for information on their semantics.
#[derive(Copy, Clone)]
pub enum Facility {
    Kernel = 0,
    User = 1 << 3,
    Mail = 2 << 3,
    Daemon = 3 << 3,
    Auth = 4 << 3,
    Syslog = 5 << 3,
    Lpr = 6 << 3,
    News = 7 << 3,
    Uucp = 8 << 3,
    Local0 = 16 << 3,
    Local1 = 17 << 3,
    Local2 = 18 << 3,
    Local3 = 19 << 3,
    Local4 = 20 << 3,
    Local5 = 21 << 3,
    Local6 = 22 << 3,
    Local7 = 23 << 3,
}

/// A receiver of syslog messages. Note that one or more messages may be received together.
pub trait SyslogReceiver {
    fn receive(&self, data: Vec<u8>);
}

/// A trait that can be used along with RefCell to be used as a SyslogReceiver.
pub trait SyslogReceiverMut {
    fn receive(&mut self, data: Vec<u8>);
}

impl<R: SyslogReceiverMut> SyslogReceiver for RefCell<R> {
    fn receive(&self, data: Vec<u8>) {
        self.borrow_mut().receive(data);
    }
}

/// Encapsulates a unix socket listener for a syslog server that accepts client connections.
pub struct Syslog {
    log_path: PathBuf,
    socket: UnixDatagram,
    receiver: Rc<dyn SyslogReceiver>,
}

impl Syslog {
    pub fn get_test_log_path() -> PathBuf {
        // NOTE this changes based on thread id, so it should be different across concurrent
        // test cases.
        let path = get_temp_path(None).join(&SYSLOG_PATH[1..]);
        // Max Unix socket path is >100 and varies between OSes.
        if path.to_string_lossy().len() <= 100 {
            path
        } else {
            Path::new("/tmp")
                .join(format!("test-{}-{}", getpid(), gettid()))
                .join(&SYSLOG_PATH[1..])
        }
    }

    /// Binds a new unix socket listener at the SYSLOG_PATH.
    pub fn new<P: AsRef<Path>>(
        log_path: P,
        receiver: Rc<dyn SyslogReceiver>,
    ) -> Result<Self, io::Error> {
        Ok(Syslog {
            log_path: log_path.as_ref().to_path_buf(),
            socket: UnixDatagram::bind(log_path)?,
            receiver,
        })
    }
}

/// Cleanup the unix socket by removing SYSLOG_PATH whenever the Syslog is dropped.
impl Drop for Syslog {
    fn drop(&mut self) {
        if let Err(e) = remove_file(&self.log_path) {
            if e.kind() != io::ErrorKind::NotFound {
                eprintln!("Failed to cleanup syslog: {:?}", e);
            }
        }
    }
}

impl AsRawFd for Syslog {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

impl Debug for Syslog {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Syslog")
            .field("log_path", &self.log_path)
            .field("socket", &self.socket)
            .finish()
    }
}

/// Creates a EventSource that adds any accept connections and returns a Mutator that will add the
/// client connection to the EventMultiplexer when applied.
impl EventSource for Syslog {
    fn on_event(&mut self) -> Result<Option<Box<dyn Mutator>>, String> {
        let mut buffer: [u8; MAX_MESSAGE] = [0; MAX_MESSAGE];
        Ok(match handle_eintr!(self.socket.recv_from(&mut buffer)) {
            Ok((len, _)) => {
                self.receiver.receive(buffer[..len].to_vec());
                None
            }
            Err(_) => Some(Box::new(RemoveFdMutator(self.as_raw_fd()))),
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;
    use std::sync::Barrier;
    use std::thread::spawn;

    use assert_matches::assert_matches;
    use libchromeos::scoped_path::ScopedPath;

    use super::*;
    use crate::linux::events::EventMultiplexer;

    struct TestReciever(Vec<Vec<u8>>);

    impl AsRef<Vec<Vec<u8>>> for TestReciever {
        fn as_ref(&self) -> &Vec<Vec<u8>> {
            &self.0
        }
    }

    impl SyslogReceiverMut for TestReciever {
        fn receive(&mut self, data: Vec<u8>) {
            self.0.push(data);
        }
    }

    fn get_test_receiver() -> Rc<RefCell<TestReciever>> {
        Rc::new(RefCell::new(TestReciever(Vec::new())))
    }

    #[test]
    fn syslog_new_fail() {
        let test_path = ScopedPath::create(Syslog::get_test_log_path()).unwrap();
        assert!(test_path.exists());

        let receiver = get_test_receiver();
        assert!(Syslog::new(Syslog::get_test_log_path(), receiver).is_err());
    }

    #[test]
    fn syslog_new_drop() {
        let log_path = Syslog::get_test_log_path();
        let test_path = ScopedPath::create(log_path.parent().unwrap()).unwrap();
        assert!(test_path.exists());
        assert!(!log_path.exists());

        let receiver = get_test_receiver();
        {
            let syslog = Syslog::new(Syslog::get_test_log_path(), receiver).unwrap();
            assert!(syslog.log_path.exists());
        }
        assert!(!log_path.exists());
    }

    #[test]
    fn syslog_overflow() {
        let log_path = Syslog::get_test_log_path();
        let _test_path = ScopedPath::create(log_path.parent().unwrap()).unwrap();
        let message: Vec<u8> = vec![b' '; MAX_MESSAGE + 1];
        let receiver = get_test_receiver();
        let mut syslog = Syslog::new(log_path.clone(), receiver.clone()).unwrap();
        assert!(log_path.exists());
        assert!(receiver.borrow().as_ref().is_empty());

        let connect_path = log_path.clone();
        let local_check = Arc::new(Barrier::new(2));
        let client_check = Arc::clone(&local_check);
        let client = spawn(move || {
            let socket = UnixDatagram::unbound().unwrap();
            socket.send_to(&message, connect_path).unwrap();

            // Make sure the read happens before dropping the socket.
            client_check.wait();
        });
        assert_matches!(syslog.on_event(), Ok(None));
        assert_eq!(receiver.as_ref().borrow().as_ref().len(), 1);
        assert_eq!(receiver.as_ref().borrow().as_ref()[0].len(), MAX_MESSAGE);
        local_check.wait();
        client.join().unwrap();
    }

    #[test]
    fn syslog_eventmultiplexer_integration() {
        let log_path = Syslog::get_test_log_path();
        let test_path = ScopedPath::create(log_path.parent().unwrap()).unwrap();
        assert!(test_path.exists());
        assert!(!log_path.exists());

        let receiver = get_test_receiver();
        let syslog = Syslog::new(log_path.clone(), receiver.clone()).unwrap();
        assert!(log_path.exists());
        let mut context = EventMultiplexer::new().unwrap();
        context.add_event(Box::new(syslog)).unwrap();

        let connect_path = log_path.clone();
        let local_check = Arc::new(Barrier::new(2));
        let client_check = Arc::clone(&local_check);
        let client = spawn(move || {
            let socket = UnixDatagram::unbound().unwrap();
            socket
                .send_to("Test Data\n".as_bytes(), connect_path)
                .unwrap();

            // Make sure the read happens before dropping the socket.
            client_check.wait();
        });

        // Check Syslog::on_event().
        context.run_once().unwrap();
        assert_eq!(receiver.as_ref().borrow().as_ref().len(), 1);
        local_check.wait();
        client.join().unwrap();
    }
}
