// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt;
use std::io;
use std::net::TcpStream;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::result;

use libc::{self, c_void, shutdown, EPIPE, SHUT_WR};
use libchromeos::sys::unix::vsock::VsockStream;

/// StreamSocket provides a generic abstraction around any connection-oriented stream socket.
/// The socket will be closed when StreamSocket is dropped, but writes to the socket can also
/// be shut down manually.
pub struct StreamSocket {
    fd: RawFd,
    shut_down: bool,
}

impl StreamSocket {
    /// Connects to the given socket address. Supported socket types are vsock, unix, and TCP.
    pub fn connect(sockaddr: &str) -> result::Result<StreamSocket, StreamSocketError> {
        const UNIX_PREFIX: &str = "unix:";
        const VSOCK_PREFIX: &str = "vsock:";

        if sockaddr.starts_with(VSOCK_PREFIX) {
            let vsock_stream = VsockStream::connect(sockaddr)
                .map_err(|e| StreamSocketError::ConnectVsock(sockaddr.to_string(), e))?;
            Ok(vsock_stream.into())
        } else if sockaddr.starts_with(UNIX_PREFIX) {
            let (_prefix, sock_path) = sockaddr.split_at(UNIX_PREFIX.len());
            let unix_stream = UnixStream::connect(sock_path)
                .map_err(|e| StreamSocketError::ConnectUnix(sockaddr.to_string(), e))?;
            Ok(unix_stream.into())
        } else {
            // Assume this is a TCP stream.
            let tcp_stream = TcpStream::connect(sockaddr)
                .map_err(|e| StreamSocketError::ConnectTcp(sockaddr.to_string(), e))?;
            Ok(tcp_stream.into())
        }
    }

    /// Shuts down writes to the socket using shutdown(2).
    pub fn shut_down_write(&mut self) -> io::Result<()> {
        // Safe because no memory is modified and the return value is checked.
        let ret = unsafe { shutdown(self.fd, SHUT_WR) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        self.shut_down = true;
        Ok(())
    }

    /// Returns true if the socket has been shut down for writes, false otherwise.
    pub fn is_shut_down(&self) -> bool {
        self.shut_down
    }
}

impl io::Read for StreamSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Safe because this will only modify the contents of |buf| and we check the return value.
        let ret = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(ret as usize)
    }
}

impl io::Write for StreamSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Safe because this doesn't modify any memory and we check the return value.
        let ret = unsafe { libc::write(self.fd, buf.as_ptr() as *const c_void, buf.len()) };
        if ret < 0 {
            // If a write causes EPIPE then the socket is shut down for writes.
            let err = io::Error::last_os_error();
            if let Some(errno) = err.raw_os_error() {
                if errno == EPIPE {
                    self.shut_down = true
                }
            }

            return Err(err);
        }

        Ok(ret as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        // No buffered data so nothing to do.
        Ok(())
    }
}

impl AsRawFd for StreamSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl From<TcpStream> for StreamSocket {
    fn from(stream: TcpStream) -> Self {
        StreamSocket {
            fd: stream.into_raw_fd(),
            shut_down: false,
        }
    }
}

impl From<UnixStream> for StreamSocket {
    fn from(stream: UnixStream) -> Self {
        StreamSocket {
            fd: stream.into_raw_fd(),
            shut_down: false,
        }
    }
}

impl From<VsockStream> for StreamSocket {
    fn from(stream: VsockStream) -> Self {
        StreamSocket {
            fd: stream.into_raw_fd(),
            shut_down: false,
        }
    }
}

impl FromRawFd for StreamSocket {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        StreamSocket {
            fd,
            shut_down: false,
        }
    }
}

impl Drop for StreamSocket {
    fn drop(&mut self) {
        // Safe because this doesn't modify any memory and we are the only
        // owner of the file descriptor.
        unsafe { libc::close(self.fd) };
    }
}

/// Error enums for StreamSocket.
#[remain::sorted]
#[derive(Debug)]
pub enum StreamSocketError {
    ConnectTcp(String, io::Error),
    ConnectUnix(String, io::Error),
    ConnectVsock(String, io::Error),
}

impl fmt::Display for StreamSocketError {
    #[remain::check]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::StreamSocketError::*;

        #[remain::sorted]
        match self {
            ConnectTcp(sockaddr, e) => {
                write!(f, "failed to connect to TCP sockaddr {}: {}", sockaddr, e)
            }
            ConnectUnix(sockaddr, e) => {
                write!(f, "failed to connect to unix sockaddr {}: {}", sockaddr, e)
            }
            ConnectVsock(sockaddr, e) => {
                write!(f, "failed to connect to vsock sockaddr {}: {}", sockaddr, e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::os::unix::net::{UnixListener, UnixStream};
    use tempfile::TempDir;

    #[test]
    fn sock_connect_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let sockaddr = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());

        let _stream = StreamSocket::connect(&sockaddr).unwrap();
    }

    #[test]
    fn sock_connect_unix() {
        let tempdir = TempDir::new().unwrap();
        let path = tempdir.path().to_owned().join("test.sock");
        let _listener = UnixListener::bind(&path).unwrap();

        let unix_addr = format!("unix:{}", path.to_str().unwrap());
        let _stream = StreamSocket::connect(&unix_addr).unwrap();
    }

    #[test]
    fn invalid_sockaddr() {
        assert!(StreamSocket::connect("this is not a valid sockaddr").is_err());
    }

    #[test]
    fn shut_down_write() {
        let (unix_stream, _dummy) = UnixStream::pair().unwrap();
        let mut stream: StreamSocket = unix_stream.into();

        stream.write_all(b"hello").unwrap();

        stream.shut_down_write().unwrap();

        assert!(stream.is_shut_down());
        assert!(stream.write(b"goodbye").is_err());
    }

    #[test]
    fn read_from_shut_down_sock() {
        let (unix_stream1, unix_stream2) = UnixStream::pair().unwrap();
        let mut stream1: StreamSocket = unix_stream1.into();
        let mut stream2: StreamSocket = unix_stream2.into();

        stream1.shut_down_write().unwrap();

        // Reads from the other end of the socket should now return EOF.
        let mut buf = Vec::new();
        assert_eq!(stream2.read_to_end(&mut buf).unwrap(), 0);
    }
}
