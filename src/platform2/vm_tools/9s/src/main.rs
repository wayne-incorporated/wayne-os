// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Runs a [9P] server.
///
/// [9P]: http://man.cat-v.org/plan_9/5/0intro
extern crate getopts;
extern crate libc;
extern crate libchromeos;
#[macro_use]
extern crate log;
extern crate p9;

use libc::gid_t;

use std::ffi::CString;
use std::fmt;
use std::fs::{remove_file, File};
use std::io::{self, BufReader, BufWriter};
use std::net;
use std::num::ParseIntError;
use std::os::raw::c_uint;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::{SocketAddr, UnixListener};
use std::path::{Path, PathBuf};
use std::result;
use std::str::FromStr;
use std::string;
use std::sync::Arc;
use std::thread;

use libchromeos::panic_handler::install_memfd_handler;
use libchromeos::sys::unix::vsock::*;
use libchromeos::syslog;

const DEFAULT_BUFFER_SIZE: usize = 8192;

// Address family identifiers.
const VSOCK: &str = "vsock:";
const UNIX: &str = "unix:";
const UNIX_FD: &str = "unix-fd:";

// Usage for this program.
const USAGE: &str = "9s [options] {vsock:<port>|unix:<path>|unix-fd:<fd>|<ip>:<port>}";

// Program name.
const IDENT: &str = "9s";

enum ListenAddress {
    Net(net::SocketAddr),
    Unix(String),
    UnixFd(RawFd),
    Vsock(c_uint),
}

#[derive(Debug)]
enum ParseAddressError {
    MissingUnixPath,
    MissingUnixFd,
    MissingVsockPort,
    Net(net::AddrParseError),
    Unix(string::ParseError),
    UnixFd(ParseIntError),
    Vsock(ParseIntError),
}

impl fmt::Display for ParseAddressError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParseAddressError::MissingUnixPath => write!(f, "missing unix path"),
            ParseAddressError::MissingUnixFd => write!(f, "missing unix file descriptor"),
            ParseAddressError::MissingVsockPort => write!(f, "missing vsock port number"),
            ParseAddressError::Net(ref e) => e.fmt(f),
            ParseAddressError::Unix(ref e) => write!(f, "invalid unix path: {}", e),
            ParseAddressError::UnixFd(ref e) => write!(f, "invalid file descriptor: {}", e),
            ParseAddressError::Vsock(ref e) => write!(f, "invalid vsock port number: {}", e),
        }
    }
}

impl FromStr for ListenAddress {
    type Err = ParseAddressError;

    fn from_str(s: &str) -> result::Result<Self, Self::Err> {
        if let Some(s) = s.strip_prefix(VSOCK) {
            if !s.is_empty() {
                Ok(ListenAddress::Vsock(
                    s.parse().map_err(ParseAddressError::Vsock)?,
                ))
            } else {
                Err(ParseAddressError::MissingVsockPort)
            }
        } else if let Some(s) = s.strip_prefix(UNIX) {
            if !s.is_empty() {
                Ok(ListenAddress::Unix(
                    s.parse().map_err(ParseAddressError::Unix)?,
                ))
            } else {
                Err(ParseAddressError::MissingUnixPath)
            }
        } else if let Some(s) = s.strip_prefix(UNIX_FD) {
            if !s.is_empty() {
                Ok(ListenAddress::UnixFd(
                    s.parse().map_err(ParseAddressError::UnixFd)?,
                ))
            } else {
                Err(ParseAddressError::MissingUnixFd)
            }
        } else {
            Ok(ListenAddress::Net(
                s.parse().map_err(ParseAddressError::Net)?,
            ))
        }
    }
}

#[derive(Debug)]
enum Error {
    Address(ParseAddressError),
    Argument(getopts::Fail),
    Cid(ParseIntError),
    IdMapConvertHost(String),
    IdMapConvertClient(String),
    IdMapDuplicate(String),
    IdMapParse(String),
    IO(io::Error),
    MissingAcceptCid,
    SocketGid(ParseIntError),
    SocketPathNotAbsolute(PathBuf),
    Syslog(syslog::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Address(ref e) => e.fmt(f),
            Error::Argument(ref e) => e.fmt(f),
            Error::Cid(ref e) => write!(f, "invalid cid value: {}", e),
            Error::IdMapConvertClient(ref s) => {
                write!(f, "malformed client portion of id map ({})", s)
            }
            Error::IdMapConvertHost(ref s) => write!(f, "malformed host portion of id map ({})", s),
            Error::IdMapDuplicate(ref s) => write!(f, "duplicate mapping for host id {}", s),
            Error::IdMapParse(ref s) => write!(
                f,
                "id map must have exactly 2 components: <host_id>:<client_id> ({})",
                s
            ),
            Error::IO(ref e) => e.fmt(f),
            Error::MissingAcceptCid => write!(f, "`accept_cid` is required for vsock servers"),
            Error::SocketGid(ref e) => write!(f, "invalid gid value: {}", e),
            Error::SocketPathNotAbsolute(ref p) => {
                write!(f, "unix socket path must be absolute: {:?}", p)
            }
            Error::Syslog(ref e) => write!(f, "failed to initialize syslog: {}", e),
        }
    }
}

struct UnixSocketAddr(SocketAddr);
impl fmt::Display for UnixSocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(path) = self.0.as_pathname() {
            write!(f, "{}", path.to_str().unwrap_or("<malformed path>"))
        } else {
            write!(f, "<unnamed or abstract socket>")
        }
    }
}

type Result<T> = result::Result<T, Error>;

#[derive(Clone)]
struct ServerParams {
    root: String,
    uid_map: p9::ServerUidMap,
    gid_map: p9::ServerGidMap,
}

fn handle_client<R: io::Read, W: io::Write>(
    server_params: Arc<ServerParams>,
    mut reader: R,
    mut writer: W,
) -> io::Result<()> {
    let params: ServerParams = (*server_params).clone();
    let mut server = p9::Server::new(PathBuf::from(&params.root), params.uid_map, params.gid_map)?;

    loop {
        server.handle_message(&mut reader, &mut writer)?;
    }
}

fn spawn_server_thread<
    R: 'static + io::Read + Send,
    W: 'static + io::Write + Send,
    D: 'static + fmt::Display + Send,
>(
    server_params: &Arc<ServerParams>,
    reader: R,
    writer: W,
    peer: D,
) {
    let reader = BufReader::with_capacity(DEFAULT_BUFFER_SIZE, reader);
    let writer = BufWriter::with_capacity(DEFAULT_BUFFER_SIZE, writer);
    let params = server_params.clone();
    thread::spawn(move || {
        if let Err(e) = handle_client(params, reader, writer) {
            error!("error while handling client {}: {}", peer, e);
        }
    });
}

fn run_vsock_server(
    server_params: Arc<ServerParams>,
    port: c_uint,
    accept_cid: VsockCid,
) -> io::Result<()> {
    let listener = VsockListener::bind((VsockCid::Any, port))?;

    loop {
        let (stream, peer) = listener.accept()?;

        if accept_cid != peer.cid {
            warn!("ignoring connection from {}", peer);
            continue;
        }

        info!("accepted connection from {}", peer);
        spawn_server_thread(&server_params, stream.try_clone()?, stream, peer);
    }
}

fn adjust_socket_ownership(path: &Path, gid: gid_t) -> io::Result<()> {
    // At this point we expect valid path since we supposedly created
    // the socket, so any failure in transforming path is _really_ unexpected.
    let path_str = path.as_os_str().to_str().expect("invalid unix socket path");
    let path_cstr = CString::new(path_str).expect("malformed unix socket path");

    // Safe as kernel only reads from the path and we know it is properly
    // formed and we check the result for errors.
    // Note: calling chown with uid -1 will preserve current user ownership.
    let res = unsafe { libc::chown(path_cstr.as_ptr(), libc::uid_t::max_value(), gid) };
    if res < 0 {
        return Err(io::Error::last_os_error());
    }

    // Allow both owner and group read/write access to the socket, and
    // deny access to the rest of the world.
    let mut permissions = path.metadata()?.permissions();
    permissions.set_mode(0o660);

    Ok(())
}

fn run_unix_server(server_params: Arc<ServerParams>, listener: UnixListener) -> io::Result<()> {
    loop {
        let (stream, peer) = listener.accept()?;
        let peer = UnixSocketAddr(peer);

        info!("accepted connection from {}", peer);
        spawn_server_thread(&server_params, stream.try_clone()?, stream, peer);
    }
}

fn run_unix_server_with_path(
    server_params: Arc<ServerParams>,
    path: &Path,
    socket_gid: Option<gid_t>,
) -> io::Result<()> {
    if path.exists() {
        let metadata = path.metadata()?;
        if !metadata.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Requested socket path points to existing non-socket object",
            ));
        }
        remove_file(path)?;
    }

    let listener = UnixListener::bind(path)?;

    if let Some(gid) = socket_gid {
        adjust_socket_ownership(path, gid)?;
    }

    run_unix_server(server_params, listener)
}

fn run_unix_server_with_fd(server_params: Arc<ServerParams>, fd: RawFd) -> io::Result<()> {
    // This is safe as we are using our very own file descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    if !metadata.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Supplied file descriptor is not a socket",
        ));
    }

    // This is safe as because we have validated that we are dealing with a socket and
    // we are checking the result.
    let ret = unsafe { libc::listen(file.as_raw_fd(), 128) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    // This is safe because we are dealing with listening socket.
    let listener = unsafe { UnixListener::from_raw_fd(file.into_raw_fd()) };
    run_unix_server(server_params, listener)
}

fn add_id_mapping<T: Clone + FromStr + Ord>(s: &str, map: &mut p9::ServerIdMap<T>) -> Result<()> {
    let components: Vec<&str> = s.split(':').collect();
    if components.len() != 2 {
        return Err(Error::IdMapParse(s.to_owned()));
    }
    let host_id = components[0]
        .parse::<T>()
        .map_err(|_| Error::IdMapConvertHost(components[0].to_owned()))?;
    let client_id = components[1]
        .parse::<T>()
        .map_err(|_| Error::IdMapConvertClient(components[1].to_owned()))?;

    if map.contains_key(&host_id) {
        return Err(Error::IdMapDuplicate(components[0].to_owned()));
    }

    map.insert(host_id, client_id);
    Ok(())
}

fn main() -> Result<()> {
    install_memfd_handler();
    let mut opts = getopts::Options::new();
    opts.optopt(
        "",
        "accept_cid",
        "only accept connections from this vsock context id",
        "CID",
    );
    opts.optopt(
        "r",
        "root",
        "root directory for clients (default is \"/\")",
        "PATH",
    );
    opts.optopt(
        "",
        "socket_gid",
        "change socket group ownership to the specified ID",
        "GID",
    );
    opts.optmulti(
        "",
        "uid_map",
        "translate uids from host to client",
        "UID:UID",
    );
    opts.optmulti(
        "",
        "gid_map",
        "translate gids from host to client",
        "GID:GID",
    );
    opts.optflag("h", "help", "print this help menu");

    let matches = opts
        .parse(std::env::args_os().skip(1))
        .map_err(Error::Argument)?;

    if matches.opt_present("h") || matches.free.is_empty() {
        print!("{}", opts.usage(USAGE));
        return Ok(());
    }

    let mut uid_map: p9::ServerUidMap = Default::default();
    matches
        .opt_strs("uid_map")
        .iter()
        .try_for_each(|s| add_id_mapping(s, &mut uid_map))?;

    let mut gid_map: p9::ServerGidMap = Default::default();
    matches
        .opt_strs("gid_map")
        .iter()
        .try_for_each(|s| add_id_mapping(s, &mut gid_map))?;

    let server_params = Arc::from(ServerParams {
        root: matches.opt_str("r").unwrap_or_else(|| "/".into()),
        uid_map,
        gid_map,
    });

    syslog::init(IDENT.to_string(), false /* log_to_stderr */).map_err(Error::Syslog)?;

    // We already checked that |matches.free| has at least one item.
    match matches.free[0]
        .parse::<ListenAddress>()
        .map_err(Error::Address)?
    {
        ListenAddress::Vsock(port) => {
            let accept_cid = if let Some(cid) = matches.opt_str("accept_cid") {
                cid.parse::<VsockCid>().map_err(Error::Cid)
            } else {
                Err(Error::MissingAcceptCid)
            }?;
            run_vsock_server(server_params, port, accept_cid).map_err(Error::IO)?;
        }
        ListenAddress::Net(_) => {
            error!("Network server unimplemented");
        }
        ListenAddress::Unix(path) => {
            let path = Path::new(&path);
            if !path.is_absolute() {
                return Err(Error::SocketPathNotAbsolute(path.to_owned()));
            }

            let socket_gid = matches
                .opt_get::<gid_t>("socket_gid")
                .map_err(Error::SocketGid)?;

            run_unix_server_with_path(server_params, path, socket_gid).map_err(Error::IO)?;
        }
        ListenAddress::UnixFd(fd) => {
            // Try duplicating the fd to verify that it is a valid file descriptor. It will also
            // ensure that we will not accidentally close file descriptor used by something else.
            // Safe because this doesn't modify any memory and we check the return value.
            let fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
            if fd < 0 {
                return Err(Error::IO(io::Error::last_os_error()));
            }

            run_unix_server_with_fd(server_params, fd).map_err(Error::IO)?;
        }
    }

    Ok(())
}
