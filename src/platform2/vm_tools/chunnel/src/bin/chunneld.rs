// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::btree_map::Entry as BTreeMapEntry;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::fs::File;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, TcpListener};
use std::os::raw::c_int;
use std::os::unix::io::{AsRawFd, IntoRawFd};
use std::result;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use dbus::arg::OwnedFd;
use dbus::blocking::LocalConnection as DBusConnection;
use dbus::{self, Error as DBusError};
use libchromeos::deprecated::{EventFd, PollContext, PollToken};
use libchromeos::panic_handler::install_memfd_handler;
use libchromeos::sys::unix::vsock::{VsockCid, VsockListener, VMADDR_PORT_ANY};
use libchromeos::sys::{block_signal, pipe};
use libchromeos::syslog;
use log::{error, warn};
use protobuf::{self, Message as ProtoMessage};

use chunnel::forwarder::ForwarderSession;
use system_api::chunneld_service::*;
use system_api::cicerone_service;

// chunnel dbus-constants.h
const CHUNNELD_INTERFACE: &str = "org.chromium.Chunneld";
const CHUNNELD_SERVICE_PATH: &str = "/org/chromium/Chunneld";
const CHUNNELD_SERVICE_NAME: &str = "org.chromium.Chunneld";

// cicerone dbus-constants.h
const VM_CICERONE_INTERFACE: &str = "org.chromium.VmCicerone";
const VM_CICERONE_SERVICE_PATH: &str = "/org/chromium/VmCicerone";
const VM_CICERONE_SERVICE_NAME: &str = "org.chromium.VmCicerone";
const CONNECT_CHUNNEL_METHOD: &str = "ConnectChunnel";

// permission_broker dbus-constants.h
const PERMISSION_BROKER_INTERFACE: &str = "org.chromium.PermissionBroker";
const PERMISSION_BROKER_SERVICE_PATH: &str = "/org/chromium/PermissionBroker";
const PERMISSION_BROKER_SERVICE_NAME: &str = "org.chromium.PermissionBroker";
const REQUEST_LOOPBACK_TCP_PORT_LOCKDOWN_METHOD: &str = "RequestLoopbackTcpPortLockdown";
const RELEASE_LOOPBACK_TCP_PORT_METHOD: &str = "ReleaseLoopbackTcpPort";

// chunneld dbus-constants.h
const UPDATE_LISTENING_PORTS_METHOD: &str = "UpdateListeningPorts";

const CHUNNEL_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DBUS_TIMEOUT: Duration = Duration::from_secs(30);

// Program name.
const IDENT: &str = "chunneld";

#[remain::sorted]
#[derive(Debug)]
enum Error {
    BindVsock(io::Error),
    BlockSigpipe(libchromeos::sys::signal::Error),
    ConnectChunnelFailure(String),
    CreateProtobusService(dbus::Error),
    DBusGetSystemBus(DBusError),
    DBusMessageSend(DBusError),
    DBusProcessMessage(DBusError),
    EventFdClone(libchromeos::sys::Error),
    EventFdNew(libchromeos::sys::Error),
    IncorrectCid(VsockCid),
    LifelinePipe(libchromeos::sys::Error),
    NoListenerForPort(u16),
    NoSessionForTag(SessionTag),
    PollContextAdd(libchromeos::sys::Error),
    PollContextDelete(libchromeos::sys::Error),
    PollContextNew(libchromeos::sys::Error),
    PollWait(libchromeos::sys::Error),
    ProtobufDeserialize(protobuf::Error),
    ProtobufSerialize(protobuf::Error),
    SetVsockNonblocking(io::Error),
    Syslog(syslog::Error),
    TcpAccept(io::Error),
    TcpListenerPort(io::Error),
    UpdateEventRead(libchromeos::sys::Error),
    VsockAccept(io::Error),
    VsockAcceptTimeout,
    VsockListenerPort(io::Error),
}

type Result<T> = result::Result<T, Error>;

impl fmt::Display for Error {
    #[remain::check]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        #[remain::sorted]
        match self {
            BindVsock(e) => write!(f, "failed to bind vsock: {}", e),
            BlockSigpipe(e) => write!(f, "failed to block SIGPIPE: {}", e),
            ConnectChunnelFailure(e) => write!(f, "failed to connect chunnel: {}", e),
            CreateProtobusService(e) => write!(f, "failed to create D-Bus service: {}", e),
            DBusGetSystemBus(e) => write!(f, "failed to get D-Bus system bus: {}", e),
            DBusMessageSend(e) => write!(f, "failed to send D-Bus message: {}", e),
            DBusProcessMessage(e) => write!(f, "failed to process D-Bus message: {}", e),
            EventFdClone(e) => write!(f, "failed to clone eventfd: {}", e),
            EventFdNew(e) => write!(f, "failed to create eventfd: {}", e),
            IncorrectCid(cid) => write!(f, "chunnel connection from unexpected cid {}", cid),
            LifelinePipe(e) => write!(f, "failed to create firewall lifeline pipe {}", e),
            NoListenerForPort(port) => write!(f, "could not find listener for port: {}", port),
            NoSessionForTag(tag) => write!(f, "could not find session for tag: {:x}", tag),
            PollContextAdd(e) => write!(f, "failed to add fd to poll context: {}", e),
            PollContextDelete(e) => write!(f, "failed to delete fd from poll context: {}", e),
            PollContextNew(e) => write!(f, "failed to create poll context: {}", e),
            PollWait(e) => write!(f, "failed to wait for poll: {}", e),
            ProtobufDeserialize(e) => write!(f, "failed to deserialize protobuf: {}", e),
            ProtobufSerialize(e) => write!(f, "failed to serialize protobuf: {}", e),
            SetVsockNonblocking(e) => write!(f, "failed to set vsock to nonblocking: {}", e),
            Syslog(e) => write!(f, "failed to initialize syslog: {}", e),
            TcpAccept(e) => write!(f, "failed to accept tcp: {}", e),
            TcpListenerPort(e) => {
                write!(f, "failed to read local sockaddr for tcp listener: {}", e)
            }
            UpdateEventRead(e) => write!(f, "failed to read update eventfd: {}", e),
            VsockAccept(e) => write!(f, "failed to accept vsock: {}", e),
            VsockAcceptTimeout => write!(f, "timed out waiting for vsock connection"),
            VsockListenerPort(e) => write!(f, "failed to get vsock listener port: {}", e),
        }
    }
}

/// A TCP forwarding target. Uniquely identifies a listening port in a given container.
struct TcpForwardTarget {
    pub port: u16,
    pub vm_name: String,
    pub container_name: String,
    pub owner_id: String,
    pub vsock_cid: VsockCid,
}

/// A tag that uniquely identifies a particular forwarding session. This has arbitrarily been
/// chosen as the fd of the local (TCP) socket.
type SessionTag = u32;

/// Implements PollToken for chunneld's main poll loop.
#[derive(Clone, Copy, PollToken)]
enum Token {
    UpdatePorts,
    Ipv4Listener(u16),
    Ipv6Listener(u16),
    LocalSocket(SessionTag),
    RemoteSocket(SessionTag),
}

/// PortListeners includes all listeners (IPv4 and IPv6) for a given port, and the target
/// container.
struct PortListeners {
    tcp4_listener: TcpListener,
    tcp6_listener: TcpListener,
    forward_target: TcpForwardTarget,
    _firewall_lifeline: File,
}

/// SocketFamily specifies whether a socket uses IPv4 or IPv6.
enum SocketFamily {
    Ipv4,
    Ipv6,
}

/// ForwarderSessions encapsulates all forwarding state for chunneld.
struct ForwarderSessions {
    listening_ports: BTreeMap<u16, PortListeners>,
    tcp4_forwarders: HashMap<SessionTag, ForwarderSession>,
    update_evt: EventFd,
    update_queue: Arc<Mutex<VecDeque<TcpForwardTarget>>>,
    dbus_conn: DBusConnection,
}

impl ForwarderSessions {
    /// Creates a new instance of ForwarderSessions.
    fn new(
        update_evt: EventFd,
        update_queue: Arc<Mutex<VecDeque<TcpForwardTarget>>>,
    ) -> Result<Self> {
        Ok(ForwarderSessions {
            listening_ports: BTreeMap::new(),
            tcp4_forwarders: HashMap::new(),
            update_evt,
            update_queue,
            dbus_conn: DBusConnection::new_system().map_err(Error::DBusGetSystemBus)?,
        })
    }

    /// Adds or removes listeners based on the latest listening ports from the D-Bus thread.
    fn process_update_queue(&mut self, poll_ctx: &PollContext<Token>) -> Result<()> {
        // Unwrap of LockResult is customary.
        let mut update_queue = self.update_queue.lock().unwrap();
        let mut active_ports: BTreeSet<u16> = BTreeSet::new();

        // Add any new listeners first.
        while let Some(target) = update_queue.pop_front() {
            let port = target.port;
            // Ignore privileged ports.
            if port < 1024 {
                continue;
            }
            if let BTreeMapEntry::Vacant(o) = self.listening_ports.entry(port) {
                // Lock down the port to allow only Chrome to connect to it.
                let (firewall_lifeline, dbus_fd) = pipe(true).map_err(Error::LifelinePipe)?;
                let (allowed,): (bool,) = self
                    .dbus_conn
                    .with_proxy(
                        PERMISSION_BROKER_SERVICE_NAME,
                        PERMISSION_BROKER_SERVICE_PATH,
                        DBUS_TIMEOUT,
                    )
                    .method_call(
                        PERMISSION_BROKER_INTERFACE,
                        REQUEST_LOOPBACK_TCP_PORT_LOCKDOWN_METHOD,
                        // Safe because ownership of dbus_fd is transferred.
                        (port, unsafe { OwnedFd::new(dbus_fd.into_raw_fd()) }),
                    )
                    .map_err(Error::DBusMessageSend)?;
                if !allowed {
                    warn!("failed to lock down loopback TCP port {}", port);
                    continue;
                }

                // Failing to bind a port is not fatal, but we should log it.
                // Both IPv4 and IPv6 localhost must be bound since the host may resolve
                // "localhost" to either.
                let tcp4_listener = match TcpListener::bind((Ipv4Addr::LOCALHOST, port)) {
                    Ok(listener) => listener,
                    Err(e) => {
                        warn!("failed to bind TCPv4 port: {}", e);
                        continue;
                    }
                };
                let tcp6_listener = match TcpListener::bind((Ipv6Addr::LOCALHOST, port)) {
                    Ok(listener) => listener,
                    Err(e) => {
                        warn!("failed to bind TCPv6 port: {}", e);
                        continue;
                    }
                };
                poll_ctx
                    .add_many(&[
                        (&tcp4_listener, Token::Ipv4Listener(port)),
                        (&tcp6_listener, Token::Ipv6Listener(port)),
                    ])
                    .map_err(Error::PollContextAdd)?;
                o.insert(PortListeners {
                    tcp4_listener,
                    tcp6_listener,
                    forward_target: target,
                    _firewall_lifeline: firewall_lifeline,
                });
            }
            active_ports.insert(port);
        }

        // Iterate over the existing listeners; if the port is no longer in the
        // listener list, remove it.
        let old_ports: Vec<u16> = self.listening_ports.keys().cloned().collect();
        for port in old_ports.iter() {
            if !active_ports.contains(port) {
                // Remove the PortListeners struct first - on error we want to drop it and the
                // fds it contains.
                let _listening_port = self.listening_ports.remove(port);
                // Release the locked down port.
                let (allowed,): (bool,) = self
                    .dbus_conn
                    .with_proxy(
                        PERMISSION_BROKER_SERVICE_NAME,
                        PERMISSION_BROKER_SERVICE_PATH,
                        DBUS_TIMEOUT,
                    )
                    .method_call(
                        PERMISSION_BROKER_INTERFACE,
                        RELEASE_LOOPBACK_TCP_PORT_METHOD,
                        (port,),
                    )
                    .map_err(Error::DBusMessageSend)?;
                if !allowed {
                    warn!("failed to release loopback TCP port {}", port);
                }
            }
        }

        // Consume the eventfd.
        self.update_evt.read().map_err(Error::UpdateEventRead)?;

        Ok(())
    }

    fn accept_connection(
        &mut self,
        poll_ctx: &PollContext<Token>,
        port: u16,
        sock_family: SocketFamily,
    ) -> Result<()> {
        let port_listeners = self
            .listening_ports
            .get(&port)
            .ok_or(Error::NoListenerForPort(port))?;

        let listener = match sock_family {
            SocketFamily::Ipv4 => &port_listeners.tcp4_listener,
            SocketFamily::Ipv6 => &port_listeners.tcp6_listener,
        };

        // This session should be dropped if any of the PollContext setup fails. Since the only
        // extant fds for the underlying sockets will be closed, they will be unregistered from
        // epoll set automatically.
        let session = create_forwarder_session(
            &mut self.dbus_conn,
            listener,
            &port_listeners.forward_target,
        )?;

        let tag = session.local_stream().as_raw_fd() as u32;

        poll_ctx
            .add_many(&[
                (session.local_stream(), Token::LocalSocket(tag)),
                (session.remote_stream(), Token::RemoteSocket(tag)),
            ])
            .map_err(Error::PollContextAdd)?;

        self.tcp4_forwarders.insert(tag, session);

        Ok(())
    }

    fn forward_from_local(&mut self, poll_ctx: &PollContext<Token>, tag: SessionTag) -> Result<()> {
        let session = self
            .tcp4_forwarders
            .get_mut(&tag)
            .ok_or(Error::NoSessionForTag(tag))?;
        let shutdown = session.forward_from_local().unwrap_or(true);
        if shutdown {
            poll_ctx
                .delete(session.local_stream())
                .map_err(Error::PollContextDelete)?;
            if session.is_shut_down() {
                self.tcp4_forwarders.remove(&tag);
            }
        }

        Ok(())
    }

    fn forward_from_remote(
        &mut self,
        poll_ctx: &PollContext<Token>,
        tag: SessionTag,
    ) -> Result<()> {
        let session = self
            .tcp4_forwarders
            .get_mut(&tag)
            .ok_or(Error::NoSessionForTag(tag))?;
        let shutdown = session.forward_from_remote().unwrap_or(true);
        if shutdown {
            poll_ctx
                .delete(session.remote_stream())
                .map_err(Error::PollContextDelete)?;
            if session.is_shut_down() {
                self.tcp4_forwarders.remove(&tag);
            }
        }

        Ok(())
    }

    fn run(&mut self) -> Result<()> {
        let poll_ctx: PollContext<Token> =
            PollContext::build_with(&[(&self.update_evt, Token::UpdatePorts)])
                .map_err(Error::PollContextNew)?;

        loop {
            let events = poll_ctx.wait().map_err(Error::PollWait)?;

            for event in events.iter_readable() {
                match event.token() {
                    Token::UpdatePorts => {
                        if let Err(e) = self.process_update_queue(&poll_ctx) {
                            error!("error updating listening ports: {}", e);
                        }
                    }
                    Token::Ipv4Listener(port) => {
                        if let Err(e) = self.accept_connection(&poll_ctx, port, SocketFamily::Ipv4)
                        {
                            error!("error accepting connection: {}", e);
                        }
                    }
                    Token::Ipv6Listener(port) => {
                        if let Err(e) = self.accept_connection(&poll_ctx, port, SocketFamily::Ipv6)
                        {
                            error!("error accepting connection: {}", e);
                        }
                    }
                    Token::LocalSocket(tag) => {
                        if let Err(e) = self.forward_from_local(&poll_ctx, tag) {
                            error!("error forwarding local traffic: {}", e);
                        }
                    }
                    Token::RemoteSocket(tag) => {
                        if let Err(e) = self.forward_from_remote(&poll_ctx, tag) {
                            error!("error forwarding remote traffic: {}", e);
                        }
                    }
                }
            }
        }
    }
}

/// Sends a D-Bus request to launch chunnel in the target container.
fn launch_chunnel(
    dbus_conn: &mut DBusConnection,
    vsock_port: u32,
    tcp4_port: u16,
    target: &TcpForwardTarget,
) -> Result<()> {
    let mut request = cicerone_service::ConnectChunnelRequest::new();
    request.vm_name = target.vm_name.to_owned();
    request.container_name = target.container_name.to_owned();
    request.owner_id = target.owner_id.to_owned();
    request.chunneld_port = vsock_port;
    request.target_tcp4_port = u32::from(tcp4_port);

    let (raw_buffer,): (Vec<u8>,) = dbus_conn
        .with_proxy(
            VM_CICERONE_SERVICE_NAME,
            VM_CICERONE_SERVICE_PATH,
            DBUS_TIMEOUT,
        )
        .method_call(
            VM_CICERONE_INTERFACE,
            CONNECT_CHUNNEL_METHOD,
            (request.write_to_bytes().map_err(Error::ProtobufSerialize)?,),
        )
        .map_err(Error::DBusMessageSend)?;
    let response: cicerone_service::ConnectChunnelResponse =
        ProtoMessage::parse_from_bytes(&raw_buffer).map_err(Error::ProtobufDeserialize)?;

    match response.status.enum_value() {
        Ok(cicerone_service::connect_chunnel_response::Status::SUCCESS) => Ok(()),
        _ => Err(Error::ConnectChunnelFailure(response.failure_reason)),
    }
}

/// Creates a forwarder session from a `listener` that has a pending connection to accept.
fn create_forwarder_session(
    dbus_conn: &mut DBusConnection,
    listener: &TcpListener,
    target: &TcpForwardTarget,
) -> Result<ForwarderSession> {
    let (tcp_stream, _) = listener.accept().map_err(Error::TcpAccept)?;
    // Bind a vsock port, tell the guest to connect, and accept the connection.
    let mut vsock_listener =
        VsockListener::bind((VsockCid::Any, VMADDR_PORT_ANY)).map_err(Error::BindVsock)?;
    vsock_listener
        .set_nonblocking(true)
        .map_err(Error::SetVsockNonblocking)?;

    let tcp4_port = listener
        .local_addr()
        .map_err(Error::TcpListenerPort)?
        .port();

    launch_chunnel(
        dbus_conn,
        vsock_listener
            .local_port()
            .map_err(Error::VsockListenerPort)?,
        tcp4_port,
        target,
    )?;

    #[derive(PollToken)]
    enum Token {
        VsockAccept,
    }

    let poll_ctx: PollContext<Token> =
        PollContext::build_with(&[(&vsock_listener, Token::VsockAccept)])
            .map_err(Error::PollContextNew)?;

    // Wait a few seconds for the guest to connect.
    let events = poll_ctx
        .wait_timeout(CHUNNEL_CONNECT_TIMEOUT)
        .map_err(Error::PollWait)?;

    match events.iter_readable().next() {
        Some(_) => {
            let (vsock_stream, sockaddr) = vsock_listener.accept().map_err(Error::VsockAccept)?;

            if sockaddr.cid != target.vsock_cid {
                Err(Error::IncorrectCid(sockaddr.cid))
            } else {
                Ok(ForwarderSession::new(
                    tcp_stream.into(),
                    vsock_stream.into(),
                ))
            }
        }
        None => Err(Error::VsockAcceptTimeout),
    }
}

/// Enqueues the new listening ports received over D-Bus for the main worker thread to process.
fn update_listening_ports(
    req: UpdateListeningPortsRequest,
    update_queue: &Arc<Mutex<VecDeque<TcpForwardTarget>>>,
    update_evt: &EventFd,
) -> UpdateListeningPortsResponse {
    let mut response = UpdateListeningPortsResponse::new();

    // Unwrap of LockResult is customary.
    let mut update_queue = update_queue.lock().unwrap();

    for (forward_port, forward_target) in req.tcp4_forward_targets {
        update_queue.push_back(TcpForwardTarget {
            port: forward_port as u16,
            vm_name: forward_target.vm_name,
            owner_id: forward_target.owner_id,
            container_name: forward_target.container_name,
            vsock_cid: forward_target.vsock_cid.into(),
        });
    }

    match update_evt.write(1) {
        Ok(_) => {
            response.status = update_listening_ports_response::Status::SUCCESS.into();
        }
        Err(_) => {
            response.status = update_listening_ports_response::Status::FAILED.into();
        }
    }

    response
}

/// Sets up the D-Bus object paths and runs the D-Bus loop.
fn dbus_thread(
    update_queue: Arc<Mutex<VecDeque<TcpForwardTarget>>>,
    update_evt: EventFd,
) -> Result<()> {
    let connection = DBusConnection::new_system().map_err(Error::CreateProtobusService)?;

    connection
        .request_name(CHUNNELD_SERVICE_NAME, false, false, false)
        .map_err(Error::CreateProtobusService)?;

    let f = dbus_tree::Factory::new_fnmut::<()>();
    let dbus_interface = f.interface(CHUNNELD_INTERFACE, ());
    let dbus_method = f
        .method(UPDATE_LISTENING_PORTS_METHOD, (), move |m| {
            let reply = m.msg.method_return();
            let raw_buf: Vec<u8> = m.msg.read1().map_err(|_| dbus_tree::MethodErr::no_arg())?;
            let proto: UpdateListeningPortsRequest = ProtoMessage::parse_from_bytes(&raw_buf)
                .map_err(|e| dbus_tree::MethodErr::invalid_arg(&e))?;

            let response = update_listening_ports(proto, &update_queue, &update_evt);
            Ok(vec![reply.append1(
                response
                    .write_to_bytes()
                    .map_err(|e| dbus_tree::MethodErr::failed(&e))?,
            )])
        })
        .in_arg("ay")
        .out_arg("ay");
    let t = f.tree(()).add(
        f.object_path(CHUNNELD_SERVICE_PATH, ())
            .introspectable()
            .add(dbus_interface.add_m(dbus_method)),
    );

    t.start_receive(&connection);

    // We don't want chunneld waking frequently, so use a big value.
    loop {
        connection
            .process(Duration::from_millis(c_int::max_value() as u64))
            .map_err(Error::DBusProcessMessage)?;
    }
}

fn main() -> Result<()> {
    install_memfd_handler();
    syslog::init(IDENT.to_string(), false /* log_to_stderr */).map_err(Error::Syslog)?;

    // Block SIGPIPE so the process doesn't exit when writing to a socket that's been shutdown.
    block_signal(libc::SIGPIPE).map_err(Error::BlockSigpipe)?;

    let update_evt = EventFd::new().map_err(Error::EventFdNew)?;
    let update_queue = Arc::new(Mutex::new(VecDeque::new()));
    let dbus_update_queue = update_queue.clone();

    let worker_update_evt = update_evt.try_clone().map_err(Error::EventFdClone)?;
    let _ = thread::Builder::new()
        .name("chunnel_dbus".to_string())
        .spawn(move || {
            match dbus_thread(dbus_update_queue, worker_update_evt) {
                Ok(()) => error!("D-Bus thread has exited unexpectedly"),
                Err(e) => error!("D-Bus thread has exited with err {}", e),
            };
        });

    let mut sessions = ForwarderSessions::new(update_evt, update_queue)?;
    sessions.run()
}
