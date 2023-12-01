// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The broker daemon that supports Trichecus from within the Chrome OS guest machine.

#![deny(unsafe_op_in_unsafe_fn)]

use std::env;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fs::File;
use std::io::Read;
use std::mem::drop;
use std::mem::replace;
use std::ops::Deref;
use std::ops::DerefMut;
use std::os::unix::net::UnixDatagram;
use std::result::Result as StdResult;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use dbus::arg::OwnedFd;
use dbus::blocking::LocalConnection;
use dbus::channel::MatchingReceiver;
use dbus::message::MatchRule;
use dbus::MethodErr;
use dbus_crossroads::Crossroads;
use getopts::Options;
use libchromeos::chromeos::is_dev_mode;
use libchromeos::panic_handler::install_memfd_handler;
use libchromeos::syslog;
use libsirenia::app_info::AppManifest;
use libsirenia::build_info::BUILD_TIMESTAMP;
use libsirenia::cli::trichechus::initialize_common_arguments;
use libsirenia::communication::trichechus;
use libsirenia::communication::trichechus::AppInfo;
use libsirenia::communication::trichechus::Trichechus;
use libsirenia::communication::trichechus::TrichechusClient;
use libsirenia::rpc;
use libsirenia::transport::Transport;
use libsirenia::transport::TransportType;
use libsirenia::transport::DEFAULT_CLIENT_PORT;
use libsirenia::transport::DEFAULT_SERVER_PORT;
use log::error;
use log::info;
use serde_bytes::ByteBuf;
use sirenia::server::register_org_chromium_mana_teeinterface;
use sirenia::server::OrgChromiumManaTEEInterface;

const GET_LOGS_SHORT_NAME: &str = "l";
const IDENT: &str = "dugong";

// Arc and Mutex are used because dbus-crossroads requires the Send trait since it is designed to
// be thread safe. At the time of writing Dugong is single threaded so Arc and Mutex aren't strictly
// necessary.
// See https://github.com/diwic/dbus-rs/issues/349 for a feature request to make Send optional.
struct DugongStateInternal {
    transport_type: TransportType,
    trichechus_client: Mutex<TrichechusClient>,
    supported_apps: Mutex<AppManifest>,
}

#[derive(Clone)]
struct DugongState(Arc<DugongStateInternal>);

impl DugongState {
    fn new(trichechus_client: TrichechusClient, transport_type: TransportType) -> Self {
        DugongState(Arc::new(DugongStateInternal {
            transport_type,
            trichechus_client: Mutex::new(trichechus_client),
            supported_apps: Mutex::new(Default::default()),
        }))
    }

    fn register_supported_apps(&mut self, manifest: AppManifest) {
        let mut supported_apps = self.0.supported_apps.lock().unwrap();
        drop(replace(supported_apps.deref_mut(), manifest));
    }

    fn transport_type(&self) -> &TransportType {
        &self.0.transport_type
    }

    fn trichechus_client(&self) -> &Mutex<TrichechusClient> {
        &self.0.trichechus_client
    }

    fn supported_apps(&self) -> &Mutex<AppManifest> {
        &self.0.supported_apps
    }
}

impl Debug for DugongState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "transport_type: {:?}", self.transport_type())
    }
}

impl OrgChromiumManaTEEInterface for DugongState {
    fn start_teeapplication(
        &mut self,
        app_id: String,
        args: Vec<String>,
        allow_unverified: bool,
    ) -> StdResult<(i32, OwnedFd, OwnedFd), MethodErr> {
        info!("Got request to start up: {}", &app_id);
        let fds = request_start_tee_app(self, &app_id, args, allow_unverified);
        match fds {
            Ok(fds) => Ok((0, fds.0, fds.1)),
            Err(e) => Err(MethodErr::failed(&e)),
        }
    }

    fn system_event(&mut self, event: String) -> StdResult<String, MethodErr> {
        let mut api_handle = self.trichechus_client().lock().unwrap();
        match api_handle.system_event(event.parse().map_err(|err| MethodErr::failed(&err))?) {
            Ok(()) => Ok(String::new()),
            Err(err) => match err.downcast::<trichechus::Error>() {
                Ok(err) => Ok(err.to_string()),
                Err(err) => Err(MethodErr::failed(&err)),
            },
        }
    }

    fn get_manatee_memory_service_socket(&mut self) -> StdResult<OwnedFd, MethodErr> {
        get_manatee_memory_service_socket(self).map_err(|err| MethodErr::failed(&err))
    }
}

fn load_tee_app(
    api_handle: &mut TrichechusClient,
    state: &DugongState,
    app_id: &str,
    allow_unverified: bool,
) -> Result<()> {
    let supported_apps = state.supported_apps().lock().unwrap();
    let elf_path = supported_apps
        .get_app_manifest_entry(app_id)
        .context("app not found")?
        .cros_path()
        .ok_or_else(|| anyhow!("no entry for loading app '{0}'", app_id))?;

    let mut elf = Vec::<u8>::new();
    File::open(&elf_path)
        .with_context(|| format!("failed to open app path '{}'", &elf_path.display()))?
        .read_to_end(&mut elf)
        .with_context(|| format!("failed to read app path '{}'", &elf_path.display()))?;

    info!("Transmitting TEE app.");
    api_handle
        .load_app(app_id.to_string(), elf, allow_unverified)
        .context("load_app rpc failed")?;

    Ok(())
}

const RPC_FAILURE_CONTEXT: &str = "start_session rpc failed";

fn request_start_tee_app(
    state: &DugongState,
    app_id: &str,
    args: Vec<String>,
    allow_unverified: bool,
) -> Result<(OwnedFd, OwnedFd)> {
    let mut transport = state
        .transport_type()
        .try_into_client(None)
        .context("failed to get client for transport")?;
    let addr = transport.bind().context("failed to bind to socket")?;
    let app_info = AppInfo {
        app_id: String::from(app_id),
        port_number: addr.get_port().context("failed to get port")?,
    };
    info!("Requesting start {:?}", &app_info);
    let mut trichechus_client = state.trichechus_client().lock().unwrap();
    if let Err(err) = trichechus_client.start_session(app_info.clone(), args.clone()) {
        match err.downcast() {
            Ok(trichechus::Error::AppNotLoaded) => {
                load_tee_app(&mut trichechus_client, state, app_id, allow_unverified)?;
                trichechus_client
                    .start_session(app_info, args)
                    .context(RPC_FAILURE_CONTEXT)?;
            }
            Ok(err) => Err(err).context(RPC_FAILURE_CONTEXT)?,
            Err(err) => Err(err).context(RPC_FAILURE_CONTEXT)?,
        }
    }
    let Transport { r, w, id: _ } = transport.connect().context("failed to connect to socket")?;
    // This is safe because into_raw_fd transfers the ownership to OwnedFd.
    Ok((unsafe { OwnedFd::new(r.into_raw_fd()) }, unsafe {
        OwnedFd::new(w.into_raw_fd())
    }))
}

fn handle_manatee_logs(dugong_state: &DugongState) -> Result<()> {
    const LOG_PATH: &str = "/dev/log";
    let mut trichechus_client = dugong_state.trichechus_client().lock().unwrap();
    let logs: Vec<ByteBuf> = trichechus_client
        .get_logs()
        .context("failed to call get_logs rpc")?;
    if logs.is_empty() {
        return Ok(());
    }

    // TODO(b/173600313) Decide whether to write this directly to a different log file.
    let raw_syslog = UnixDatagram::unbound().context("failed connect to /dev/log")?;
    for entry in logs.as_slice() {
        raw_syslog
            .send_to(entry.deref(), LOG_PATH)
            .context("failed write to /dev/log")?;
    }

    Ok(())
}

fn get_manatee_memory_service_socket(state: &DugongState) -> Result<OwnedFd> {
    let mut transport = state
        .transport_type()
        .try_into_client(None)
        .context("failed to get client for transport")?;
    let addr = transport.bind().context("failed to bind to socket")?;
    let mut trichechus_client = state.trichechus_client().lock().unwrap();
    trichechus_client
        .prepare_manatee_memory_service_socket(addr.get_port().context("failed to get port")?)
        .context(RPC_FAILURE_CONTEXT)?;
    let Transport { r, w: _, id: _ } =
        transport.connect().context("failed to connect to socket")?;
    // This is safe because into_raw_fd transfers the ownership to OwnedFd.
    Ok(unsafe { OwnedFd::new(r.into_raw_fd()) })
}

fn register_dbus_interface_for_app(
    crossroads: &mut Crossroads,
    dugong_state: DugongState,
    app_id: &str,
) {
    // D-Bus identifiers only allow alphanumeric and underscore characters. Since we allow hyphens
    // in TEE app IDs, replace them with underscores when creating the D-Bus identifier.
    let app_dbus_identifier = app_id.replace('-', "_");
    let interface_token = crossroads.register(
        format!("org.chromium.manatee.{}", &app_dbus_identifier),
        |b| {
            // Allow unverified apps when developer mode is enabled to ease testing use cases.
            b.method(
                "StartInstance",
                ("args",),
                ("error_code", "fd_in", "fd_out"),
                |_, t: &mut (DugongState, String), args: (Vec<String>,)| {
                    t.0.start_teeapplication(t.1.clone(), args.0, is_dev_mode().unwrap_or(false))
                },
            )
            .annotate("org.chromium.DBus.Method.Kind", "simple");
        },
    );
    crossroads.insert(
        format!("/org/chromium/ManaTEE1/{}", &app_dbus_identifier),
        &[interface_token],
        (dugong_state, app_id.to_string()),
    );
}

fn start_dbus_handler(dugong_state: DugongState) -> Result<()> {
    let c = LocalConnection::new_system().context("failed to open D-Bus connection")?;
    c.request_name(
        "org.chromium.ManaTEE",
        false, /*allow_replacement*/
        false, /*replace_existing*/
        false, /*do_not_queue*/
    )
    .context("failed to register D-Bus handler")?;

    let mut crossroads = Crossroads::new();
    let interface_token = register_org_chromium_mana_teeinterface::<DugongState>(&mut crossroads);
    crossroads.insert(
        "/org/chromium/ManaTEE1",
        &[interface_token],
        dugong_state.clone(),
    );
    dugong_state
        .supported_apps()
        .lock()
        .unwrap()
        .iter()
        .for_each(|entry| {
            register_dbus_interface_for_app(&mut crossroads, dugong_state.clone(), entry.app_id())
        });
    c.start_receive(
        MatchRule::new_method_call(),
        Box::new(move |msg, conn| {
            if let Err(err) = crossroads.handle_message(msg, conn) {
                error!("Failed to handle message: {:?}", err);
                false
            } else {
                true
            }
        }),
    );

    info!("Finished dbus setup, starting handler.");
    loop {
        if let Err(err) = handle_manatee_logs(&dugong_state) {
            if matches!(
                err.source().map(|a| a.downcast_ref::<rpc::Error>()),
                Some(_)
            ) {
                error!("Trichechus disconnected: {}", err);
                return Err(err);
            }
            error!("Failed to forward syslog: {}", err);
        }
        c.process(Duration::from_millis(1000))
            .context("failed to process the D-Bus message")?;
    }
}

fn main() -> Result<()> {
    install_memfd_handler();
    let args: Vec<String> = env::args().collect();
    let mut opts = Options::new();
    opts.optflag(
        GET_LOGS_SHORT_NAME,
        "get-logs",
        "connect to trichechus, get and print logs, then exit.",
    );
    let (config, matches) = initialize_common_arguments(opts, &args[1..]).unwrap();
    let get_logs = matches.opt_present(GET_LOGS_SHORT_NAME);
    let transport_type = config.connection_type;

    if let Err(e) = syslog::init(IDENT.to_string(), true /*log_to_stderr*/) {
        eprintln!("failed to initialize syslog: {}", e);
        bail!("failed to start up the syslog: {}", e);
    }

    info!("Starting {}: {}", IDENT, BUILD_TIMESTAMP);
    info!("Opening connection to trichechus");
    // Adjust the source port when connecting to a non-standard port to facilitate testing.
    let bind_port = match transport_type.get_port().context("failed to get port")? {
        DEFAULT_SERVER_PORT => DEFAULT_CLIENT_PORT,
        port => port + 1,
    };
    let mut transport = transport_type
        .try_into_client(Some(bind_port))
        .context("failed to get client for transport")?;

    let transport = transport.connect().map_err(|e| {
        error!("transport connect failed: {}", e);
        anyhow!("transport connect failed: {}", e)
    })?;
    info!("Starting rpc");
    let mut client = TrichechusClient::new(transport);
    if get_logs {
        info!("Getting logs");
        let logs = client.get_logs().context("failed to fetch logs")?;
        for entry in &logs[..] {
            print!("{}", String::from_utf8_lossy(entry));
        }
    } else {
        let apps = client.get_apps().context("failed to fetch app list")?;
        let mut dugong_state = DugongState::new(client, transport_type);
        dugong_state.register_supported_apps(apps);
        start_dbus_handler(dugong_state).unwrap();
        unreachable!()
    }
    Ok(())
}
