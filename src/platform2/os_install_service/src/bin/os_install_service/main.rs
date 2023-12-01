// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod install;
mod install_logger;

use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Error};
use crossbeam_channel as cbchannel;
use dbus::blocking::{LocalConnection, SyncConnection};
use dbus::channel::{BusType, Channel, Sender};
use dbus::tree::{Factory, Signal};
use log::{error, info};

type Result<T> = std::result::Result<T, Error>;

include!(concat!(env!("OUT_DIR"), "/dbus_constants.rs"));

#[derive(Clone, Debug, Eq, PartialEq)]
enum Status {
    InProgress,
    Failed,
    NoDestinationDeviceFound,
    Succeeded,
}

impl Status {
    fn as_str(&self) -> &str {
        match self {
            Self::InProgress => STATUS_IN_PROGRESS,
            Self::Failed => STATUS_FAILED,
            Self::Succeeded => STATUS_SUCCEEDED,
            Self::NoDestinationDeviceFound => STATUS_NO_DESTINATION_DEVICE_FOUND,
        }
    }
}

fn create_dbus_connection(bus: BusType) -> Result<SyncConnection> {
    let conn = SyncConnection::from(Channel::get_private(bus).context("failed to create Channel")?);
    let allow_replacement = false;
    let replace_existing = true;
    let do_not_queue = false;
    conn.request_name(
        OS_INSTALL_SERVICE_SERVICE_NAME,
        allow_replacement,
        replace_existing,
        do_not_queue,
    )
    .context(format!(
        "failed to register service as {}",
        OS_INSTALL_SERVICE_SERVICE_NAME
    ))?;
    Ok(conn)
}

/// Check for the file indicating we should autoinstall.
///
/// In some situations we want to trigger an install without user intervention.
/// Returns true if the file to trigger it is present.
fn is_autoinstall_file_present() -> bool {
    // This guid is used for ChromeOS Flex UEFI variables,
    // and was originally defined for crdyboot:
    // https://chromium.googlesource.com/chromiumos/platform/crdyboot/
    let file = Path::new(
        "/sys/firmware/efi/efivars/ChromiumOSAutoInstall-2a6f93c9-29ea-46bf-b618-271b63baacf3",
    );

    file.exists()
}

/// Ask the system to shut down after autoinstall.
///
/// For UI-initiated install the browser will handle invoking shutdown. For
/// autoinstall we do it ourselves.
fn request_autoinstall_shutdown() -> Result<()> {
    let connection = LocalConnection::new_system()?;
    let proxy = connection.with_proxy(
        "org.chromium.PowerManager",
        "/org/chromium/PowerManager",
        Duration::from_secs(1),
    );
    // The options are "user initiated" (0) and "other" (1), see:
    // https://source.chromium.org/chromium/chromium/src/+/refs/heads/main:third_party/cros_system_api/dbus/power_manager/dbus-constants.h;l=115;drc=f7ad0c97ab13f1ba4836f3019e728e62e4f98cff
    let shutdown_reason_other = 1;
    proxy
        .method_call(
            "org.chromium.PowerManager",
            "RequestShutdown",
            (shutdown_reason_other, "OS autoinstall shut down"),
        )
        .context("failed to ask PowerManager to shut down the system")
}

#[derive(Debug)]
struct SignalContent {
    status: Status,
    log: String,
}

impl SignalContent {
    fn new(status: Status) -> Self {
        Self {
            status,
            log: install_logger::read_file_log(),
        }
    }
}

/// Send a status update signal.
///
/// The signal contains two strings: the Status enum and instance log.
fn send_signal(conn: &SyncConnection, signal: &Signal<()>, content: SignalContent) {
    // Send the signal. If it fails there's nothing we can do
    // except log the error.
    if conn
        .send(signal.emit(
            &OS_INSTALL_SERVICE_SERVICE_PATH.into(),
            &OS_INSTALL_SERVICE_INTERFACE.into(),
            &[content.status.as_str(), content.log.as_str()],
        ))
        .is_err()
    {
        error!("failed to send signal");
    }
}

/// Function that actually does the installation. Normally this is
/// `install::install`, but other functions can be passed in for
/// testing.
type InstallFn = fn() -> install::Result;

struct Installer {
    /// Channel for the service to tell the installer thread to start
    /// installing.
    start_sender: cbchannel::Sender<()>,

    /// Channel for the installer thread to send messages to the
    /// service. These messages then get sent as dbus signal.
    signal_receiver: cbchannel::Receiver<SignalContent>,
}

impl Installer {
    fn new_inner(install_fn: InstallFn) -> Result<Installer> {
        let (signal_sender, signal_receiver) = cbchannel::unbounded();
        let (start_sender, start_receiver) = cbchannel::unbounded();

        let worker = move || Self::event_loop(install_fn, start_receiver, signal_sender);

        let thread_builder = thread::Builder::new().name("os_install_service".into());

        // The dbus service provided by the dbus-rs crate is
        // synchronous, so long-running methods like installation
        // should happen in a background thread and provide updates
        // via a signal so that other calls to the service don't get
        // blocked.
        //
        // We don't bother keeping the join handle because the service
        // is expected to run forever.
        match thread_builder.spawn(worker) {
            Ok(handle) => handle,
            Err(err) => {
                return Err(Error::from(err).context("failed to spawn thread"));
            }
        };

        Ok(Installer {
            start_sender,
            signal_receiver,
        })
    }

    fn new() -> Result<Installer> {
        Installer::new_inner(install::install)
    }

    fn event_loop(
        install_fn: InstallFn,
        start_receiver: cbchannel::Receiver<()>,
        signal_sender: cbchannel::Sender<SignalContent>,
    ) {
        while start_receiver.recv().is_ok() {
            let status = match (install_fn)() {
                Ok(()) => {
                    info!("install succeeded");
                    Status::Succeeded
                }
                Err(install::Error::NoDestinationDeviceFound) => {
                    error!("install failed: no destination device found");
                    Status::NoDestinationDeviceFound
                }
                Err(err) => {
                    error!("install failed: {}", err);
                    Status::Failed
                }
            };

            if let Err(err) = signal_sender.send(SignalContent::new(status)) {
                // Just log the error, there's nothing else we can do.
                error!("failed to send install status update: {}", err);
            }

            // The install has finished at this point so reset the
            // file log now.
            install_logger::reset_file_log();
        }
    }
}

/// OSInstall dbus server.
struct Server {
    /// Bus to listen on. Usually the system bus, but for testing can
    /// use the session bus.
    bus: BusType,

    /// Optional channel to send back a message indicating the server
    /// is ready to handle requests. Only used for testing.
    ready_channel: Option<cbchannel::Sender<()>>,

    /// Dbus poll duration.
    poll_duration: Duration,

    installer: Installer,
}

impl Server {
    fn create() -> Result<Server> {
        Ok(Server {
            bus: BusType::System,
            ready_channel: None,
            poll_duration: Duration::from_secs(1),
            installer: Installer::new().context("failed to create Installer")?,
        })
    }

    fn run(&self) -> Result<()> {
        let conn =
            Arc::new(create_dbus_connection(self.bus).context("failed to create dbus connection")?);

        let f = Factory::new_sync::<()>();

        let signal = Arc::new(
            f.signal(SIGNAL_OS_INSTALL_STATUS_CHANGED, ())
                .sarg::<&str, _>("status")
                .sarg::<&str, _>("report"),
        );

        let start_sender = self.installer.start_sender.clone();

        // This dbus method takes no arguments and returns the initial
        // installation status. The installation then goes on in the
        // background; further updates are delivered via signal.
        let method_start_os_install = f
            .method(METHOD_START_OS_INSTALL, (), move |m| {
                let status = match start_sender.send(()) {
                    Ok(()) => Status::InProgress,
                    Err(err) => {
                        error!("failed to start install: {}", err);
                        Status::Failed
                    }
                };

                let return_msg = m.msg.method_return().append1(status.as_str());

                Ok(vec![return_msg])
            })
            .outarg::<&str, _>("status");

        // Register the service's dbus method and signal.
        let tree = f
            .tree(())
            .add(
                f.object_path(OS_INSTALL_SERVICE_SERVICE_PATH, ())
                    .introspectable()
                    .add(
                        f.interface(OS_INSTALL_SERVICE_INTERFACE, ())
                            .add_m(method_start_os_install)
                            .add_s(signal.clone()),
                    ),
            )
            .add(f.object_path("/", ()).introspectable());

        tree.start_receive_sync(&*conn);

        let autoinstall = is_autoinstall_file_present();
        if autoinstall {
            info!("autoinstall file found");
            match self.installer.start_sender.try_send(()) {
                Ok(()) => info!("starting install automatically"),
                Err(err) => error!("failed to start autoinstall: {}", err),
            }
        }

        // If a ready channel was given, communicate that the server is
        // ready for requests. This is used for tests.
        if let Some(ready_channel) = &self.ready_channel {
            ready_channel.send(()).context("failed to signal ready")?;
        }

        // Serve clients forever.
        loop {
            conn.process(self.poll_duration)
                .context("failed to poll the connection")?;

            // Process any pending signals.
            while let Ok(content) = self.installer.signal_receiver.try_recv() {
                if autoinstall && content.status == Status::Succeeded {
                    info!("autoinstall completed; attempting to shut down");
                    if let Err(err) = request_autoinstall_shutdown() {
                        error!("failed to shut down: {}", err);
                    }
                }
                send_signal(&conn, &signal, content);
            }
        }
    }
}

fn main() -> Result<()> {
    libchromeos::panic_handler::install_memfd_handler();
    if let Err(err) = install_logger::init(Path::new("/var/log/os_install_service")) {
        // If logging somehow fails to initialize, just print the
        // error and continue on.
        eprintln!("failed to initialize logger: {}", err);
    }

    info!("creating server");
    match Server::create() {
        Ok(server) => server.run(),
        Err(err) => {
            error!("failed to create the server: {}", err);
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Instant;

    use super::*;

    fn status_from_str(s: &str) -> Option<Status> {
        if s == Status::InProgress.as_str() {
            Some(Status::InProgress)
        } else if s == Status::Failed.as_str() {
            Some(Status::Failed)
        } else if s == Status::Succeeded.as_str() {
            Some(Status::Succeeded)
        } else {
            None
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct SignalHappened {
        status: Status,
        log: String,
    }

    impl dbus::arg::ReadAll for SignalHappened {
        fn read(
            i: &mut dbus::arg::Iter,
        ) -> std::result::Result<Self, dbus::arg::TypeMismatchError> {
            Ok(SignalHappened {
                status: status_from_str(i.read()?).unwrap(),
                log: i.read()?,
            })
        }
    }

    impl dbus::message::SignalArgs for SignalHappened {
        const NAME: &'static str = SIGNAL_OS_INSTALL_STATUS_CHANGED;
        const INTERFACE: &'static str = OS_INSTALL_SERVICE_INTERFACE;
    }

    lazy_static::lazy_static! {
        static ref MOCK_INSTALL_RESULT: Arc<Mutex<Option<install::Result>>> =
            Arc::new(Mutex::new(None));
    }

    fn set_mock_install_result(result: install::Result) {
        let mut guard = MOCK_INSTALL_RESULT.lock().unwrap();
        *guard = Some(result)
    }

    fn mock_install() -> install::Result {
        let mut guard = MOCK_INSTALL_RESULT.lock().unwrap();
        guard.take().unwrap()
    }

    fn check_signals(signals: Vec<SignalHappened>, status: Status, expected_log: &str) {
        assert_eq!(signals.len(), 1);
        let signal = &signals[0];
        assert_eq!(signal.status, status);
        assert!(signal.log.contains(expected_log));
    }

    // A word of caution: I initially tried having multiple tests
    // here, each one would start the dbus server and then shut down
    // at the end of the test. I found that the dbus package has some
    // weird behavior with that case though, at least in the 0.8.4
    // version currently available in the chroot. Possibly fixed in
    // this commit, although I didn't test it:
    // https://github.com/diwic/dbus-rs/commit/0d63f1083765f2da9bb93de017b1f53f88ab281d
    #[test]
    fn integration_test() -> Result<()> {
        // Exit early if there is no dbus session. This is the case
        // when running tests inside the chroot, and also in Github
        // Actions.
        if std::env::var("DBUS_SESSION_BUS_ADDRESS").is_err() {
            return Ok(());
        }

        let logdir = tempfile::TempDir::new()?;

        install_logger::init(logdir.path())?;

        // Create a channel for the server to notify when
        // it is ready to receive requests.
        let (ready_sender, ready_receiver) = cbchannel::bounded(1);

        // Run the server.
        let server = Server {
            bus: BusType::Session,
            ready_channel: Some(ready_sender),

            // Set short poll duration so the test runs quickly.
            poll_duration: Duration::from_millis(10),

            installer: Installer::new_inner(mock_install)?,
        };
        thread::spawn(move || server.run().unwrap());

        // Wait for the server to be ready.
        ready_receiver.recv()?;

        // Connect to the server.
        let conn = SyncConnection::new_session()?;
        let timeout = Duration::from_millis(500);
        let proxy = conn.with_proxy(
            OS_INSTALL_SERVICE_SERVICE_NAME,
            OS_INSTALL_SERVICE_SERVICE_PATH,
            timeout,
        );

        // Set up a handler to record every time a signal comes in.
        let signals = Arc::new(Mutex::new(Vec::new()));
        let signals_copy = signals.clone();
        proxy.match_signal(
            move |signal: SignalHappened, _: &SyncConnection, _: &dbus::Message| {
                signals_copy.lock().unwrap().push(signal);

                // Return true to keep the handler.
                true
            },
        )?;
        let wait_for_signals = |num_signals: usize, max_duration: Duration| {
            let end_time = Instant::now() + max_duration;
            while Instant::now() < end_time {
                // Wait for signals.
                conn.process(Duration::from_millis(10)).unwrap();

                // Exit early if the expected number of signals has
                // been received.
                if signals.lock().unwrap().len() == num_signals {
                    break;
                }
            }

            // Copy the received signals to return them, then clear
            // the signals vec.
            let mut guard = signals.lock().unwrap();
            let received = guard.clone();
            guard.clear();
            received
        };

        // Test a failed installation.
        set_mock_install_result(Err(install::Error::NotRunningFromInstaller));
        let status: (String,) =
            proxy.method_call(OS_INSTALL_SERVICE_INTERFACE, METHOD_START_OS_INSTALL, ())?;
        assert_eq!(status.0, Status::InProgress.as_str());
        let signals = wait_for_signals(1, Duration::from_secs(1));
        check_signals(
            signals,
            Status::Failed,
            "install failed: not running from installer",
        );

        // Test a successful installation.
        set_mock_install_result(Ok(()));
        let status: (String,) =
            proxy.method_call(OS_INSTALL_SERVICE_INTERFACE, METHOD_START_OS_INSTALL, ())?;
        assert_eq!(status.0, Status::InProgress.as_str());
        let signals = wait_for_signals(1, Duration::from_secs(1));
        check_signals(signals, Status::Succeeded, "install succeeded");

        Ok(())
    }

    /// Check one of the dbus constants produced by build.rs to
    /// validate the C++ value is correctly translated to Rust.
    #[test]
    fn test_dbus_constant() {
        assert_eq!(
            OS_INSTALL_SERVICE_INTERFACE,
            "org.chromium.OsInstallService"
        );
    }
}
