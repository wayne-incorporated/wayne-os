// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The client binary for interacting with ManaTEE from command line on Chrome OS.

#![deny(unsafe_op_in_unsafe_fn)]

use std::env;
use std::fs::File;
use std::io::copy;
use std::io::stdin;
use std::io::stdout;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::mem::replace;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::path::Path;
use std::path::PathBuf;
use std::process::exit;
use std::process::ChildStderr;
use std::process::Command;
use std::process::Stdio;
use std::str::FromStr;
use std::sync::Mutex;
use std::thread::sleep;
use std::thread::spawn;
use std::thread::JoinHandle;
use std::time::Duration;
use std::time::Instant;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Error;
use anyhow::Result;
use dbus::arg::OwnedFd;
use dbus::blocking::Connection;
use dbus::blocking::Proxy;
use getopts::Options;
use libchromeos::chromeos::is_dev_mode;
use libchromeos::panic_handler::install_memfd_handler;
use libchromeos::sys::handle_eintr;
use libchromeos::sys::unix::vsock::SocketAddr as VsockAddr;
use libchromeos::sys::unix::vsock::VsockCid;
use libchromeos::sys::unix::wait_for_interrupt;
use libchromeos::sys::unix::KillOnDrop;
use libsirenia::build_info::BUILD_TIMESTAMP;
use libsirenia::cli::TransportTypeOption;
use libsirenia::cli::VerbosityOption;
use libsirenia::cli::DEFAULT_TRANSPORT_TYPE_LONG_NAME;
use libsirenia::cli::DEFAULT_TRANSPORT_TYPE_SHORT_NAME;
use libsirenia::communication::trichechus;
use libsirenia::communication::trichechus::AppInfo;
use libsirenia::communication::trichechus::Trichechus;
use libsirenia::communication::trichechus::TrichechusClient;
use libsirenia::linux::events::CopyFdEventSource;
use libsirenia::linux::events::EventMultiplexer;
use libsirenia::sys;
use libsirenia::sys::dup;
use libsirenia::sys::is_a_tty;
use libsirenia::transport::Transport;
use libsirenia::transport::TransportType;
use libsirenia::transport::DEFAULT_CLIENT_PORT;
use libsirenia::transport::DEFAULT_SERVER_PORT;
use libsirenia::transport::LOOPBACK_DEFAULT;
use log::debug;
use log::error;
use log::info;
use manatee_client::client::OrgChromiumManaTEEInterface;

const DEFAULT_DBUS_TIMEOUT: Duration = Duration::from_secs(25);

const DEVELOPER_SHELL_APP_ID: &str = "shell";

const MINIJAIL_NAME: &str = "minijail0";
const CRONISTA_NAME: &str = "cronista";
const TRICHECHUS_NAME: &str = "trichechus";
const DUGONG_NAME: &str = "dugong";

const CRONISTA_USER: &str = "cronista";
const DUGONG_USER: &str = "dugong";

fn to_dbus_error(err: Error) -> dbus::Error {
    dbus::Error::new_failed(&format!("{}", err))
}

/// Implementation of the D-Bus interface over a direct Vsock connection.
struct Passthrough {
    client: Mutex<TrichechusClient>,
    uri: TransportType,
}

impl Passthrough {
    fn new(trichechus_uri: Option<TransportType>, bind_timeout: Option<Duration>) -> Result<Self> {
        let uri = trichechus_uri.unwrap_or(TransportType::VsockConnection(VsockAddr {
            cid: VsockCid::Host,
            port: DEFAULT_SERVER_PORT,
        }));

        info!("Opening connection to trichechus");
        // Adjust the source port when connecting to a non-standard port to facilitate testing.
        let bind_port = match uri.get_port().context("failed to get port")? {
            DEFAULT_SERVER_PORT => DEFAULT_CLIENT_PORT,
            port => port + 1,
        };
        let start = Instant::now();
        // Duration::default() is zero (i.e. no timeout).
        let bind_timeout = bind_timeout.unwrap_or_default();
        let mut transport = loop {
            match uri.try_into_client(Some(bind_port)) {
                Ok(t) => break t,
                Err(err) => {
                    if start.elapsed() >= bind_timeout {
                        return Err(err).context("failed to get client for transport");
                    }
                    sleep(Duration::from_millis(100));
                }
            }
        };

        let transport = transport.connect().map_err(|e| {
            error!("transport connect failed: {}", e);
            anyhow!("transport connect failed: {}", e)
        })?;
        Ok(Passthrough {
            client: Mutex::new(TrichechusClient::new(transport)),
            uri,
        })
    }

    fn start_teeapplication_impl(
        &self,
        app_id: &str,
        args: Vec<&str>,
    ) -> Result<(i32, OwnedFd, OwnedFd)> {
        info!("Setting up app vsock.");
        let mut app_transport = self
            .uri
            .try_into_client(None)
            .context("failed to get client for transport")?;
        let addr = app_transport.bind().context("failed to bind to socket")?;
        let app_info = AppInfo {
            app_id: app_id.to_string(),
            port_number: addr.get_port().context("failed to get port")?,
        };

        info!("Starting rpc.");
        self.client
            .lock()
            .unwrap()
            .start_session(app_info, args.iter().map(|s| s.to_string()).collect())
            .context("start_session rpc failed")?;

        info!("Starting TEE application: {}", app_id);
        let Transport { r, w, id: _ } = app_transport
            .connect()
            .context("failed to connect to socket")?;

        info!("Forwarding stdio.");
        // Safe because ownership of the file descriptors is transferred.
        Ok((
            0, /* error_code */
            unsafe { OwnedFd::new(r.into_raw_fd()) },
            unsafe { OwnedFd::new(w.into_raw_fd()) },
        ))
    }
}

impl OrgChromiumManaTEEInterface for Passthrough {
    fn start_teeapplication(
        &self,
        app_id: &str,
        args: Vec<&str>,
        _allow_unverified: bool,
    ) -> std::result::Result<(i32, OwnedFd, OwnedFd), dbus::Error> {
        self.start_teeapplication_impl(app_id, args)
            .map_err(to_dbus_error)
    }

    fn system_event(&self, event: &str) -> std::result::Result<String, dbus::Error> {
        match self.client.lock().unwrap().system_event(
            event
                .parse()
                .map_err(|err: String| dbus::Error::new_failed(&err))?,
        ) {
            Ok(()) => Ok(String::new()),
            Err(err) => match err.downcast::<trichechus::Error>() {
                Ok(err) => Ok(err.to_string()),
                Err(err) => Err(dbus::Error::new_failed(&err.to_string())),
            },
        }
    }

    fn get_manatee_memory_service_socket(&self) -> std::result::Result<OwnedFd, dbus::Error> {
        Err(to_dbus_error(anyhow!(
            "GetManateeMemeoryServiceSocket not supported"
        )))
    }
}

fn connect_to_dugong<'a>(c: &'a Connection) -> Result<Proxy<'a, &Connection>> {
    Ok(c.with_proxy(
        "org.chromium.ManaTEE",
        "/org/chromium/ManaTEE1",
        DEFAULT_DBUS_TIMEOUT,
    ))
}

fn handle_app_fds_interactive(input: File, output: File) -> Result<()> {
    let mut ctx = EventMultiplexer::new().unwrap();
    let raw = sys::ScopedRaw::new().map_err(|_| anyhow!("failed to put stdin in raw mode"))?;

    let copy_in = CopyFdEventSource::new(Box::new(input), Box::new(dup::<File>(1)?))?;
    ctx.add_event(Box::new(copy_in.0))?;
    ctx.add_event(Box::new(copy_in.1))?;

    let copy_out = CopyFdEventSource::new(Box::new(dup::<File>(0)?), Box::new(output))?;
    ctx.add_event(Box::new(copy_out.0))?;
    ctx.add_event(Box::new(copy_out.1))?;

    let start = ctx.len();
    while ctx.len() == start {
        ctx.run_once()?;
    }
    drop(raw);
    Ok(())
}

fn handle_app_fds(mut input: File, mut output: File) -> Result<()> {
    let output_thread_handle = spawn(move || -> Result<()> {
        handle_eintr!(copy(&mut input, &mut stdout())).context("failed to copy to stdout")?;
        // Once stdout is closed, stdin is invalid and it is time to exit.
        exit(0);
    });

    handle_eintr!(copy(&mut stdin(), &mut output)).context("failed to copy from stdin")?;

    output_thread_handle
        .join()
        .map_err(|boxed_err| *boxed_err.downcast::<Error>().unwrap())?
}

fn start_manatee_app(
    api: &dyn OrgChromiumManaTEEInterface,
    app_id: &str,
    args: Vec<&str>,
    handler: &dyn Fn(File, File) -> Result<()>,
    allow_unverified: bool,
) -> Result<()> {
    info!("Starting TEE application: {}", app_id);
    let (fd_in, fd_out) = match api
        .start_teeapplication(app_id, args, allow_unverified)
        .context("failed to call start_teeapplication D-Bus method")?
    {
        (0, fd_in, fd_out) => (fd_in, fd_out),
        (code, _, _) => bail!("start app failed with code: {}", code),
    };
    info!("Forwarding stdio.");

    // Safe because ownership of the file descriptor is transferred.
    let file_in = unsafe { File::from_raw_fd(fd_in.into_fd()) };
    // Safe because ownership of the file descriptor is transferred.
    let file_out = unsafe { File::from_raw_fd(fd_out.into_fd()) };

    handler(file_in, file_out)
}

fn system_event(trichechus_uri: Option<TransportType>, event: &str) -> Result<()> {
    let timeout = if trichechus_uri.is_none() {
        info!("Connecting to D-Bus.");
        let connection = Connection::new_system().context("failed to get D-Bus connection")?;
        let conn_path = connect_to_dugong(&connection)?;
        match conn_path.system_event(event) {
            Ok(v) => {
                return if v.is_empty() {
                    Ok(())
                } else {
                    Err(anyhow!("failed to invoke system event: {}", v))
                }
            }
            Err(err) => {
                error!("D-Bus call failed: {}", err);
                info!("Falling back to default vsock interface.");
            }
        }
        Some(Duration::from_secs(10))
    } else {
        None
    };
    let passthrough = Passthrough::new(trichechus_uri, timeout)?;
    let err = passthrough
        .system_event(event)
        .context("system_event D-Bus call failed")?;
    if err.is_empty() {
        Ok(())
    } else {
        Err(anyhow!("system_event failed with: {}", err))
    }
}

fn dbus_start_manatee_app(
    app_id: &str,
    args: Vec<&str>,
    handler: &dyn Fn(File, File) -> Result<()>,
    allow_unverified: bool,
) -> Result<()> {
    info!("Connecting to D-Bus.");
    let connection = Connection::new_system().context("failed to get D-Bus connection")?;
    let conn_path = connect_to_dugong(&connection)?;
    start_manatee_app(&conn_path, app_id, args, handler, allow_unverified)
}

fn direct_start_manatee_app(
    trichechus_uri: TransportType,
    app_id: &str,
    args: Vec<&str>,
    elf: Option<Vec<u8>>,
    handler: &dyn Fn(File, File) -> Result<()>,
    allow_unverified: bool,
) -> Result<()> {
    let passthrough = Passthrough::new(Some(trichechus_uri), None)?;

    if allow_unverified && !is_dev_mode().unwrap_or(false) {
        bail!("allow_unverified is only respected in developer mode");
    }

    if let Some(elf) = elf {
        info!("Transmitting TEE app.");
        passthrough
            .client
            .lock()
            .unwrap()
            .load_app(app_id.to_string(), elf, allow_unverified)
            .context("load_app rpc failed")?;
    }

    // Allow loading unverified apps when developer mode is enabled to ease testing use cases.
    start_manatee_app(&passthrough, app_id, args, handler, allow_unverified)
}

fn locate_command(name: &str) -> Result<PathBuf> {
    which::which(name).with_context(|| format!("failed to locate command '{}'", name))
}

fn read_line<R: Read>(job_name: &str, reader: &mut BufReader<R>, line: &mut String) -> Result<()> {
    line.clear();
    reader
        .read_line(line)
        .with_context(|| format!("failed to read stderr of {}", job_name))?;
    eprint!("{}", &line);
    Ok(())
}

fn get_listening_port<R: Read + Send + 'static, C: Fn(&str) -> bool>(
    job_name: &'static str,
    read: R,
    conditions: &[C],
) -> Result<(u32, JoinHandle<()>)> {
    let mut reader = BufReader::new(read);
    let mut line = String::new();
    read_line(job_name, &mut reader, &mut line)?;

    for condition in conditions {
        if condition(&line) {
            read_line(job_name, &mut reader, &mut line)?;
        }
    }

    if !line.contains("waiting for connection at: ip://127.0.0.1:") {
        bail!(
            "failed to locate listening URI for {0:}; last line: '{1:}'",
            job_name.to_string(),
            line
        );
    }
    let port = u32::from_str(&line[line.rfind(':').unwrap() + 1..line.len() - 1])
        .with_context(|| format!("failed to parse port number from line '{0:}'", line))?;

    let join_handle =
        spawn(
            move || {
                while read_line(job_name, &mut reader, &mut line).is_ok() && !line.is_empty() {}
            },
        );
    Ok((port, join_handle))
}

fn run_test_environment() -> Result<()> {
    let minijail_path = locate_command(MINIJAIL_NAME)?;
    let cronista_path = locate_command(CRONISTA_NAME)?;
    let trichechus_path = locate_command(TRICHECHUS_NAME)?;
    let dugong_path = locate_command(DUGONG_NAME)?;

    // Cronista.
    let mut cronista = KillOnDrop::from(
        Command::new(&minijail_path)
            .args(&[
                "-u",
                CRONISTA_USER,
                "--",
                cronista_path.to_str().unwrap(),
                "-U",
                "ip://127.0.0.1:0",
            ])
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to start command '{}'", CRONISTA_NAME))?,
    );

    let (cronista_port, cronista_stderr_print) = get_listening_port(
        CRONISTA_NAME,
        replace(&mut cronista.as_mut().stderr, Option::<ChildStderr>::None).unwrap(),
        &[|l: &str| l.ends_with("starting cronista\n")],
    )?;

    // Trichechus.
    let mut trichechus = KillOnDrop::from(
        Command::new(trichechus_path)
            .args(&[
                "-U",
                "ip://127.0.0.1:0",
                "-C",
                &format!("ip://127.0.0.1:{}", cronista_port),
            ])
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to start command '{}'", TRICHECHUS_NAME))?,
    );

    let conditions = [
        |l: &str| l == "Syslog exists.\n" || l == "Creating syslog.\n",
        |l: &str| l.contains("starting trichechus:"),
        |l: &str| l.contains("Unable to start new process group:"),
    ];
    let (trichechus_port, trichechus_stderr_print) = get_listening_port(
        TRICHECHUS_NAME,
        replace(&mut trichechus.as_mut().stderr, Option::<ChildStderr>::None).unwrap(),
        &conditions,
    )?;

    // Dugong.
    let dugong = KillOnDrop::from(
        Command::new(&minijail_path)
            .args(&[
                "-u",
                DUGONG_USER,
                "--",
                dugong_path.to_str().unwrap(),
                "-U",
                &format!("ip://127.0.0.1:{}", trichechus_port),
            ])
            .spawn()
            .with_context(|| format!("failed to start command '{}'", DUGONG_NAME))?,
    );

    println!("*** Press Ctrl-C to continue. ***");
    wait_for_interrupt().ok();

    drop(dugong);
    drop(trichechus);
    drop(cronista);

    trichechus_stderr_print.join().unwrap();
    cronista_stderr_print.join().unwrap();

    Ok(())
}

fn split_args<I: IntoIterator<Item = String>>(into_iter: I) -> (Vec<String>, Vec<String>) {
    let mut opts = Vec::new();
    let mut args = Vec::new();

    let mut found_delimiter = false;
    for value in into_iter {
        if !found_delimiter {
            if value != "--" {
                opts.push(value)
            } else {
                found_delimiter = true;
            }
        } else {
            args.push(value);
        }
    }
    (opts, args)
}

fn get_usage() -> String {
    format!("[-h] [-r | -a <name> [-X <path>] [-i true|false] | --halt | --poweroff | --reboot] [-- ...]\nversion: {}", BUILD_TIMESTAMP)
}

fn main() -> Result<()> {
    const HELP_SHORT_NAME: &str = "h";
    const RUN_SERVICES_LOCALLY_SHORT_NAME: &str = "r";

    const APP_ID_SHORT_NAME: &str = "a";
    const APP_ELF_SHORT_NAME: &str = "X";
    const INTERACTIVE_SHORT_NAME: &str = "i";

    const HALT_LONG_NAME: &str = "halt";
    const POWEROFF_LONG_NAME: &str = "poweroff";
    const REBOOT_LONG_NAME: &str = "reboot";

    const ALLOW_UNVERIFIED_LONG_NAME: &str = "allow-unverified";

    install_memfd_handler();
    let mut options = Options::new();
    options.optflag(HELP_SHORT_NAME, "help", "Show this help string.");
    options.optflag(
        RUN_SERVICES_LOCALLY_SHORT_NAME,
        "run-services-locally",
        "Run a test sirenia environment locally.",
    );

    options.optopt(
        APP_ID_SHORT_NAME,
        "app-id",
        "Specify the app ID to invoke.",
        "demo_app",
    );
    options.optopt(
        APP_ELF_SHORT_NAME,
        "app-elf",
        "Specify the app elf file to load.",
        "/bin/bash",
    );
    options.optopt(
        INTERACTIVE_SHORT_NAME,
        "interactive",
        "Enable or disable readline support. Defaults to false except for 'shell'",
        "true|false",
    );
    options.optflag(
        "",
        ALLOW_UNVERIFIED_LONG_NAME,
        "allow app to load if hash doesn't match",
    );

    options.optflag("", HALT_LONG_NAME, "Send a halt command to the hypervisor.");
    options.optflag(
        "",
        POWEROFF_LONG_NAME,
        "Send a poweroff command to the hypervisor.",
    );
    options.optflag(
        "",
        REBOOT_LONG_NAME,
        "Send a reboot command to the hypervisor.",
    );
    let trichechus_uri_opt = TransportTypeOption::new(
        DEFAULT_TRANSPORT_TYPE_SHORT_NAME,
        DEFAULT_TRANSPORT_TYPE_LONG_NAME,
        "trichechus URI (set to bypass dugong D-Bus)",
        LOOPBACK_DEFAULT,
        &mut options,
    );
    let verbosity_opt = VerbosityOption::default(&mut options);

    let (opts, args) = split_args(env::args());
    let matches = options.parse(&opts[1..]).map_err(|err| {
        eprintln!("{}", options.usage(&get_usage()));
        anyhow!("failed parse command line options: {}", err)
    })?;

    let verbosity = verbosity_opt.from_matches(&matches);
    stderrlog::new().verbosity(verbosity).init().unwrap();
    debug!("Verbosity: {}", verbosity);

    if matches.opt_present(HELP_SHORT_NAME) {
        println!("{}", options.usage(&get_usage()));
        return Ok(());
    }

    // Validate options, by counting mutually exclusive groups of options.
    let mut opts = Vec::<String>::new();
    let mut mutually_exclusive_opts = 0;
    if matches.opt_present(RUN_SERVICES_LOCALLY_SHORT_NAME) {
        mutually_exclusive_opts += 1;
        opts.push(format!("-{}", RUN_SERVICES_LOCALLY_SHORT_NAME));
    }
    if matches.opt_present(APP_ID_SHORT_NAME)
        || matches.opt_present(APP_ELF_SHORT_NAME)
        || matches.opt_present(INTERACTIVE_SHORT_NAME)
    {
        mutually_exclusive_opts += 1;
        if matches.opt_present(APP_ID_SHORT_NAME) {
            opts.push(format!("-{}", APP_ID_SHORT_NAME));
        } else if matches.opt_present(APP_ELF_SHORT_NAME) {
            opts.push(format!("-{}", APP_ELF_SHORT_NAME));
        } else {
            opts.push(format!("-{}", INTERACTIVE_SHORT_NAME));
        }
    }
    for long_name in &[HALT_LONG_NAME, POWEROFF_LONG_NAME, REBOOT_LONG_NAME] {
        if matches.opt_present(long_name) {
            mutually_exclusive_opts += 1;
            opts.push(format!("--{}", long_name));
        }
    }
    if mutually_exclusive_opts > 1 {
        eprintln!("{}", options.usage(&get_usage()));
        bail!("incompatible options set : {0:?}", opts);
    }

    let trichechus_uri = trichechus_uri_opt.from_matches(&matches).map_err(|err| {
        eprintln!("{}", options.usage(&get_usage()));
        anyhow!("failed to get transport type option: {}", err)
    })?;

    let interactive: Option<bool> = if matches.opt_present(INTERACTIVE_SHORT_NAME) {
        Some(
            matches
                .opt_get::<String>(INTERACTIVE_SHORT_NAME)
                .unwrap()
                .unwrap()
                .parse()
                .map_err(|err| {
                    eprintln!("{}", options.usage(&get_usage()));
                    anyhow!("invalid value for -i: {}", err)
                })?,
        )
    } else {
        None
    };

    if matches.opt_present(RUN_SERVICES_LOCALLY_SHORT_NAME) {
        return run_test_environment();
    }

    if matches.opt_present(HALT_LONG_NAME) {
        return system_event(trichechus_uri, "halt");
    }

    if matches.opt_present(POWEROFF_LONG_NAME) {
        return system_event(trichechus_uri, "poweroff");
    }

    if matches.opt_present(REBOOT_LONG_NAME) {
        return system_event(trichechus_uri, "reboot");
    }

    let app_id = matches
        .opt_get(APP_ID_SHORT_NAME)
        .unwrap()
        .unwrap_or_else(|| DEVELOPER_SHELL_APP_ID.to_string());

    let elf = if let Some(elf_path) = matches.opt_get::<String>(APP_ELF_SHORT_NAME).unwrap() {
        let mut data = Vec::<u8>::new();
        File::open(Path::new(&elf_path))
            .context("open failed")?
            .read_to_end(&mut data)
            .context("read failed")?;
        Some(data)
    } else {
        None
    };

    let handler: &dyn Fn(File, File) -> Result<()> = if is_a_tty(stdin().as_raw_fd())
        && interactive.unwrap_or_else(|| app_id.as_str() == DEVELOPER_SHELL_APP_ID)
    {
        &handle_app_fds_interactive
    } else {
        &handle_app_fds
    };

    let args_ref = args.iter().map(AsRef::<str>::as_ref).collect();
    let allow_unverified = matches.opt_present(ALLOW_UNVERIFIED_LONG_NAME);
    match trichechus_uri {
        None => dbus_start_manatee_app(&app_id, args_ref, handler, allow_unverified),
        Some(trichechus_uri) => direct_start_manatee_app(
            trichechus_uri,
            &app_id,
            args_ref,
            elf,
            handler,
            allow_unverified,
        ),
    }
}
