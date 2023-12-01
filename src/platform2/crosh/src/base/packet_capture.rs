// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides the command "packet_capture" for crosh which can capture packets and store them in .pcap file.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs::{metadata, remove_file, File};
use std::io::{copy, stdout, Write};
use std::os::unix::io::IntoRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{sleep, spawn};
use std::time::Duration;

use dbus::arg::{self, OwnedFd, Variant};
use dbus::blocking::Connection;
use getopts::{self, Options};
use libc::{c_int, SIGINT};
use libchromeos::sys::{error, pipe};
use system_api::client::OrgChromiumDebugd;

use crate::dispatcher::{self, Arguments, Command, Dispatcher};
use crate::util::{
    clear_signal_handlers, dev_commands_included, generate_output_file_path, set_signal_handlers,
    DEFAULT_DBUS_TIMEOUT,
};

const FLAGS: [(
    &str,
    &str,
    &str,
    bool, /* option only available in dev-mode */
); 6] = [
    ("device", "<device>", "device", false),
    ("max-size", "<max size in MiB>", "max_size", false),
    ("frequency", "<frequency>", "frequency", true),
    ("ht-location", "<above|below>", "ht_location", true),
    ("vht-width", "<80|160>", "vht_width", true),
    (
        "monitor-connection-on",
        "<monitored_device>",
        "monitor_connection_on",
        true,
    ),
];

const HELP: &str = r#"
Start packet capture.  Start a device-based capture on <device>,
  or do an over-the-air capture on <frequency> with an optionally
  provided HT channel location or VHT channel width.  An over-the-air
  capture can also be initiated using the channel parameters of a
  currently connected <monitored_device>.  Note that over-the-air
  captures are not available with all 802.11 devices. Set <max_size>
  to stop the packet capture if the output .pcap file size exceedes this
  limit. Only device-based capture options (--device and --max-size) are
  available in verified mode. Switch to developer mode to use other
  options.
"#;

pub fn register(dispatcher: &mut Dispatcher) {
    dispatcher.register_command(
        Command::new(
            "packet_capture".to_string(),
            "".to_string(),
            "Run the packet_capture command via debugd.".to_string(),
        )
        .set_command_callback(Some(execute_packet_capture))
        .set_help_callback(packet_capture_help),
    );
}

fn packet_capture_help(_cmd: &Command, w: &mut dyn Write, _level: usize) {
    let help = create_help_string();
    w.write_all(help.as_bytes()).unwrap();
    w.flush().unwrap();
}

fn create_help_string() -> String {
    let mut help = "Usage: packet_capture [options]\n".to_string();
    for flag in FLAGS.iter() {
        let _ = writeln!(help, "\t--{} \t{}", flag.0, flag.1);
    }
    help.push_str(HELP);
    help
}

fn stop_packet_capture(handle: &str) -> Result<(), dispatcher::Error> {
    let connection = Connection::new_system().map_err(|err| {
        error!("ERROR: Failed to get D-Bus connection: {}", err);
        dispatcher::Error::CommandReturnedError
    })?;
    let conn_path = connection.with_proxy(
        "org.chromium.debugd",
        "/org/chromium/debugd",
        DEFAULT_DBUS_TIMEOUT,
    );

    conn_path.packet_capture_stop(handle).map_err(|err| {
        println!("ERROR: Got unexpected result: {}", err);
        dispatcher::Error::CommandReturnedError
    })?;

    Ok(())
}

/// Set to true when SIGINT is received and triggers sending a stop command over D-Bus.
static STOP_FLAG: AtomicBool = AtomicBool::new(false);
/// Set to true when the original D-Bus command closes the pipe signalling completion.
static DONE_FLAG: AtomicBool = AtomicBool::new(false);

// Handle Ctrl-c/SIGINT by sending a stop over D-Bus.
extern "C" fn sigint_handler(_: c_int) {
    STOP_FLAG.store(true, Ordering::Release);
}

fn execute_packet_capture(_cmd: &Command, args: &Arguments) -> Result<(), dispatcher::Error> {
    let mut opts = Options::new();

    for flag in FLAGS.iter() {
        opts.optopt("", flag.0, flag.1, "");
    }

    opts.optflag("h", "help", "print command usage");

    let matches = opts
        .parse(args.get_tokens())
        .map_err(|_| dispatcher::Error::CommandReturnedError)?;

    if matches.opt_present("h") {
        println!("{}", create_help_string());
        return Ok(());
    }

    let mut dbus_options = HashMap::new();
    let dev_mode: bool = dev_commands_included();
    for flag in FLAGS.iter() {
        // Iterate over the argument options.
        let name = flag.2;
        let argument_name = flag.0;
        if let Some(value) = matches.opt_str(argument_name) {
            // Frequency based capture options are only available for developer mode.
            if !dev_mode && flag.3 {
                eprintln!("Option --{} is only available in developer mode. Please switch to developer mode to use.", flag.0);
                return Err(dispatcher::Error::CommandReturnedError);
            }
            // The argument will be sent to dbus as int for "frequency" and "max-size" option
            // and String for other options.
            let variant_value: Variant<Box<dyn arg::RefArg>> =
                if argument_name == "frequency" || argument_name == "max-size" {
                    Variant(Box::new(value.parse::<i32>().unwrap()))
                } else {
                    Variant(Box::new(value))
                };
            dbus_options.insert(name.to_string(), variant_value);
        }
    }

    // Create and open the capture file.
    let capture_file_path = generate_output_file_path("packet_capture", "pcap").unwrap();
    execute_packet_capture_helper(&capture_file_path, dbus_options)?;

    let capture_file_metadata =
        metadata(&capture_file_path).map_err(|_| dispatcher::Error::CommandReturnedError)?;
    if capture_file_metadata.len() == 0 {
        // Remove the capture file if nothing is captured in the file.
        remove_capture_file_on_error(&capture_file_path);
    } else {
        println!("Capture file stored in: {}", &capture_file_path);
        println!("Output file may contain personal information. Don't share it with people you don't trust.");
    }
    Ok(())
}

fn remove_capture_file_on_error(capture_file_path: &str) {
    match remove_file(capture_file_path) {
        Ok(()) => eprintln!("No capture done!"),
        _ => eprintln!("Could not remove capture file."),
    }
}

fn execute_packet_capture_helper(
    output_file_path: &str,
    dbus_options: HashMap<String, Variant<Box<dyn arg::RefArg>>>,
) -> Result<(), dispatcher::Error> {
    let capture_file = File::create(output_file_path).map_err(|err| {
        eprintln!("Couldn't open capture file: {}", err);
        dispatcher::Error::CommandReturnedError
    })?;

    let connection = Connection::new_system().map_err(|err| {
        eprintln!("ERROR: Failed to get D-Bus connection: {}", err);
        dispatcher::Error::CommandReturnedError
    })?;
    let conn_path = connection.with_proxy(
        "org.chromium.debugd",
        "/org/chromium/debugd",
        DEFAULT_DBUS_TIMEOUT,
    );

    // Safe because sigint_handler is async signal safe.
    unsafe { set_signal_handlers(&[SIGINT], sigint_handler) };
    // Pass a pipe through D-Bus to collect the response.
    let (mut read_pipe, write_pipe) = pipe(true).unwrap();
    let handle = conn_path
        .packet_capture_start(
            // Safe because write_pipe isn't copied elsewhere.
            unsafe { OwnedFd::new(write_pipe.into_raw_fd()) },
            unsafe { OwnedFd::new(capture_file.into_raw_fd()) },
            dbus_options,
        )
        .map_err(|err| {
            eprintln!("ERROR: Got unexpected result: {}", err);
            if let Err(err) = copy(&mut read_pipe, &mut stdout()) {
                eprintln!("ERROR: Failed to print the output: {}", err);
            }
            STOP_FLAG.store(true, Ordering::Release);
            clear_signal_handlers(&[SIGINT]);
            dispatcher::Error::CommandReturnedError
        })?;

    // Start a thread to send a stop on SIGINT, or stops when DONE_FLAG is set.
    let watcher = spawn(move || loop {
        if STOP_FLAG.load(Ordering::Acquire) {
            stop_packet_capture(&handle).unwrap_or(());
            break;
        }
        if DONE_FLAG.load(Ordering::Acquire) {
            break;
        }
        sleep(Duration::from_millis(50));
    });

    // Print the stdout response.
    if let Err(err) = copy(&mut read_pipe, &mut stdout()) {
        eprintln!("ERROR: Failed to print the output: {}", err);
        STOP_FLAG.store(true, Ordering::Release);
        clear_signal_handlers(&[SIGINT]);
        watcher.join().ok();
        return Err(dispatcher::Error::CommandReturnedError);
    }
    clear_signal_handlers(&[SIGINT]);
    DONE_FLAG.store(true, Ordering::Release);
    watcher
        .join()
        .map_err(|_| dispatcher::Error::CommandReturnedError)?;
    Ok(())
}
