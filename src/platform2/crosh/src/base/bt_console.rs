// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Provides the command "bt_console" for crosh which manages Bluetooth.

use dbus::blocking::Connection;
use libchromeos::sys::error;
use std::fmt::{self, Display};
use std::io::Write;
use std::process::{self};
use std::time::Duration;

use crate::dispatcher::{self, wait_for_result, Arguments, Command, Dispatcher};

const BLUEZ_EXECUTABLE: &str = "/usr/bin/bluetoothctl";
const BLUEZ_DEFAULT_ARG: &str = "--restricted";

const FLOSS_EXECUTABLE: &str = "/usr/bin/btclient";
const FLOSS_DEFAULT_ARG: &str = "--restricted";

const HELP: &str = r#"
  Enters a Bluetooth debugging console.
"#;

#[derive(Debug)]
pub enum Error {
    DbusBluetoothManagerService(dbus::Error, String),
    DbusConnection(dbus::Error),
}

impl Display for Error {
    #[remain::check]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        #[sorted]
        match self {
            DbusBluetoothManagerService(err, m) => write!(f, "failed to call '{}': {}", m, err),
            DbusConnection(err) => write!(f, "failed to connect to D-Bus: {}", err),
        }
    }
}

pub fn register(dispatcher: &mut Dispatcher) {
    dispatcher.register_command(
        Command::new("bt_console".to_string(), "".to_string(), "".to_string())
            .set_command_callback(Some(execute_btclient))
            .set_help_callback(btclient_help),
    );
}

fn is_floss_enabled() -> Result<bool, Error> {
    let connection = Connection::new_system().map_err(Error::DbusConnection)?;

    let proxy = connection.with_proxy(
        "org.chromium.bluetooth.Manager",
        "/org/chromium/bluetooth/Manager",
        Duration::from_secs(10),
    );

    let (reply,): (bool,) = proxy
        .method_call("org.chromium.bluetooth.Manager", "GetFlossEnabled", ())
        .map_err(|err| {
            error!("ERROR: D-Bus method call failed: {}", err);
            Error::DbusBluetoothManagerService(err, "GetFlossEnabled".to_string())
        })?;

    Ok(reply)
}

fn btclient_help(_cmd: &Command, w: &mut dyn Write, _level: usize) {
    w.write_all(HELP.as_bytes()).unwrap();
    w.flush().unwrap();
}

fn execute_btclient(_cmd: &Command, args: &Arguments) -> Result<(), dispatcher::Error> {
    if !args.get_args().is_empty() {
        return Err(dispatcher::Error::CommandInvalidArguments(String::from(
            "No argument is allowed",
        )));
    }

    if !is_floss_enabled().unwrap_or(false) {
        return wait_for_result(
            process::Command::new(BLUEZ_EXECUTABLE)
                .args(vec![BLUEZ_DEFAULT_ARG])
                .spawn()
                .or(Err(dispatcher::Error::CommandReturnedError))?,
        );
    }

    wait_for_result(
        process::Command::new(FLOSS_EXECUTABLE)
            .args(vec![FLOSS_DEFAULT_ARG])
            .spawn()
            .or(Err(dispatcher::Error::CommandReturnedError))?,
    )
}
