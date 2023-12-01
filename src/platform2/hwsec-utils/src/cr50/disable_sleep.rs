// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use dbus::blocking::Connection;
use log::error;
use log::info;

use crate::command_runner::CommandRunner;
use crate::context::Context;
use crate::error::HwsecError;

/// Define the name used on powerd dbus.
const POWERD_DBUS_NAME: &str = "org.chromium.PowerManager";
/// Define the path used within powerd dbus.
const POWERD_DBUS_PATH: &str = "/org/chromium/PowerManager";
const TIMEOUT_DURATION: Duration = Duration::from_secs(60);
#[derive(Debug)]
struct SuspendImminent {}

impl dbus::arg::ReadAll for SuspendImminent {
    fn read(_i: &mut dbus::arg::Iter) -> std::result::Result<Self, dbus::arg::TypeMismatchError> {
        Ok(SuspendImminent {})
    }
}

impl dbus::message::SignalArgs for SuspendImminent {
    const NAME: &'static str = "SuspendImminent";
    const INTERFACE: &'static str = POWERD_DBUS_NAME;
}

fn send_disable_deep_sleep_command_to_cr50(ctx: &mut impl Context) -> Result<(), HwsecError> {
    info!("Sending disable deep sleep command to Cr50");
    let trunks_send_result = ctx
        .cmd_runner()
        .run("trunks_send", vec!["--raw", "80010000000c20000000003b"])
        .map_err(|_| {
            eprintln!("ERROR: Failed to run gsctool.");
            HwsecError::CommandRunnerError
        })?;

    if trunks_send_result.status.success() {
        info!("Disable sleep command sent to Cr50");
        Ok(())
    } else {
        error!("Error sending disable sleep command to Cr50");
        Err(HwsecError::InternalError)
    }
}

pub fn monitor_suspend_dbus_signal(ctx: &mut impl Context) -> Result<(), HwsecError> {
    // Start up a connection to the system bus.
    let conn = Connection::new_system().map_err(|_| {
        error!("Failed to start system dbus connection");
        HwsecError::InternalError
    })?;

    let proxy = conn.with_proxy(POWERD_DBUS_NAME, POWERD_DBUS_PATH, TIMEOUT_DURATION);

    let signal = Arc::new(Mutex::new(false));
    let signal_copy = Arc::clone(&signal);
    // Listen to the SuspendImminent signal on the org.chromium.PowerManager interface.
    info!("Start monitoring dbus for SuspendImminent signal");
    proxy
        .match_signal(
            move |_signal: SuspendImminent, _: &Connection, _: &dbus::Message| {
                let mut received = signal_copy.lock().unwrap();
                *received = true;
                // Return true to not abandon the match.
                true
            },
        )
        .map_err(|_| HwsecError::InternalError)?;

    // Listen to incoming signals forever.
    loop {
        conn.process(TIMEOUT_DURATION)
            .map_err(|_| HwsecError::InternalError)?;
        let mut received = signal.lock().unwrap();
        if *received {
            info!("SuspendImminent signal received");
            send_disable_deep_sleep_command_to_cr50(ctx)?;
            *received = false;
        }
    }
}
