// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements a basic power_manager client.

use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context as AnyhowContext;
use anyhow::Result;
use dbus::blocking::Connection;
use log::debug;
use log::error;
use log::info;
use sync::Mutex;
use system_api::client::OrgChromiumPowerManager;

use crate::hiberutil::log_duration;
use crate::metrics::DurationMetricUnit;
use crate::metrics::METRICS_LOGGER;

/// Define the name used on powerd dbus.
const POWERD_DBUS_NAME: &str = "org.chromium.PowerManager";
/// Define the path used within powerd dbus.
const POWERD_DBUS_PATH: &str = "/org/chromium/PowerManager";

/// Define the default maximum duration the powerd proxy will wait for method
/// call responses.
const POWERD_DBUS_PROXY_TIMEOUT: Duration = Duration::from_secs(60);

/// Define the amount of time to process requests for before checking for a
/// result. Make this long enough that we're not busy looping, but short enough
/// that an extra period won't be noticeable to humans.
const POWERD_PROCESS_PERIOD: Duration = Duration::from_millis(50);

/// Define how long to wait around for powerd to finish the RequestSuspend
/// method before printing impatiently that we're still waiting. This should be
/// long enough that a correctly functioning run will not see it, but short
/// enough that a confused developer at the console with a broken system will.
const POWERD_REPRINT_PERIOD: Duration = Duration::from_secs(30);

/// Values for the flavor parameter of powerd's RequestSuspend method.
#[repr(u32)]
enum PowerdSuspendFlavor {
    FromDiskPrepare = 3,
    FromDiskAbort = 4,
}

/// Implements a pending resume ticket. When created, it tells powerd to prepare
/// for imminent resume. When dropped, notifies powerd that the resume has been
/// aborted.
pub struct PowerdPendingResume {}

impl PowerdPendingResume {
    pub fn new() -> Result<Self> {
        powerd_request_suspend(PowerdSuspendFlavor::FromDiskPrepare)?;
        wait_for_hibernate_resume_ready()?;
        Ok(PowerdPendingResume {})
    }
}

impl Drop for PowerdPendingResume {
    fn drop(&mut self) {
        if let Err(e) = powerd_request_suspend(PowerdSuspendFlavor::FromDiskAbort) {
            error!("Failed to notify powerd of aborted resume: {}", e);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HibernateResumeReady {}

impl dbus::arg::ReadAll for HibernateResumeReady {
    fn read(_i: &mut dbus::arg::Iter) -> std::result::Result<Self, dbus::arg::TypeMismatchError> {
        Ok(HibernateResumeReady {})
    }
}

impl dbus::message::SignalArgs for HibernateResumeReady {
    const NAME: &'static str = "HibernateResumeReady";
    const INTERFACE: &'static str = POWERD_DBUS_NAME;
}

/// Helper function to wait for a HibernateResumeReady signal to come in from powerd.
fn wait_for_hibernate_resume_ready() -> Result<()> {
    // First open up a connection to the session bus.
    let conn = Connection::new_system().context("Failed to start system dbus connection")?;

    // Second, create a wrapper struct around the connection that makes it easy
    // to send method calls to a specific destination and path.
    let proxy = conn.with_proxy(
        POWERD_DBUS_NAME,
        POWERD_DBUS_PATH,
        POWERD_DBUS_PROXY_TIMEOUT,
    );

    // Set up a handler to record every time a signal comes in.
    let signals = Arc::new(Mutex::new(Vec::new()));
    let signals_copy = signals.clone();
    proxy.match_signal(
        move |signal: HibernateResumeReady, _: &Connection, _: &dbus::Message| {
            signals_copy.lock().push(signal);

            // Return false to abandon the match.
            false
        },
    )?;

    info!("Waiting for HibernateResumeReady signal");
    let start = Instant::now();
    loop {
        let end_time = Instant::now() + POWERD_REPRINT_PERIOD;
        while Instant::now() < end_time {
            // Wait for signals.
            conn.process(POWERD_PROCESS_PERIOD).unwrap();
            if signals.lock().len() != 0 {
                let duration = start.elapsed();
                log_duration("Got powerd HibernateResumeReady signal", duration);
                let mut metrics_logger = METRICS_LOGGER.lock().unwrap();
                metrics_logger.log_duration_sample(
                    "Platform.Hibernate.HibernateResumeReady",
                    duration,
                    DurationMetricUnit::Seconds,
                    10,
                );
                return Ok(());
            }
        }

        info!("Still waiting for HibernateResumeReady signal");
    }
}

/// Helper function to make a simple RequestSuspend d-bus call to powerd.
fn powerd_request_suspend(flavor: PowerdSuspendFlavor) -> Result<()> {
    // First open up a connection to the session bus.
    let conn = Connection::new_system().context("Failed to start system dbus connection")?;

    // Second, create a wrapper struct around the connection that makes it easy
    // to send method calls to a specific destination and path.
    let proxy = conn.with_proxy(
        POWERD_DBUS_NAME,
        POWERD_DBUS_PATH,
        POWERD_DBUS_PROXY_TIMEOUT,
    );

    let external_wakeup_count: u64 = u64::MAX;
    let wakeup_timeout: i32 = 0;
    let flavor = flavor as u32;
    info!("Calling powerd RequestSuspend, flavor {}", flavor);
    proxy.request_suspend(external_wakeup_count, wakeup_timeout, flavor)?;
    debug!("RequestSuspend returned");
    Ok(())
}
