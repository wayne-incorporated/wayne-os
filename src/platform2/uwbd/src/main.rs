// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::error::Error;
use std::sync::{Arc, Mutex};

use dbus::blocking::SyncConnection;
use dbus::channel::MatchingReceiver;
use dbus::Path;
use dbus_crossroads::Crossroads;
use log::{debug, error};

use uwbd::common::{DBUS_OBJECT_PATH, DBUS_SERVICE_NAME};
use uwbd::dbus_bindings::server::org_chromium_uwbd::register_org_chromium_uwbd;
use uwbd::dbus_uwb_service::DBusUwbService;
use uwbd::dbus_uwb_service_callback::DBusUwbServiceCallback;

/// Serve the D-Bus SyncConnection.
///
/// This function is forked from Crossroads::serve(), because Crossroads::serve() only accepts
/// dbus::blocking::Connection. The parameter `cr` is wrapped by Arc<Mutex<_>> for making it Sync.
fn serve_sync_connection(
    cr: Arc<Mutex<Crossroads>>,
    connection: &dbus::blocking::SyncConnection,
) -> Result<(), dbus::Error> {
    connection.start_receive(
        dbus::message::MatchRule::new_method_call(),
        Box::new(move |msg, conn| {
            cr.lock().unwrap().handle_message(msg, conn).unwrap();
            true
        }),
    );

    // Serve clients forever.
    loop {
        connection.process(std::time::Duration::from_millis(1000))?;
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    // Install the custom panic handler to get better crash signatures.
    libchromeos::panic_handler::install_memfd_handler();
    // Initialize the logging to syslog.
    syslog::init_unix(syslog::Facility::LOG_USER, log::LevelFilter::Debug)?;

    // Connect to D-Bus.
    let dbus_connection = Arc::new(SyncConnection::new_system().map_err(|e| {
        error!("Failed to connect to D-Bus: {}", e);
        e
    })?);
    dbus_connection
        .request_name(DBUS_SERVICE_NAME, false, true, false)
        .map_err(|e| {
            error!(
                "Failed to request the service name {}: {}",
                DBUS_SERVICE_NAME, e
            );
            e
        })?;

    // Create a new crossroads instance, register the IfaceToken, and insert it to the service path.
    let mut crossroad = Crossroads::new();
    let iface_token = register_org_chromium_uwbd(&mut crossroad);
    crossroad.insert(
        DBUS_OBJECT_PATH,
        &[iface_token],
        DBusUwbService::new(DBusUwbServiceCallback::new(
            dbus_connection.clone(),
            Path::new(DBUS_OBJECT_PATH)?.into_static(),
        ))
        .ok_or("Failed to create DBusUwbService")?,
    );

    // Run the D-Bus service forever.
    debug!("Starting the UWB D-Bus daemon");
    serve_sync_connection(Arc::new(Mutex::new(crossroad)), &dbus_connection).map_err(|e| {
        error!("Failed to serve the daemon: {}", e);
        e
    })?;
    unreachable!()
}
