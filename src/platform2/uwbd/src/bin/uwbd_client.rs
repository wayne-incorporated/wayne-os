// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provide a simple uwbd client, used to verify the uwbd service end-to-end.

use std::error::Error;
use std::time::Duration;

use dbus::blocking::{Connection, Proxy};
use protobuf::Message;
use uwb_core::proto::bindings::{
    DisableResponse, EnableResponse, SetLoggerModeRequest, SetLoggerModeResponse, UciLoggerMode,
};
use uwb_core::proto::utils::write_to_bytes;

use uwbd::common::{DBUS_OBJECT_PATH, DBUS_SERVICE_NAME};
use uwbd::dbus_bindings::client::OrgChromiumUwbd;

fn main() -> Result<(), Box<dyn Error>> {
    const TIMEOUT: Duration = Duration::from_millis(5000);

    // Connect to D-Bus and create uwbd proxy.
    let dbus_connection = Connection::new_system()?;
    let uwbd_proxy = Proxy::new(
        DBUS_SERVICE_NAME,
        DBUS_OBJECT_PATH,
        TIMEOUT,
        &dbus_connection,
    );

    // Call the uwbd methods.
    let mut request = SetLoggerModeRequest::new();
    request.set_logger_mode(UciLoggerMode::UCI_LOGGER_MODE_UNFILTERED);
    let request_bytes = write_to_bytes(&request)?;
    let result_bytes = uwbd_proxy.set_logger_mode(request_bytes)?;
    let result = SetLoggerModeResponse::parse_from_bytes(&result_bytes)?;
    println!("SetLoggerMode(Unfiltered) returns: {:?}", result.status);

    let result_bytes = uwbd_proxy.enable()?;
    let result = EnableResponse::parse_from_bytes(&result_bytes)?;
    println!("Enable() returns: {:?}", result.status);

    let result_bytes = uwbd_proxy.disable()?;
    let result = DisableResponse::parse_from_bytes(&result_bytes)?;
    println!("Disable() returns: {:?}", result.status);

    Ok(())
}
