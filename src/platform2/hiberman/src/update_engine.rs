// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements a client interface to the update_engine.

use std::time::Duration;

use anyhow::Context as AnyhowContext;
use anyhow::Result;
use dbus::blocking::Connection;
use log::info;
use protobuf::Message;
use system_api::update_engine::Operation;
use system_api::update_engine::StatusResult;
use update_engine_dbus::client::OrgChromiumUpdateEngineInterface;

/// Define the default maximum duration the update_engine proxy will wait for method
/// call responses.
const UPDATE_ENGINE_DBUS_PROXY_TIMEOUT: Duration = Duration::from_secs(30);

pub fn is_update_engine_idle() -> Result<bool> {
    let status = get_status().context("Failed to get update engine status")?;
    let current_operation = status.current_operation.enum_value();
    if current_operation != Ok(Operation::IDLE) {
        info!("Update engine status is {:?}", status.current_operation);
    }

    Ok(current_operation == Ok(Operation::IDLE))
}

fn get_status() -> Result<StatusResult> {
    // First open up a connection to the system bus.
    let conn = Connection::new_system().context("Failed to start system dbus connection")?;

    // Second, create a wrapper struct around the connection that makes it easy
    // to send method calls to a specific destination and path.
    let proxy = conn.with_proxy(
        "org.chromium.UpdateEngine",
        "/org/chromium/UpdateEngine",
        UPDATE_ENGINE_DBUS_PROXY_TIMEOUT,
    );

    // Fire off the method call to update_engine.
    let result = proxy
        .get_status_advanced()
        .context("Failed to call UpdateEngine.GetStatusAdvanced")?;
    // Parse the resulting protobuf back into a structure.
    StatusResult::parse_from_bytes(&result).context("Failed to parse StatusResult protobuf")
}
