// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use dbus::arg::AppendAll;
use dbus::blocking::SyncConnection;
use dbus::channel::Sender;
use dbus::message::SignalArgs;
use dbus::Path;
use log::error;
use uwb_core::service::ProtoUwbServiceCallback;

use crate::dbus_bindings::server::{
    OrgChromiumUwbdOnRangeDataReceived, OrgChromiumUwbdOnServiceReset,
    OrgChromiumUwbdOnSessionStateChanged, OrgChromiumUwbdOnUciDeviceStatusChanged,
    OrgChromiumUwbdOnVendorNotificationReceived,
};

pub struct DBusUwbServiceCallback {
    dbus_connection: Arc<SyncConnection>,
    dbus_object_path: Path<'static>,
}

impl DBusUwbServiceCallback {
    pub fn new(dbus_connection: Arc<SyncConnection>, dbus_object_path: Path<'static>) -> Self {
        Self {
            dbus_connection,
            dbus_object_path,
        }
    }

    fn send_signal<M: SignalArgs + AppendAll>(&mut self, msg: M) {
        let msg = msg.to_emit_message(&self.dbus_object_path);
        if let Err(e) = self.dbus_connection.send(msg) {
            error!("Failed to send D-Bus signal: {:?}", e);
        }
    }
}

impl ProtoUwbServiceCallback for DBusUwbServiceCallback {
    fn on_service_reset(&mut self, payload: Vec<u8>) {
        self.send_signal(OrgChromiumUwbdOnServiceReset { payload });
    }

    fn on_uci_device_status_changed(&mut self, payload: Vec<u8>) {
        self.send_signal(OrgChromiumUwbdOnUciDeviceStatusChanged { payload });
    }

    fn on_session_state_changed(&mut self, payload: Vec<u8>) {
        self.send_signal(OrgChromiumUwbdOnSessionStateChanged { payload });
    }

    fn on_range_data_received(&mut self, payload: Vec<u8>) {
        self.send_signal(OrgChromiumUwbdOnRangeDataReceived { payload });
    }

    fn on_vendor_notification_received(&mut self, payload: Vec<u8>) {
        self.send_signal(OrgChromiumUwbdOnVendorNotificationReceived { payload });
    }
}
