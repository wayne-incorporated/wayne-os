// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This script montiors dbus for suspend events and then sends a command
// to the cr50 to disable deep sleep during suspend.
// The disable deep sleep flag is transiant, so it must be resent before
// each suspend.

use hwsec_utils::context::RealContext;
use hwsec_utils::cr50::monitor_suspend_dbus_signal;
use libchromeos::syslog;

fn main() {
    let ident = match syslog::get_ident_from_process() {
        Some(ident) => ident,
        None => std::process::exit(1),
    };

    if let Err(e) = syslog::init(ident, false /* Don't log to stderr */) {
        eprintln!("failed to initialize syslog: {}", e);
        std::process::exit(1)
    }

    let mut real_ctx = RealContext::new();

    if monitor_suspend_dbus_signal(&mut real_ctx).is_err() {
        std::process::exit(1)
    };
}
