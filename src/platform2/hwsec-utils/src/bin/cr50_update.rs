// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use hwsec_utils::context::RealContext;
use hwsec_utils::cr50::cr50_update;
use hwsec_utils::error::HwsecError;
use libchromeos::syslog;

// This script is run at postinstall phase of Chrome OS installation process.
// It checks if the currently running cr50 image is ready to accept a
// background update and if the resident trunks_send utility is capable of
// updating the H1. If any of the checks fails, the script exits, otherwise it
// tries updating the H1 with the new cr50 image.
fn main() {
    let ident = match syslog::get_ident_from_process() {
        Some(ident) => ident,
        None => std::process::exit(1),
    };

    if let Err(e) = syslog::init(ident, true /* Don't log to stderr */) {
        eprintln!("failed to initialize syslog: {}", e);
        std::process::exit(1)
    }

    let mut real_ctx = RealContext::new();
    match cr50_update(&mut real_ctx) {
        Ok(()) => std::process::exit(0),
        Err(hwsec_error) => match hwsec_error {
            HwsecError::GsctoolError(err_code) => std::process::exit(err_code),
            _ => std::process::exit(-1),
        },
    }
}
