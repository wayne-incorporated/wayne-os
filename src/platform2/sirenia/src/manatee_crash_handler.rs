// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This is a crash handler for the hypervisor. It is set as the core handler
//! by trichechus at startup. It is responsible for sending crash information
//!  to the crash reporter framework in the CrOS guest.

use std::env;

use libchromeos::syslog;
use log::warn;

const IDENT: &str = "manatee_crash_handler";

// TODO(b/239801953): Statically enforce absence of panics.
// Deliberately returning () since the crash handler should not panic.
fn main() {
    if let Err(e) = syslog::init(IDENT.to_string(), false /*log_to_stderr*/) {
        eprintln!("failed to setup logging: {}", e);
    }
    let mut argv = env::args();
    argv.next(); // executable name
    let pid = argv.next().unwrap_or_else(|| "".to_string());
    let tid = argv.next().unwrap_or_else(|| "".to_string());
    let sig = argv.next().unwrap_or_else(|| "".to_string());
    let uid = argv.next().unwrap_or_else(|| "".to_string());
    let gid = argv.next().unwrap_or_else(|| "".to_string());
    let exe = argv.next().unwrap_or_else(|| "".to_string());
    warn!(
        "crash: pid={} tid={} sig={} uid={} gid={} exe={}",
        pid, tid, sig, uid, gid, exe
    );
}
