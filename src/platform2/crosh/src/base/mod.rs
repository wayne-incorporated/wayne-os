// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// The base module handles registration of a base set of crosh commands.

mod arc;
mod bt_console;
mod builtin_corpssh;
mod ccd_pass;
mod display_debug;
mod dlc_install;
mod dmesg;
mod insert_coin;
mod packet_capture;
mod printscan_debug;
mod rollback;
mod set_time;
mod verify_ro;
mod vmc;
mod wireguard;

use crate::dispatcher::Dispatcher;

pub fn register(dispatcher: &mut Dispatcher) {
    arc::register(dispatcher);
    builtin_corpssh::register(dispatcher);
    bt_console::register(dispatcher);
    ccd_pass::register(dispatcher);
    dlc_install::register(dispatcher);
    display_debug::register(dispatcher);
    dmesg::register(dispatcher);
    insert_coin::register(dispatcher);
    packet_capture::register(dispatcher);
    printscan_debug::register(dispatcher);
    rollback::register(dispatcher);
    set_time::register(dispatcher);
    verify_ro::register(dispatcher);
    vmc::register(dispatcher);
    wireguard::register(dispatcher);
}
