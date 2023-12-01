// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Encapsulate the sub modules of crosh.

#![allow(clippy::unnecessary_wraps)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod base;
pub mod dev;
pub mod dispatcher;
pub mod legacy;
pub mod util;

use dispatcher::Dispatcher;
use libchromeos::sys::error;

pub fn setup_dispatcher() -> Dispatcher {
    let mut dispatcher = Dispatcher::new();

    if util::dev_commands_included() {
        legacy::register_dev_mode_commands(&mut dispatcher);
        dev::register(&mut dispatcher);
    }

    if util::usb_commands_included() {
        legacy::register_removable_commands(&mut dispatcher);
    }

    base::register(&mut dispatcher);
    legacy::register(&mut dispatcher);

    if let Err(err) = dispatcher.validate() {
        // Use error! too so that the message is included in the syslog.
        error!("FATAL: {}", err);
        panic!("FATAL: {}", err);
    }

    dispatcher
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_registered_commands() {
        util::set_dev_commands_included(true);
        util::set_usb_commands_included(true);
        setup_dispatcher();
    }
}
