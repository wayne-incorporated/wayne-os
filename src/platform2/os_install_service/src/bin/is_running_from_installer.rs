// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::process;

use os_install_service::disk::is_running_from_installer;

fn main() {
    libchromeos::panic_handler::install_memfd_handler();
    match is_running_from_installer() {
        Ok(true) => {
            println!("yes");
        }
        Ok(false) => {
            println!("no");
        }
        Err(err) => {
            println!("failed to check if running from installer: {:#}", err);
            process::exit(1);
        }
    }
}
