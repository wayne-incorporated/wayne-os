// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Provides the command "vmc" for crosh which manages containers inside the vm.

use std::io::{copy, Write};
use std::path::Path;
use std::process::{self, Stdio};

use crate::dispatcher::{self, wait_for_result, Arguments, Command, Dispatcher};
use crate::util::is_chrome_feature_enabled;

const EXECUTABLE: &str = "/usr/bin/vmc";

pub fn register(dispatcher: &mut Dispatcher) {
    const NAME: &str = "vmc";
    dispatcher.register_command(if Path::new(EXECUTABLE).exists() {
        Command::new(NAME.to_string(), "".to_string(), "".to_string())
            .set_command_callback(Some(execute_vmc))
            .set_help_callback(vmc_help)
    } else {
        Command::new_disabled_command(
            NAME.to_string(),
            "Sorry, but VMs are not supported on this device.".to_string(),
        )
    });
}

fn vmc_help(_cmd: &Command, w: &mut dyn Write, _level: usize) {
    let mut sub = process::Command::new(EXECUTABLE)
        .arg("--help")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    if copy(&mut sub.stdout.take().unwrap(), w).is_err() {
        panic!();
    }

    if sub.wait().is_err() {
        panic!();
    }
}

fn execute_vmc(_cmd: &Command, args: &Arguments) -> Result<(), dispatcher::Error> {
    if !is_chrome_feature_enabled("IsVmManagementCliAllowed").unwrap_or(false) {
        eprintln!("CLI access to VMs is disallowed by policy.");
        eprintln!("Please contact your administrator for assistance.");
        return Err(dispatcher::Error::CommandReturnedError);
    }

    wait_for_result(
        process::Command::new(EXECUTABLE)
            .args(args.get_args())
            .spawn()
            .or(Err(dispatcher::Error::CommandReturnedError))?,
    )
}
