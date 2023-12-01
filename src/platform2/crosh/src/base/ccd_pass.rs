// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Provides the command "ccd_pass" for crosh

use std::path::Path;
use std::process;

use crate::dispatcher::{self, wait_for_result, Arguments, Command, Dispatcher};

const EXECUTABLE: &str = "/usr/sbin/gsctool";

pub fn register(dispatcher: &mut Dispatcher) {
    // Only register the ccd_pass command if the executable is present.
    if !Path::new(EXECUTABLE).exists() {
        return;
    }
    dispatcher.register_command(
        Command::new(
            "ccd_pass".to_string(),
            "".to_string(),
            "When prompted, set or clear CCD password (use the word 'clear' to clear
  the password)."
                .to_string(),
        )
        .set_command_callback(Some(execute_ccd_pass)),
    );
}

fn execute_ccd_pass(_cmd: &Command, _args: &Arguments) -> Result<(), dispatcher::Error> {
    wait_for_result(
        process::Command::new(EXECUTABLE)
            .arg("-t")
            .arg("-P")
            .spawn()
            .or(Err(dispatcher::Error::CommandReturnedError))?,
    )
}
