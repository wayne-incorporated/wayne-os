// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Provides the command "rollback" for switching to the canary update channel.

use std::process;

use crate::dispatcher::wait_for_result;
use crate::dispatcher::Arguments;
use crate::dispatcher::Command;
use crate::dispatcher::Dispatcher;
use crate::dispatcher::{self};
use crate::util::prompt_for_yes;
use crate::util::UPDATE_ENGINE;

static ROLLBACK_ARGS: &[&str] = &["--rollback"];

pub fn register(dispatcher: &mut Dispatcher) {
    dispatcher.register_command(
        Command::new(
            "rollback".to_string(),
            "".to_string(),
            "
  Attempt to rollback to the previous update cached on your system. Only
  available on non-stable channels and non-enterprise enrolled devices.

  Please note that this will powerwash your device."
                .to_string(),
        )
        .set_command_callback(Some(execute_rollback)),
    );
}

fn execute_rollback(_cmd: &Command, args: &Arguments) -> Result<(), dispatcher::Error> {
    if !args.get_args().is_empty() {
        return Err(dispatcher::Error::CommandInvalidArguments(
            "too many arguments".to_string(),
        ));
    }
    if !prompt_for_yes(
        "NB: This will powerwash your device!
Are you sure you want to rollback to the previous version?",
    ) {
        println!("Not attempting rollback.");
        return Ok(());
    }
    if wait_for_result(
        process::Command::new(UPDATE_ENGINE)
            .args(ROLLBACK_ARGS)
            .spawn()
            .map_err(|_| dispatcher::Error::CommandReturnedError)?,
    )
    .is_ok()
    {
        println!(concat!(
            "Rollback attempt succeeded -- after a couple minutes you will get an ",
            "update available and you should reboot to complete rollback."
        ))
    } else {
        println!("Rollback attempt failed. Check chrome://system for more information.");
    }
    Ok(())
}
