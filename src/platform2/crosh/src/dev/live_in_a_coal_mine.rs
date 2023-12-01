// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Provides the command "live_in_a_coal_mine" for switching to the canary update channel.

use std::process;

use crate::dispatcher::wait_for_result;
use crate::dispatcher::Arguments;
use crate::dispatcher::Command;
use crate::dispatcher::Dispatcher;
use crate::dispatcher::{self};
use crate::util::prompt_for_yes;
use crate::util::UPDATE_ENGINE;

static CANARY_CHANNEL_ARGS: &[&str] = &["-channel=canary-channel"];
static SHOW_CHANNEL_ARGS: &[&str] = &["--show_channel"];

pub fn register(dispatcher: &mut Dispatcher) {
    dispatcher.register_command(
        Command::new(
            "live_in_a_coal_mine".to_string(),
            "".to_string(),
            "Switch to the canary channel.

  WARNING: This is bleeding edge software and is often more buggy than the dev
  channel.  Please do not use this unless you are a developer.  This is often
  updated daily and has only passed automated tests -- the QA level is low!

  This channel may not always boot reliably or have a functioning auto update
  mechanism. Do not do this unless you are prepared to recover your ChromeOS
  device, please be familiar with this article first:
  https://support.google.com/chromebook/answer/1080595"
                .to_string(),
        )
        .set_command_callback(Some(execute_live_in_a_coal_mine)),
    );
}

fn execute_live_in_a_coal_mine(_cmd: &Command, _args: &Arguments) -> Result<(), dispatcher::Error> {
    if prompt_for_yes("Are you sure you want to change to the canary channel?") {
        wait_for_result(
            process::Command::new(UPDATE_ENGINE)
                .args(CANARY_CHANNEL_ARGS)
                .spawn()
                .map_err(|_| dispatcher::Error::CommandReturnedError)?,
        )?;
        wait_for_result(
            process::Command::new(UPDATE_ENGINE)
                .args(SHOW_CHANNEL_ARGS)
                .spawn()
                .map_err(|_| dispatcher::Error::CommandReturnedError)?,
        )?;
    } else {
        println!("Fly, my pretties, fly! (not changing channels)");
    }
    Ok(())
}
