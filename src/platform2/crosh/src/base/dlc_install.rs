// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Provides the command "dlc_install" for crosh.

use std::process::{self};

use lazy_static::lazy_static;
use regex::Regex;

use crate::dispatcher::{self, wait_for_result, Arguments, Command, Dispatcher};

const EXECUTABLE: &str = "/usr/bin/dlcservice_util";
// This is a magical string that dlcservice passes into udpate_engine daemon to
// transform into the full https:// QA Omaha server URL.
const TESTSERVER: &str = "autest";

const CMD: &str = "dlc_install";
const USAGE: &str = "<dlc-id>";
const HELP: &str = "Trigger a DLC installation against a **test** update server.

The **test** update server will serve signed DLC payloads which will only
successfully install if signed and verifiable. Otherwise, installations will
fail. The magical string 'autest' is passed into update_engine during this
installation, which will make requests against QA Omaha server and not the
production Omaha server.

WARNING: This may install an untested version of the DLC which was never
intended for end users!";

pub fn register(dispatcher: &mut Dispatcher) {
    dispatcher.register_command(
        Command::new(CMD.to_string(), USAGE.to_string(), HELP.to_string())
            .set_command_callback(Some(dlc_install_callback)),
    );
}

fn dlc_install_callback(_cmd: &Command, _args: &Arguments) -> Result<(), dispatcher::Error> {
    match validate_args(_args) {
        Ok(dlc_id) => execute_dlc_install(&dlc_id),
        Err(err) => Err(err),
    }
}

fn validate_args(_args: &Arguments) -> Result<String, dispatcher::Error> {
    let args = _args.get_args();
    if args.len() != 1 {
        return Err(dispatcher::Error::CommandInvalidArguments(
            "Please pass in a single DLC ID to install.".to_string(),
        ));
    }

    let dlc_id = &args[0];
    match validate_dlc(dlc_id) {
        Ok(()) => Ok(dlc_id.to_string()),
        Err(err) => Err(err),
    }
}

fn validate_dlc(_dlc_id: &str) -> Result<(), dispatcher::Error> {
    if _dlc_id.len() > 40 {
        return Err(dispatcher::Error::CommandInvalidArguments(
            "DLC ID is too long.".to_string(),
        ));
    }

    lazy_static! {
        static ref RE: Regex = Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9-]+$").unwrap();
    }
    if !RE.is_match(_dlc_id) {
        return Err(dispatcher::Error::CommandInvalidArguments(
            "DLC ID is not a valid format.".to_string(),
        ));
    }
    match is_dlc_supported(_dlc_id) {
        Ok(()) => Ok(()),
        Err(_) => Err(dispatcher::Error::CommandInvalidArguments(
            "DLC ID is unsupported.".to_string(),
        )),
    }
}

fn is_dlc_supported(_dlc_id: &str) -> Result<(), dispatcher::Error> {
    wait_for_result(
        process::Command::new(EXECUTABLE)
            .args(vec![
                "--dlc_state".to_string(),
                flag_and_arg("--id", _dlc_id),
            ])
            .spawn()
            .or(Err(dispatcher::Error::CommandReturnedError))?,
    )
}

fn execute_dlc_install(_dlc_id: &str) -> Result<(), dispatcher::Error> {
    wait_for_result(
        process::Command::new(EXECUTABLE)
            .args(vec![
                "--install".to_string(),
                flag_and_arg("--omaha_url", TESTSERVER),
                flag_and_arg("--id", _dlc_id),
            ])
            .spawn()
            .or(Err(dispatcher::Error::CommandReturnedError))?,
    )
}

fn flag_and_arg(_flag: &str, _arg: &str) -> String {
    vec![_flag.to_string(), _arg.to_string()].join("=")
}
