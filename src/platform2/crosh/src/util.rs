// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Provides helper functions used by handler implementations of crosh commands.

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::env;
use std::error;
use std::fmt::{self, Display};
use std::fs::read_to_string;
use std::io::stdin;
use std::io::stdout;
use std::io::Read;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chrono::Local;
use dbus::blocking::Connection;
use libc::c_int;
use libchromeos::chromeos;
use libchromeos::sys::error;
use libchromeos::sys::unix::{clear_signal_handler, register_signal_handler};
use regex::Regex;

// 25 seconds is the default timeout for dbus-send.
pub const DEFAULT_DBUS_TIMEOUT: Duration = Duration::from_secs(25);
// Path to update_engine_client.
pub const UPDATE_ENGINE: &str = "/usr/bin/update_engine_client";

const CROS_USER_ID_HASH: &str = "CROS_USER_ID_HASH";

static INCLUDE_DEV: AtomicBool = AtomicBool::new(false);
static INCLUDE_USB: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
pub enum Error {
    DbusChromeFeaturesService(dbus::Error, String),
    DbusConnection(dbus::Error),
    DbusGetUserIdHash(chromeos::Error),
    NoMatchFound,
    WrappedError(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    #[remain::check]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        #[sorted]
        match self {
            DbusChromeFeaturesService(err, m) => write!(f, "failed to call '{}': {}", m, err),
            DbusConnection(err) => write!(f, "failed to connect to D-Bus: {}", err),
            DbusGetUserIdHash(err) => {
                write!(f, "failed to get user-id hash over to D-Bus: {:?}", err)
            }
            NoMatchFound => write!(f, "No match found."),
            WrappedError(err) => write!(f, "{}", err),
        }
    }
}

impl<T: error::Error> From<T> for Error {
    fn from(err: T) -> Self {
        Error::WrappedError(format!("{:?}", err))
    }
}

// Return the user ID hash from the environment. If it is not available, fetch it from session
// manager and set the environment variable.
pub fn get_user_id_hash() -> Result<String> {
    if let Ok(lookup) = env::var(CROS_USER_ID_HASH) {
        return Ok(lookup);
    }

    let user_id_hash = chromeos::get_user_id_hash().map_err(|err| {
        error!("ERROR: D-Bus call failed: {}", err);
        Error::DbusGetUserIdHash(err)
    })?;

    env::set_var(CROS_USER_ID_HASH, &user_id_hash);
    Ok(user_id_hash)
}

// Return the output file path for the given output type in user's Downloads directory.
pub fn generate_output_file_path(output_type: &str, file_extension: &str) -> Result<String> {
    let date = Local::now();
    let formatted_date = date.format("%Y-%m-%d_%H.%M.%S");
    let user_id_hash = get_user_id_hash()?;
    let random_string: String = thread_rng().sample_iter(&Alphanumeric).take(6).collect();
    Ok(format!(
        "/home/user/{}/MyFiles/Downloads/{}_{}_{}.{}",
        user_id_hash, output_type, formatted_date, random_string, file_extension
    ))
}

pub fn is_chrome_feature_enabled(method_name: &str) -> Result<bool> {
    let user_id_hash = get_user_id_hash()?;

    let connection = Connection::new_system().map_err(|err| {
        error!("ERROR: Failed to get D-Bus connection: {}", err);
        Error::DbusConnection(err)
    })?;

    let proxy = connection.with_proxy(
        "org.chromium.ChromeFeaturesService",
        "/org/chromium/ChromeFeaturesService",
        DEFAULT_DBUS_TIMEOUT,
    );

    let (reply,): (bool,) = proxy
        .method_call(
            "org.chromium.ChromeFeaturesServiceInterface",
            method_name,
            (user_id_hash,),
        )
        .map_err(|err| {
            error!("ERROR: D-Bus method call failed: {}", err);
            Error::DbusChromeFeaturesService(err, method_name.to_string())
        })?;

    Ok(reply)
}

pub fn is_removable() -> Result<bool> {
    let dev = root_dev()?;
    let groups = Regex::new(r#"/dev/([^/]+?)p?[0-9]+$"#)?
        .captures(&dev)
        .ok_or(Error::NoMatchFound)?;

    let dev = groups.get(1).unwrap().as_str();

    match read_to_string(format!("/sys/block/{}/removable", dev)) {
        Ok(contents) => Ok(contents.trim() == "1"),
        Err(err) => Err(err.into()),
    }
}

pub fn is_consumer_device() -> Result<bool> {
    let output = Command::new("/usr/sbin/cryptohome")
        .arg("--action=install_attributes_get")
        .arg("--name=enterprise.mode")
        .output()?;

    let stdout = String::from_utf8(output.stdout).unwrap();

    // If the attribute is not set, cryptohome will treat it as an error, return 1 and output
    // nothing.
    match output.status.code() {
        Some(0) => Ok(!stdout.contains("enterprise")),
        Some(1) if stdout.is_empty() => Ok(true),
        None => Err(Error::WrappedError("failed to get exit code".to_string())),
        _ => Err(Error::WrappedError(stdout)),
    }
}

pub fn set_dev_commands_included(value: bool) {
    INCLUDE_DEV.store(value, Ordering::Release);
}

pub fn set_usb_commands_included(value: bool) {
    INCLUDE_USB.store(value, Ordering::Release);
}

pub fn dev_commands_included() -> bool {
    INCLUDE_DEV.load(Ordering::Acquire)
}

pub fn usb_commands_included() -> bool {
    INCLUDE_USB.load(Ordering::Acquire)
}

/// # Safety
/// handler needs to be async safe.
pub unsafe fn set_signal_handlers(signums: &[c_int], handler: extern "C" fn(c_int)) {
    for signum in signums {
        // Safe as long as handler is async safe.
        if unsafe { register_signal_handler(*signum, handler) }.is_err() {
            error!("sigaction failed for {}", signum);
        }
    }
}

pub fn clear_signal_handlers(signums: &[c_int]) {
    for signum in signums {
        if clear_signal_handler(*signum).is_err() {
            error!("sigaction failed for {}", signum);
        }
    }
}

fn root_dev() -> Result<String> {
    let mut child = Command::new("rootdev")
        .arg("-s")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()?;

    let mut result = String::new();
    child.stdout.take().unwrap().read_to_string(&mut result)?;
    child.wait()?;

    Ok(result.trim().to_string())
}

/// Print 'msg' followed by a [y/N] prompt and test the user input. Return true for 'y' or 'Y'.
pub fn prompt_for_yes(msg: &str) -> bool {
    print!("{} [y/N] ", msg);
    stdout().flush().ok();

    let mut response = String::new();
    stdin().read_line(&mut response).ok();
    matches!(response.as_str(), "y\n" | "Y\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_output_file_path() {
        // Set the user id hash env variable to a random value because it is necessary for output path generation.
        env::set_var(CROS_USER_ID_HASH, "useridhashfortesting");
        let expected_path_re = Regex::new(concat!(
            r"^/home/user/.+/MyFiles/Downloads/",
            r"packet_capture_\d{4}-\d{2}-\d{2}_\d{2}.\d{2}.\d{2}_.{6}\.pcap$"
        ))
        .unwrap();
        let result_output_path = generate_output_file_path("packet_capture", "pcap").unwrap();
        assert!(expected_path_re.is_match(&result_output_path));
    }
}
