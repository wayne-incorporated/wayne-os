// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements Chrome OS specific logic such as code that depends on system_api.

use std::ffi::{CString, NulError};
use std::os::raw::{c_char, c_int};
use std::path::{Path, PathBuf};
use std::str::{from_utf8, Utf8Error};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dbus::blocking::Connection;
use dbus::Error as DbusError;
use lazy_static::lazy_static;
use system_api::client::OrgChromiumSessionManagerInterface;
use thiserror::Error as ThisError;
use vboot_reference_sys::crossystem::*;

// 25 seconds is the default timeout for dbus-send.
pub const DBUS_TIMEOUT: Duration = Duration::from_secs(25);
const DAEMONSTORE_BASE_PATH: &str = "/run/daemon-store/";

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("D-Bus failed to connect: {0}")]
    DbusConnection(DbusError),
    #[error("D-Bus call failed: {0}")]
    DbusMethodCall(DbusError),
    #[error("crossystem call failed")]
    CrossystemFailed,
    #[error("got invalid utf8: {0}")]
    InvalidUtf8(Utf8Error),
    #[error("invalid argument: {0}")]
    CStringNew(NulError),
}

pub type Result<R> = std::result::Result<R, Error>;

/// Fetch the user ID hash from session manager as a hexadecimal string.
pub fn get_user_id_hash() -> Result<String> {
    let connection = Connection::new_system().map_err(Error::DbusConnection)?;
    let conn_path = connection.with_proxy(
        "org.chromium.SessionManager",
        "/org/chromium/SessionManager",
        DBUS_TIMEOUT,
    );

    let (_, user_id_hash) = conn_path
        .retrieve_primary_session()
        .map_err(Error::DbusMethodCall)?;

    Ok(user_id_hash)
}

/// Return the expected daemonstore path of the specified daemon if there is an active user session.
pub fn get_daemonstore_path(daemon_name: &str) -> Result<PathBuf> {
    let user_hash = get_user_id_hash()?;
    Ok(Path::new(DAEMONSTORE_BASE_PATH)
        .join(daemon_name)
        .join(user_hash))
}

/// Return true if the device is in developer mode.
pub fn is_dev_mode() -> Result<bool> {
    Crossystem::new()
        .get_int_property(CrossystemIntProperty::CrosDebug)
        .map(|x| x == 1)
}

const BUFFER_SIZE: u16 = 128;

/// Integer properties present in crossystem.
pub enum CrossystemIntProperty {
    /// Used to check dev mode.
    CrosDebug,
    DebugBuild,
}

impl AsRef<str> for CrossystemIntProperty {
    fn as_ref(&self) -> &'static str {
        match self {
            CrossystemIntProperty::CrosDebug => "cros_debug",
            CrossystemIntProperty::DebugBuild => "debug_build",
        }
    }
}

/// String properties present in crossystem.
pub enum CrossystemStringProperty {
    Arch,
}

impl AsRef<str> for CrossystemStringProperty {
    fn as_ref(&self) -> &'static str {
        match self {
            CrossystemStringProperty::Arch => "arch",
        }
    }
}

/// An Rust abstraction for `vboot/crossystem.h`.
pub struct Crossystem {
    mutex: Arc<Mutex<()>>,
}

fn check_return(ret: c_int) -> Result<c_int> {
    match ret {
        -1 => Err(Error::CrossystemFailed),
        ret => Ok(ret),
    }
}

impl Crossystem {
    pub fn new() -> Self {
        lazy_static! {
            static ref MUTEX: Arc<Mutex<()>> = Arc::new(Mutex::new(()));
        }

        Crossystem {
            mutex: MUTEX.clone(),
        }
    }

    pub fn get_int_property(&self, property: CrossystemIntProperty) -> Result<c_int> {
        let _guard = self.mutex.lock().unwrap();
        let name = CString::new(AsRef::<str>::as_ref(&property)).unwrap();

        // Safe because it doesn't change any system state, mutex guard provides thread safety, and
        // name is owned.
        check_return(unsafe { VbGetSystemPropertyInt(name.as_ptr()) })
    }

    pub fn get_string_property(&self, property: CrossystemStringProperty) -> Result<String> {
        let _guard = self.mutex.lock().unwrap();
        let name = CString::new(AsRef::<str>::as_ref(&property)).unwrap();
        let mut buffer: Vec<u8> = vec![0; BUFFER_SIZE as usize];

        // Safe because it doesn't change any system state, mutex guard provides thread safety, and
        // both name and buffer are owned.
        check_return(unsafe {
            VbGetSystemPropertyString(
                name.as_ptr(),
                buffer.as_mut_ptr() as *mut c_char,
                BUFFER_SIZE.into(),
            )
        })?;

        let str_len = buffer
            .iter()
            .position(|&x| x == b'\0')
            .unwrap_or(buffer.len());
        match from_utf8(&buffer[0..str_len]) {
            Ok(ret) => Ok(ret.to_string()),
            Err(err) => Err(Error::InvalidUtf8(err)),
        }
    }

    pub fn set_int_property(&self, property: CrossystemIntProperty, value: c_int) -> Result<()> {
        let _guard = self.mutex.lock().unwrap();
        let name = CString::new(AsRef::<str>::as_ref(&property)).unwrap();

        // Safe because the mutex guard provides thread safety, and name is owned.
        check_return(unsafe { VbSetSystemPropertyInt(name.as_ptr(), value) }).map(drop)
    }

    pub fn set_string_property(
        &self,
        property: CrossystemStringProperty,
        value: &str,
    ) -> Result<()> {
        let _guard = self.mutex.lock().unwrap();
        let name = CString::new(AsRef::<str>::as_ref(&property)).unwrap();
        let value = CString::new(value).map_err(Error::CStringNew)?;

        // Safe because the mutex guard provides thread safety, and both name and value are owned.
        check_return(unsafe { VbSetSystemPropertyString(name.as_ptr(), value.as_ptr()) }).map(drop)
    }
}

impl Default for Crossystem {
    fn default() -> Self {
        Crossystem::new()
    }
}
