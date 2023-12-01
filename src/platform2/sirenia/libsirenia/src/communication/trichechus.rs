// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The module that handles the communication api for sending messages between
//! Dugong and Trichechus

use std::fmt::Debug;
use std::result::Result as StdResult;
use std::str::FromStr;

use serde::Deserialize;
use serde::Serialize;
use serde_bytes::ByteBuf;
use sirenia_rpc_macros::sirenia_rpc;
use thiserror::Error as ThisError;

use crate::app_info::AppManifest;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ThisError)]
pub enum Error {
    #[error("App ID not found in the manifest")]
    InvalidAppId,
    #[error("Digest of TEE app executable is missing from the manifest")]
    DigestMissing,
    #[error("Digest of TEE app executable did not match value in manifest")]
    DigestMismatch,
    #[error("App not loadable")]
    AppNotLoadable,
    #[error("App requires developer mode")]
    RequiresDevmode,
    #[error("Sandbox type not implemented")]
    SandboxTypeNotImplemented,
    #[error("App not found at expected path")]
    AppPath,
    #[error("App not loaded yet")]
    AppNotLoaded,
    #[error("{0}")]
    Custom(String),
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Custom(s)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AppInfo {
    pub app_id: String,
    pub port_number: u32,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum SystemEvent {
    Halt,
    PowerOff,
    Reboot,
}

impl FromStr for SystemEvent {
    type Err = String;

    fn from_str(event: &str) -> StdResult<SystemEvent, String> {
        Ok(match event {
            "halt" => SystemEvent::Halt,
            "poweroff" => SystemEvent::PowerOff,
            "reboot" => SystemEvent::Reboot,
            _ => return Err(format!("Failed to convert '{}' to an event.", event)),
        })
    }
}

#[sirenia_rpc(error = "Error")]
pub trait Trichechus<E> {
    fn start_session(&mut self, app_info: AppInfo, args: Vec<String>) -> StdResult<(), E>;

    // Loads app `app_id` with the image in 'elf'. If `allow_unverified` is true and developer mode
    // is enabled, the load will load `elf` even if its SHA mismatches the expected SHA for `app_id`
    // as per the manifest.
    fn load_app(
        &mut self,
        app_id: String,
        elf: Vec<u8>,
        allow_unverified: bool,
    ) -> StdResult<(), E>;

    #[error()]
    fn get_apps(&mut self) -> StdResult<AppManifest, E>;
    #[error()]
    fn get_logs(&mut self) -> StdResult<Vec<ByteBuf>, E>;

    fn prepare_manatee_memory_service_socket(&mut self, port_number: u32) -> StdResult<(), E>;

    fn system_event(&mut self, event: SystemEvent) -> StdResult<(), E>;
}
