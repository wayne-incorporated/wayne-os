// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements an API for managing device mapper (DM) devices

use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::str;

use anyhow::Context;
use anyhow::Result;

use crate::hiberutil::checked_command;
use crate::hiberutil::checked_command_output;

/// Path of the dmsetup utility.
const DMSETUP_PATH: &str = "/sbin/dmsetup";

pub struct DeviceMapper {}

impl DeviceMapper {
    /// Create a new DM device.
    pub fn create_device(name: &str, table: &str) -> Result<()> {
        let args = vec![
            String::from("create"),
            name.to_string(),
            String::from("--table"),
            table.to_string(),
        ];

        Self::run_dmsetup(args).context(format!("Failed to create DM device '{name}'"))?;
        Ok(())
    }

    /// Remove an existing DM device.
    pub fn remove_device(name: &str) -> Result<()> {
        Self::run_dmsetup(["remove", name])
            .context(format!("Failed to remove DM device '{name}'"))?;
        Ok(())
    }

    /// Rename a DM device.
    pub fn rename_device(old_name: &str, new_name: &str) -> Result<()> {
        Self::run_dmsetup(["rename", old_name, new_name]).context(format!(
            "Failed to rename DM device '{old_name}' to '{new_name}"
        ))?;
        Ok(())
    }

    /// Set the UUID of a DM device.
    pub fn set_device_uuid(name: &str, uuid: &str) -> Result<()> {
        Self::run_dmsetup(["rename", name, "--setuuid", uuid])
            .context(format!("Failed to set UUID of DM device '{name}'"))?;
        Ok(())
    }

    /// Suspend a DM device.
    pub fn suspend_device(name: &str) -> Result<()> {
        Self::run_dmsetup(["suspend", name])
            .context(format!("Failed to suspend DM device '{name}'"))?;
        Ok(())
    }

    /// Resume a suspended DM device.
    pub fn resume_device(name: &str) -> Result<()> {
        Self::run_dmsetup(["resume", name])
            .context(format!("Failed to suspend DM device '{name}'"))?;
        Ok(())
    }

    /// Reload the device table of a DM device.
    pub fn reload_device_table(name: &str, table: &str) -> Result<()> {
        Self::run_dmsetup(["reload", name, "--table", table]).context(format!(
            "Failed to reload DM table for device \
                              '{name}' (table: '{table}')"
        ))?;
        Ok(())
    }

    /// Get the table of a DM device.
    pub fn get_device_table(name: &str) -> Result<String> {
        let out = checked_command_output(Command::new(DMSETUP_PATH).args(["table", name]))
            .context(format!("Failed to get DM table for device '{name}'"))?;

        let table = str::from_utf8(&out.stdout)
            .context(format!(
                "Table of DM device '{name}' contains non-UTF8 characters"
            ))?
            .trim()
            .to_string();
        Ok(table)
    }

    /// Check whether a DM device exists.
    pub fn device_exists(name: &str) -> bool {
        Self::run_dmsetup(["status", name]).is_ok()
    }

    /// Get the path of a DM device.
    pub fn device_path(name: &str) -> Result<PathBuf> {
        let symlink_path = Path::new("/dev/mapper").join(name);

        fs::canonicalize(symlink_path).map_err(anyhow::Error::from)
    }

    fn run_dmsetup<I, S>(args: I) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        checked_command(Command::new(DMSETUP_PATH).args(args))
    }
}
