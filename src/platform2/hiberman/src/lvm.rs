// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements LVM helper functions.

use std::fs::OpenOptions;
use std::fs::{self};
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::str;

use anyhow::Context;
use anyhow::Result;
use log::info;
use log::warn;

use crate::hiberutil::checked_command;
use crate::hiberutil::checked_command_output;
use crate::hiberutil::is_snapshot_active;
use crate::hiberutil::stateful_block_partition_one;

/// Define the minimum size of a block device sector.
const SECTOR_SIZE: usize = 512;
/// Define the size of an LVM extent.
const LVM_EXTENT_SIZE: u64 = 64 * 1024;

/// Get the path to the given logical volume.
pub fn lv_path(volume_group: &str, name: &str) -> PathBuf {
    PathBuf::from(format!("/dev/{}/{}", volume_group, name))
}

/// Get the volume group name for the stateful block device.
pub fn get_vg_name(blockdev: &str) -> Result<String> {
    let output = checked_command_output(Command::new("/sbin/pvs").args([
        "--noheadings",
        "-o",
        "vg_name",
        blockdev,
    ]))
    .context("Cannot run pvs to get volume group name")?;

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Determine if the given logical volume exists.
pub fn lv_exists(volume_group: &str, name: &str) -> Result<bool> {
    let volume = full_lv_name(volume_group, name);
    let output = Command::new("/sbin/lvs")
        .arg(&volume)
        .output()
        .context("Failed to get output for child process")?;
    Ok(output.status.success())
}

/// Enumerate all logical volumes in a volume group.
pub fn get_lvs(volume_group: &str) -> Result<Vec<String>> {
    let output = checked_command_output(Command::new("/sbin/lvs").args([
        "--options=name",
        "--noheadings",
        volume_group,
    ]))
    .context("Failed to LVs in volume group '{volume_group}'")?;
    let output_string = String::from_utf8_lossy(&output.stdout);
    let mut elements: Vec<String> = vec![];
    output_string.split_whitespace().for_each(|e| {
        elements.push(e.trim().to_string());
    });

    Ok(elements)
}

/// Activate a logical volume.
pub fn activate_lv(volume_group: &str, name: &str) -> Result<()> {
    if lv_path(volume_group, name).exists() {
        // LV is already active
        return Ok(());
    }

    let full_name = full_lv_name(volume_group, name);
    checked_command(Command::new("/sbin/lvchange").args(["-ay", &full_name]))
        .context("Failed to activate logical volume '{full_name}'")?;

    Ok(())
}

/// Create a new thinpool volume under the given volume group, with the
/// specified name and size.
pub fn create_thin_volume(volume_group: &str, size: u64, name: &str) -> Result<()> {
    // lvcreate --thin -V "${lv_size}b" -n "{name}" "${volume_group}/thinpool"
    let size_arg = format!("{}b", size);
    let thinpool = format!("{}/thinpool", volume_group);
    checked_command(
        Command::new("/sbin/lvcreate").args(["--thin", "-V", &size_arg, "-n", name, &thinpool]),
    )
    .context("Cannot create logical volume")
}

/// Take a newly created thin volume and ensure space is fully allocated for it
/// from the thinpool. This is destructive to the data on the volume.
pub fn thicken_thin_volume<P: AsRef<Path>>(path: P, size: u64) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .open(path.as_ref())
        .context(format!(
            "Failed to open thin disk: {}",
            path.as_ref().display()
        ))?;
    let buf = [0u8; SECTOR_SIZE];
    let skip = LVM_EXTENT_SIZE - (SECTOR_SIZE as u64);
    let mut offset = 0;

    loop {
        file.write_all(&buf).context("Failed to thicken LV")?;
        offset += LVM_EXTENT_SIZE;
        if offset >= size {
            break;
        }
        // Unwrap is fine here because LVM_EXTENT_SIZE can fit in an i64.
        file.seek(SeekFrom::Current(skip.try_into().unwrap()))
            .context(format!("Failed to seek {}/{} in LV", offset + skip, size))?;
    }

    Ok(())
}

/// Remove a logical volume.
pub fn lv_remove(volume_group: &str, name: &str) -> Result<()> {
    let volume = full_lv_name(volume_group, name);

    checked_command(Command::new("/sbin/lvremove").args(["-y", &volume]))
        .context(format!("Failed to remove logical volume '{volume}'"))
}

/// Returns the free space in the thinpool.
pub fn get_free_thinpool_space(volume_group: &str) -> Result<u64> {
    let volume = full_lv_name(volume_group, "thinpool");

    let out = checked_command_output(Command::new("/sbin/lvs").args([
        "--noheadings",
        "--units",
        "b",
        "-o",
        "lv_size,data_percent",
        &volume,
    ]))?;

    let output = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let mut split = output.split(' ');
    // strip the unit indication
    let size_s = split.next().unwrap().trim_end_matches('B');
    let percent_s = split.next().unwrap();
    let size = size_s.parse::<u64>().unwrap();
    let percent = percent_s.parse::<f64>().unwrap();
    let free_space = (size as f64 * 0.01 * (100.0 - percent)) as u64;

    Ok(free_space)
}

/// Get the data usage of a thin volume in percent.
pub fn get_thin_volume_usage_percent(volume_group: &str, name: &str) -> Result<u8> {
    let volume = full_lv_name(volume_group, name);

    let out = checked_command_output(Command::new("/sbin/lvs").args([
        "--noheadings",
        "-o",
        "data_percent",
        &volume,
    ]))?;

    let output = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let percent = output.parse::<f64>().unwrap();

    Ok(percent as u8)
}

/// Get the fully qualified name of an LV.
fn full_lv_name(volume_group: &str, name: &str) -> String {
    format!("{}/{}", volume_group, name)
}

pub struct ActivatedLogicalVolume {
    lv_arg: Option<String>,
}

impl ActivatedLogicalVolume {
    pub fn new(vg_name: &str, lv_name: &str) -> Result<Option<Self>> {
        // If it already exists, don't reactivate it.
        if fs::metadata(lv_path(vg_name, lv_name)).is_ok() {
            return Ok(None);
        }

        activate_lv(vg_name, lv_name)?;

        Ok(Some(Self {
            lv_arg: Some(full_lv_name(vg_name, lv_name)),
        }))
    }

    /// Don't deactivate the logical volume on drop.
    pub fn dont_deactivate(&mut self) {
        self.lv_arg = None;
    }
}

impl Drop for ActivatedLogicalVolume {
    fn drop(&mut self) {
        if let Some(lv_arg) = self.lv_arg.take() {
            let r = checked_command(Command::new("/sbin/lvchange").args(["-an", &lv_arg]));

            match r {
                Ok(_) => {
                    info!("Deactivated LV {}", lv_arg);
                }
                Err(e) => {
                    warn!("Failed to deactivate LV {}: {}", lv_arg, e);
                }
            }
        }
    }
}

pub fn activate_physical_lv(lv_name: &str) -> Result<Option<ActivatedLogicalVolume>> {
    if !is_snapshot_active() {
        return Ok(None);
    }

    let partition1 = stateful_block_partition_one()?;
    // Assume that a failure to get the VG name indicates a non-LVM system.
    let vg_name = match get_vg_name(&partition1) {
        Ok(vg) => vg,
        Err(_) => {
            return Ok(None);
        }
    };

    ActivatedLogicalVolume::new(&vg_name, lv_name)
}
