// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process,
};

use anyhow::{Context, Error};

use crate::lsblk::{get_lsblk_devices, LsBlkDevice};
use crate::util::get_command_output;

/// Find device path for the disk containing the root filesystem.
///
/// The return value is a string in /dev, for example "/dev/sda".
fn get_root_disk_device_path() -> Result<PathBuf, Error> {
    let mut command = process::Command::new("rootdev");
    command.args(["-s", "-d"]);
    let output = get_command_output(command)?;
    let output = String::from_utf8(output)?;
    let trimmed = output.trim();
    Ok(Path::new(trimmed).into())
}

/// Information about a disk device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Disk {
    /// Absolute disk path, e.g. "/dev/sda".
    pub device_path: PathBuf,

    /// Whether the disk is removable. This is not completely
    /// reliable, for example USB SSDs may not show as removable.
    pub is_removable: bool,

    /// Whether this disk is what the OS is running from.
    pub is_root: bool,

    /// Size of the disk in bytes.
    pub size_in_bytes: u64,
}

/// Get information about all disk devices.
pub fn get_disks() -> Result<Vec<Disk>, Error> {
    let devices = get_lsblk_devices(None).context("failed to get block devices")?;

    let root_disk_kname =
        get_root_disk_device_path().context("failed to get the root disk's path")?;

    let mut disks = Vec::new();
    for device in devices {
        if device.device_type != "disk" {
            continue;
        }
        disks.push(Disk {
            device_path: Path::new(&device.name).into(),
            is_removable: device.is_removable,
            is_root: Path::new(&device.kernel_name) == root_disk_kname,
            size_in_bytes: device.size_in_bytes,
        });
    }
    Ok(disks)
}

/// Classification of a disk based on its partition layout.
#[derive(Debug, Eq, PartialEq)]
pub enum DiskLayout {
    /// Disk doesn't have CrOS on it.
    NotCros,

    /// Disk contains CrOS in the USB layout (the ROOT-B partition is
    /// a stub).
    UsbInstaller,

    /// CrOS is installed to this disk.
    Installed,
}

/// Classify a disk using the lsblk output for a single disk.
///
/// This checks for ROOT-A and ROOT-B partitions; if they don't both
/// exist, it's not a CrOS disk.
///
/// The installer is built with the "usb" disk_layout. To save space,
/// that layout uses a small (2MiB) ROOT-B. When installed, the ROOT-A
/// and ROOT-B sizes must be identical for the updater to
/// function. So, if the size of ROOT-A and ROOT-B are not identical,
/// this is an installer disk.
fn classify_disk_layout(devices: &[LsBlkDevice]) -> DiskLayout {
    let mut root_a = None;
    let mut root_b = None;

    // Find ROOT-A and ROOT-B partitions. If they don't both exist,
    // this is not a CrOS disk at all.
    for device in devices {
        let num = device.partition_number();

        // ROOT-A is partition number 3.
        if num == Some(3) {
            root_a = Some(device);
        }
        // ROOT-B is partition number 5.
        if num == Some(5) {
            root_b = Some(device);
        }
    }

    if let (Some(root_a), Some(root_b)) = (root_a, root_b) {
        if root_a.size_in_bytes == root_b.size_in_bytes {
            DiskLayout::Installed
        } else {
            DiskLayout::UsbInstaller
        }
    } else {
        DiskLayout::NotCros
    }
}

/// Get a disk partition device path.
///
/// This handles inserting a 'p' before the number if needed.
pub fn get_partition_device(disk_device: &Path, num: u32) -> PathBuf {
    let mut buf = disk_device.as_os_str().to_os_string();

    // If the disk path ends in a number, e.g. "/dev/nvme0n1", append
    // a "p" before the partition number.
    if let Some(byte) = buf.as_bytes().last() {
        if byte.is_ascii_digit() {
            buf.push("p");
        }
    }

    buf.push(num.to_string());

    PathBuf::from(buf)
}

/// Check if the root device is an installer.
pub fn is_running_from_installer() -> Result<bool, Error> {
    // Inspect only partitions on the root device. This avoids having
    // lsblk try to touch devices that might be slow to read.
    let root_dev = get_root_disk_device_path().context("failed to get root device")?;

    let devices = get_lsblk_devices(Some(&root_dev)).context("failed to get devices with lsblk")?;

    Ok(classify_disk_layout(&devices) == DiskLayout::UsbInstaller)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mkdev(name: &str, size_in_bytes: u64) -> LsBlkDevice {
        LsBlkDevice {
            kernel_name: name.into(),
            name: name.into(),
            is_removable: false,
            size_in_bytes,
            device_type: "part".into(),
        }
    }

    #[test]
    fn test_classify_disk_layout() {
        let root_a = mkdev("/dev/sda3", 123);
        let root_b = mkdev("/dev/sda5", 123);
        let root_c = mkdev("/dev/sda7", 123);
        let root_b_small = mkdev("/dev/sda5", 11);

        assert_eq!(classify_disk_layout(&[root_a.clone()]), DiskLayout::NotCros);
        assert_eq!(classify_disk_layout(&[root_b.clone()]), DiskLayout::NotCros);
        assert_eq!(
            classify_disk_layout(&[root_a.clone(), root_c]),
            DiskLayout::NotCros
        );
        assert_eq!(
            classify_disk_layout(&[root_a.clone(), root_b]),
            DiskLayout::Installed
        );
        assert_eq!(
            classify_disk_layout(&[root_a, root_b_small]),
            DiskLayout::UsbInstaller
        );
    }
}
