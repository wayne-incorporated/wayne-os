// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::path::Path;
use std::process;

use anyhow::Error;
use serde::Deserialize;

use crate::util::get_command_output;

/// Struct for deserializing the JSON output of `lsblk`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct LsBlkDevice {
    /// Device name.
    ///
    /// This is a full path because lsblk is run with "--paths".
    pub name: String,

    /// Internal kernel device name.
    #[serde(rename = "kname")]
    pub kernel_name: String,

    /// Whether the device is removable.
    ///
    /// Note that this uses the "hotplug" property rather than the "rm"
    /// property from lsblk. The hotplug property is broader, for
    /// example it includes USB HDDs.
    #[serde(rename = "hotplug")]
    pub is_removable: bool,

    /// Size in bytes.
    #[serde(rename = "size")]
    pub size_in_bytes: u64,

    /// Device type.
    #[serde(rename = "type")]
    pub device_type: String,
}

impl LsBlkDevice {
    /// Get the partition number, e.g. for `/dev/sda12` this returns 12.
    pub fn partition_number(&self) -> Option<u64> {
        if self.device_type != "part" {
            return None;
        }

        // Find the index of the last non-numeric character.
        let index = self.name.rfind(|c: char| !c.is_ascii_digit())?;

        // Parse the rest of the string past that index into a number.
        let num_part = &self.name[index + 1..];
        num_part.parse().ok()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
struct LsBlkDeviceWithChildren {
    #[serde(flatten)]
    details: LsBlkDevice,

    /// Child devices.
    #[serde(default)]
    children: Vec<LsBlkDeviceWithChildren>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct LsBlkOutput {
    #[serde(rename = "blockdevices")]
    block_devices: Vec<LsBlkDeviceWithChildren>,
}

impl LsBlkOutput {
    fn parse(input: &[u8]) -> Result<LsBlkOutput, serde_json::Error> {
        serde_json::from_slice(input)
    }

    fn flattened(self) -> Vec<LsBlkDevice> {
        let mut output = Vec::new();
        let mut stack = self.block_devices;
        while let Some(device) = stack.pop() {
            output.push(device.details);
            stack.extend(device.children);
        }
        output
    }
}

/// Capture information about block devices from lsblk.
///
/// lsblk is a convenient tool that already exists on CrOS base builds
/// and in most other linux distributions. Using the "--json" flag
/// makes the output easily parsible.
///
/// target: Block device to show information about. It will limit
/// lsblk to only return information about partitions on the target
/// device. If target is None lsblk will return information about most
/// block devices, excluding the zram device and slow devices such as
/// floppy drives.
///
/// Returns the raw output of lsblk.
fn get_lsblk_output(target_drive: Option<&Path>) -> Result<Vec<u8>, Error> {
    let mut command = process::Command::new("lsblk");
    command.args([
        // Print size in bytes
        "--bytes",
        // Select the fields to output
        "--output",
        "KNAME,NAME,HOTPLUG,SIZE,TYPE",
        // Format output as JSON
        "--json",
        // Print full device paths
        "--paths",
        // Exclude some devices by major number. See
        // https://www.kernel.org/doc/Documentation/admin-guide/devices.txt
        // for a list of major numbers.
        //
        // - Exclude floppy drives (2), as they are slow.
        // - Exclude scsi cdrom drives (11), as they are slow.
        // - Exclude zram (253), not a valid install target.
        "--exclude",
        "2,11,253",
    ]);
    if let Some(target_drive) = target_drive {
        command.arg(target_drive);
    }
    Ok(get_command_output(command)?)
}

/// Capture information about block devices from lsblk.
///
/// target: Block device to show information about. It will limit
/// lsblk to only return information about partitions on the target
/// device. If target is None lsblk will return information about most
/// block devices, excluding the zram device and slow devices such as
/// floppy drives.
///
/// Returns a flattened vector of devices.
pub fn get_lsblk_devices(target_drive: Option<&Path>) -> Result<Vec<LsBlkDevice>, Error> {
    let output = get_lsblk_output(target_drive)?;
    let parsed = LsBlkOutput::parse(&output)?;
    Ok(parsed.flattened())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partition_number() {
        let mkdev = |path: &str| LsBlkDevice {
            kernel_name: path.into(),
            name: path.into(),
            is_removable: false,
            size_in_bytes: 0,
            device_type: "part".into(),
        };

        // Valid partition devices.
        assert_eq!(mkdev("/dev/sda1").partition_number(), Some(1));
        assert_eq!(mkdev("/dev/sda12").partition_number(), Some(12));
        assert_eq!(mkdev("/dev/nvme0n1p3").partition_number(), Some(3));

        // Doesn't end in a number.
        assert_eq!(mkdev("/dev/dev").partition_number(), None);

        // Not a partition-type device.
        let mut dev = mkdev("/dev/sda1");
        dev.device_type = "disk".into();
        assert_eq!(dev.partition_number(), None);
    }

    fn mkdev(
        kname: &str,
        name: &str,
        is_removable: bool,
        size_in_bytes: u64,
        dtype: &str,
    ) -> LsBlkDevice {
        LsBlkDevice {
            kernel_name: kname.into(),
            name: name.into(),
            is_removable,
            size_in_bytes,
            device_type: dtype.into(),
        }
    }

    #[test]
    fn test_lsblk_deserialization() {
        // This test input was generated by running this command in a VM:
        //
        //     lsblk --bytes --output KNAME,NAME,HOTPLUG,SIZE,TYPE \
        //         --json --paths --exclude 2,11,253
        let input = include_bytes!("test_lsblk_output.json");

        #[rustfmt::skip]
        let expected = vec![
            mkdev("/dev/sda", "/dev/sda", false, 6939566592, "disk"),
            mkdev("/dev/sda12", "/dev/sda12", false, 67108864, "part"),
            mkdev("/dev/sda11", "/dev/sda11", false, 512, "part"),
            mkdev("/dev/sda10", "/dev/sda10", false, 512, "part"),
            mkdev("/dev/sda9", "/dev/sda9", false, 512, "part"),
            mkdev("/dev/sda8", "/dev/sda8", false, 16777216, "part"),
            mkdev("/dev/sda7", "/dev/sda7", false, 512, "part"),
            mkdev("/dev/sda6", "/dev/sda6", false, 512, "part"),
            mkdev("/dev/sda5", "/dev/sda5", false, 2097152, "part"),
            mkdev("/dev/sda4", "/dev/sda4", false, 16777216, "part"),
            mkdev("/dev/sda3", "/dev/sda3", false, 2516582400, "part"),
            mkdev("/dev/sda2", "/dev/sda2", false, 16777216, "part"),
            mkdev("/dev/sda1", "/dev/sda1", false, 4301324800, "part"),
            mkdev("/dev/loop4", "/dev/loop4", false, 6475776, "loop"),
            mkdev("/dev/loop3", "/dev/loop3", false, 9670656, "loop"),
            mkdev("/dev/loop2", "/dev/loop2", false, 102133760, "loop"),
            mkdev("/dev/loop1", "/dev/loop1", false, 1243103232, "loop"),
            mkdev("/dev/dm-1", "/dev/mapper/encstateful", false, 1243103232, "dm"),
            mkdev("/dev/loop0", "/dev/loop0", false, 4096, "loop"),
        ];

        let output = LsBlkOutput::parse(input).unwrap();
        assert_eq!(output.flattened(), expected);
    }
}
