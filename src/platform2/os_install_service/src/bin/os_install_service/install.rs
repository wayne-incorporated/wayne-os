// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::install_logger;
use log::{error, info};
use os_install_service::disk::{self, Disk};
use os_install_service::mount::Mount;
use os_install_service::util;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not running from installer")]
    NotRunningFromInstaller,

    #[error("failed to enumerate disks: {0}")]
    DiskEnumerationFailed(anyhow::Error),

    #[error("no valid destination disk found")]
    NoDestinationDeviceFound,

    #[error("failed to run process: {0}")]
    Process(util::ProcessError),
}

pub type Result = std::result::Result<(), Error>;

/// Convert GiB to bytes.
fn gibibytes_to_bytes(num_gibibytes: u64) -> u64 {
    num_gibibytes * 1024 * 1024 * 1024
}

/// Choose the "best" device to install to.
///
/// - Don't install to the disk that the installer is on
///
/// - Don't install to a disk that is too small
///
/// - Prefer to install to a non-removable disk
///
/// - Secondarily prefer larger disks over smaller disks
///
/// Return value is a full device path, for example "/dev/sdd".
fn choose_destination_device_path(mut disks: Vec<Disk>) -> Option<PathBuf> {
    // Estimate of the minimum required disk size. This doesn't need
    // to be especially precise.
    let minimum_size_in_bytes = gibibytes_to_bytes(14);

    // Start by getting all disks and then progressively filter and
    // sort (clarity favored over efficiency here since the list
    // should be very small)
    info!("found {} disks", disks.len());

    // Filter out the current root disk (the disk containing the
    // partition mounted at "/") as that would be installing with
    // src == dst
    disks.retain(|dsk| !dsk.is_root);
    info!("filtering out root disk, {} remaining", disks.len());

    // Filter out any disks that are too small (although as noted
    // above we're a bit low-resolution on exactly what is too small)
    disks.retain(|dsk| dsk.size_in_bytes >= minimum_size_in_bytes);
    info!(
        "filtering out disks smaller than {} bytes, {} remaining",
        minimum_size_in_bytes,
        disks.len()
    );

    // Sort disks from largest to smallest.
    disks.sort_unstable_by_key(|dsk| dsk.size_in_bytes);
    disks.reverse();

    // Prefer to install to a non-removable disk. This is not a hard
    // requirement.
    let best_disk = match disks.iter().find(|dsk| !dsk.is_removable) {
        Some(disk) => Some(disk),
        None => disks.first(),
    }?;

    info!("best disk: {:?}", best_disk);
    Some(best_disk.device_path.clone())
}

/// Set up the disk with an empty GPT table.
fn reformat(dest: &Path) {
    let mut cmd = Command::new("/usr/sbin/parted");
    cmd.arg("--script").arg(dest).args(["mklabel", "gpt"]);

    if let Err(err) = util::get_command_output(cmd) {
        // Log the error but otherwise ignore it.
        error!("failed to reformat disk: {}", err);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BootMode {
    Legacy,
    Uefi,
}

impl BootMode {
    /// Get whether the machine was booted in UEFI mode or not.
    fn from_kernel_cmdline() -> BootMode {
        let cmdline = match fs::read_to_string("/proc/cmdline") {
            Ok(cmdline) => cmdline,
            Err(err) => {
                // Default to legacy mode.
                error!("failed to read kernel command line: {}", err);
                return BootMode::Legacy;
            }
        };
        if cmdline.split_whitespace().any(|e| e == "cros_efi") {
            BootMode::Uefi
        } else {
            BootMode::Legacy
        }
    }
}

/// Run chromeos-install with appropriate arguments.
fn run_chromeos_install(dest: &Path, boot_mode: BootMode) -> Result {
    let mut cmd = Command::new("/usr/sbin/chromeos-install");
    // Destination device.
    cmd.arg("--dst").arg(dest);
    // Don't ask questions.
    cmd.arg("--yes");
    // Don't check if the destination drive is removable.
    // `os_install_service` has already taken the
    // "removableness" of devices into account when choosing the
    // destination drive, and we don't want `chromeos-install` to
    // contest that decision and fail with an error.
    cmd.arg("--skip_dst_removable");

    if boot_mode == BootMode::Uefi {
        cmd.args(["--target_bios", "efi"]);
    }

    util::run_command_log_output(cmd).map_err(Error::Process)?;

    Ok(())
}

/// Copy the install log onto the target system.
///
/// This makes it persistent and available for future QA on the
/// installed system.
///
/// This only should occur if the target's stateful partition was
/// created properly.
fn save_install_log(dest: &Path) -> anyhow::Result<()> {
    // Mount the installed stateful partition.
    let stateful_partition_num = 1;
    let dest_stateful_partition = disk::get_partition_device(dest, stateful_partition_num);
    let stateful_partition_mount = Mount::mount_ext4(&dest_stateful_partition)?;
    // Get the instance log and write it to the stateful partition.
    let instance_log = install_logger::read_file_log();
    let log_dst = stateful_partition_mount
        .mount_point
        .path()
        .join("flex-install.log");
    info!("writing install log to {}", log_dst.display());
    fs::write(log_dst, instance_log)?;
    Ok(())
}

fn install_to_device(dest: &Path) -> Result {
    let boot_mode = BootMode::from_kernel_cmdline();

    run_chromeos_install(dest, boot_mode)?;

    Ok(())
}

pub fn install() -> Result {
    // Check if running from installer. This shouldn't really be
    // needed since the install service should only run from the
    // installer, but check anyway just to be safe.
    match disk::is_running_from_installer() {
        Ok(true) => {}
        Ok(false) => {
            error!("refusing to install when not running from installer");
            return Err(Error::NotRunningFromInstaller);
        }
        Err(err) => {
            error!("is_running_from_installer failed: {:#}", err);
            return Err(Error::NotRunningFromInstaller);
        }
    }

    let disks = disk::get_disks().map_err(Error::DiskEnumerationFailed)?;

    // Pick destination device
    let dest = choose_destination_device_path(disks).ok_or(Error::NoDestinationDeviceFound)?;

    if let Err(err) = install_to_device(&dest) {
        error!("installation failed: {}", err);

        // If install fails, reset the GPT table. This ensures that
        // the user won't accidentally boot into a not-quite-completed
        // installation (e.g. if the failure is during postinstall).
        reformat(&dest);

        return Err(err);
    }

    // Save off the log on a successful install.
    if let Err(err) = save_install_log(&dest) {
        error!("failed to save install log: {:?}", err);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gibibytes_to_bytes() {
        assert_eq!(gibibytes_to_bytes(4), 4294967296)
    }

    #[test]
    fn test_choose_destination_device_path() {
        // One valid target.
        assert_eq!(
            choose_destination_device_path(vec![Disk {
                device_path: PathBuf::from("/dev/sda"),
                is_removable: false,
                is_root: false,
                size_in_bytes: gibibytes_to_bytes(32),
            }]),
            Some(PathBuf::from("/dev/sda"))
        );

        // Two valid targets, the bigger one should be chosen.
        assert_eq!(
            choose_destination_device_path(vec![
                Disk {
                    device_path: PathBuf::from("/dev/sda"),
                    is_removable: false,
                    is_root: false,
                    size_in_bytes: gibibytes_to_bytes(1),
                },
                Disk {
                    device_path: PathBuf::from("/dev/sdb"),
                    is_removable: false,
                    is_root: false,
                    size_in_bytes: gibibytes_to_bytes(32),
                }
            ]),
            Some(PathBuf::from("/dev/sdb"))
        );

        // One valid target: non-removable is preferred but not a hard
        // requirement.
        assert_eq!(
            choose_destination_device_path(vec![Disk {
                device_path: PathBuf::from("/dev/sda"),
                is_removable: true,
                is_root: false,
                size_in_bytes: gibibytes_to_bytes(32),
            }]),
            Some(PathBuf::from("/dev/sda"))
        );

        // No valid targets: no disks at all.
        assert_eq!(choose_destination_device_path(vec![]), None);

        // No valid targets: can't install to the same disk as the
        // installer.
        assert_eq!(
            choose_destination_device_path(vec![Disk {
                device_path: PathBuf::from("/dev/sda"),
                is_removable: false,
                is_root: true,
                size_in_bytes: gibibytes_to_bytes(32),
            }]),
            None,
        );

        // No valid targets: the non-installer disk is too small.
        assert_eq!(
            choose_destination_device_path(vec![
                Disk {
                    device_path: PathBuf::from("/dev/sda"),
                    is_removable: false,
                    is_root: true,
                    size_in_bytes: gibibytes_to_bytes(32),
                },
                Disk {
                    device_path: PathBuf::from("/dev/sdb"),
                    is_removable: false,
                    is_root: false,
                    size_in_bytes: gibibytes_to_bytes(1)
                }
            ]),
            None,
        );
    }
}
