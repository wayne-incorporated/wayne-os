// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements volume and disk management.
// TODO(b/241434344): Things farming out to external processes should be
// implemented in a common helper library instead.

use anyhow::Context;
use anyhow::Result;
use log::debug;
use log::error;
use log::info;
use log::warn;

use std::ffi::OsStr;
use std::fs::create_dir;
use std::fs::read_dir;
use std::fs::read_link;
use std::fs::remove_file;
use std::fs::OpenOptions;
use std::io::IoSlice;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use crate::cookie::set_hibernate_cookie;
use crate::cookie::HibernateCookieValue;
use crate::device_mapper::DeviceMapper;
use crate::files::HIBERMETA_DIR;
use crate::hiberutil::checked_command;
use crate::hiberutil::checked_command_output;
use crate::hiberutil::emergency_reboot;
use crate::hiberutil::get_device_mounted_at_dir;
use crate::hiberutil::get_page_size;
use crate::hiberutil::get_ram_size;
use crate::hiberutil::keyctl_add_key;
use crate::hiberutil::keyctl_remove_key;
use crate::hiberutil::log_io_duration;
use crate::hiberutil::mount_filesystem;
use crate::hiberutil::stateful_block_partition_one;
use crate::hiberutil::unmount_filesystem;
use crate::hiberutil::HibernateError;
use crate::lvm::activate_lv;
use crate::lvm::create_thin_volume;
use crate::lvm::get_free_thinpool_space;
use crate::lvm::get_lvs;
use crate::lvm::get_thin_volume_usage_percent;
use crate::lvm::get_vg_name;
use crate::lvm::lv_exists;
use crate::lvm::lv_path;
use crate::lvm::lv_remove;
use crate::lvm::thicken_thin_volume;
use crate::lvm::ActivatedLogicalVolume;
use crate::metrics::METRICS_LOGGER;
use crate::snapwatch::DmSnapshotSpaceMonitor;

/// Define the name of the hibernate logical volume.
const HIBERMETA_VOLUME_NAME: &str = "hibermeta";
const HIBERIMAGE_VOLUME_NAME: &str = "hiberimage";
const HIBERINTEGRITY_VOLUME_NAME: &str = "hiberintegrity";
/// Define the name of the thinpool logical volume.
pub const THINPOOL_NAME: &str = "thinpool";

/// Define the known path to the dmsetup utility.
const DMSETUP_PATH: &str = "/sbin/dmsetup";
/// Define the path to the losetup utility.
const LOSETUP_PATH: &str = "/sbin/losetup";
const MKFS_EXT2_PATH: &str = "/sbin/mkfs.ext2";
/// The path of the e2fsck utility.
const E2FSCK_PATH: &str = "/sbin/e2fsck";

const SIZE_1K: u64 = 1024;
const SIZE_4K: u64 = 4 * SIZE_1K;
const SIZE_1M: u64 = SIZE_1K * SIZE_1K;
const SIZE_1G: u64 = SIZE_1K * SIZE_1M;

/// Define the number of sectors per dm-snapshot chunk.
const DM_SNAPSHOT_CHUNK_SIZE: usize = 8;

/// Define the list of logical volumes known to not need a snapshot.
const NO_SNAPSHOT_LVS: [&str; 6] = [
    "cryptohome-",
    // DLC LVs are read-only, therefore they don't need snapshots.
    "dlc_",
    HIBERIMAGE_VOLUME_NAME,
    HIBERINTEGRITY_VOLUME_NAME,
    HIBERMETA_VOLUME_NAME,
    THINPOOL_NAME,
];

/// Define the size of a volume snapshot.
const SNAPSHOT_SIZE: u64 = 512 * SIZE_1M;

/// Define the size of the unencrypted snapshot, which is a little bit bigger.
const UNENCRYPTED_SNAPSHOT_SIZE: u64 = SIZE_1G;

/// Define the number of milliseconds to wait for all dm-snapshot merges to
/// complete.
const MERGE_TIMEOUT_MS: u32 = 20 * 60 * 1000;

/// AES-GCM uses a fixed 12 byte IV. The other 12 bytes are auth tag.
const AES_GCM_INTEGRITY_BYTES_PER_BLOCK: u64 = 12 + 12;

/// Logical disk sector size (512 bytes).
const SECTOR_SIZE: u64 = 512;

/// The pending stateful merge is an object that when dropped will ask the
/// volume manager to merge the stateful snapshots.
pub struct PendingStatefulMerge<'a> {
    pub volume_manager: &'a mut VolumeManager,
    monitors: Vec<DmSnapshotSpaceMonitor>,
}

impl<'a> PendingStatefulMerge<'a> {
    pub fn new(volume_manager: &'a mut VolumeManager) -> Result<Self> {
        let monitors = volume_manager.monitor_stateful_snapshots()?;
        Ok(Self {
            volume_manager,
            monitors,
        })
    }
}

impl Drop for PendingStatefulMerge<'_> {
    fn drop(&mut self) {
        if let Err(e) = self
            .volume_manager
            .merge_stateful_snapshots(&mut self.monitors)
        {
            error!("Attempting to merge stateful snapshots returned: {:?}", e);
            // If we failed to merge the snapshots, the system is in a bad way.
            // Reboot to try and recover.
            emergency_reboot("Failed to merge stateful snapshots");
        }
    }
}

/// Result of a file system check.
enum FileSystemStatus {
    // These values are persisted to logs. Entries should not be renumbered and
    // numeric values should never be reused.
    Clean = 0,
    HasErrors = 1,
    Count = 2,
}

enum ThinpoolMode {
    ReadOnly,
    ReadWrite,
}

#[derive(Copy, Clone)]
enum HibernateVolume {
    Integrity,
    Image,
    Meta,
}

struct VolumeProperties {
    name: String,
    size: u64,
    thicken_at_creation: bool,
}

pub struct VolumeManager {
    vg_name: String,
}

impl VolumeManager {
    pub const HIBERIMAGE: &str = "hiberimage";
    const HIBERIMAGE_INTEGRITY: &str = "hiberimage_integrity";
    const HIBERINTEGRITY: &str = "hiberintegrity";

    /// Create a new VolumeManager.
    pub fn new() -> Result<Self> {
        let partition1 = stateful_block_partition_one()?;
        let vg_name = get_vg_name(&partition1)?;
        Ok(Self { vg_name })
    }

    /// Activate the thinpool in RO mode.
    pub fn activate_thinpool_ro(&mut self) -> Result<()> {
        activate_lv(&self.vg_name, THINPOOL_NAME).context("Failed to activate thinpool")?;
        self.set_thinpool_mode(ThinpoolMode::ReadOnly)
            .context("Failed to make thin-pool RO")
    }

    /// Change the RO thinpool to be RW.
    pub fn make_thinpool_rw(&mut self) -> Result<()> {
        self.set_thinpool_mode(ThinpoolMode::ReadWrite)
            .context("Failed to make thin-pool RW")
    }

    /// Set up the hibermeta logical volume.
    pub fn setup_hibermeta_lv(&mut self, create: bool) -> Result<ActiveMount> {
        if get_device_mounted_at_dir(HIBERMETA_DIR).is_ok() {
            return Err(HibernateError::HibernateVolumeError())
                .context(format!("{HIBERMETA_DIR} is already mounted"));
        }

        if lv_exists(&self.vg_name, HIBERMETA_VOLUME_NAME)? {
            info!("Activating hibermeta");
            activate_lv(&self.vg_name, HIBERMETA_VOLUME_NAME)?;

            let bdev_path = lv_path(&self.vg_name, HIBERMETA_VOLUME_NAME);
            let bdev_path = bdev_path.to_string_lossy();
            if let Err(e) = checked_command(Command::new(E2FSCK_PATH).args(["-p", &bdev_path])) {
                // fsck failed => re-format 'hibermeta'
                warn!(
                    "File system check for 'hibermeta' volume {} failed: {}",
                    bdev_path, e
                );

                log_file_system_status(FileSystemStatus::HasErrors);

                info!("Formatting 'hibermeta' volume {}", bdev_path);
                // Use -K to tell mkfs not to run a discard on the block device, which
                // would destroy all the nice thickening done at creation time.
                checked_command_output(Command::new(MKFS_EXT2_PATH).args(["-K", &bdev_path]))
                    .context("Cannot format 'hibermeta' volume")?;
            } else {
                log_file_system_status(FileSystemStatus::Clean);
            }
        } else if create {
            self.create_hibermeta_lv()?;
        } else {
            return Err(HibernateError::HibernateVolumeError()).context("Missing hibernate volume");
        }

        self.mount_hibermeta()
    }

    pub fn setup_hiberimage(
        &self,
        hiberintegrity_key: &[u8],
        hiberimage_key: &[u8],
        format_integrity_dev: bool,
    ) -> Result<()> {
        self.create_or_activate_lv(HibernateVolume::Image)?;
        self.create_or_activate_lv(HibernateVolume::Integrity)?;

        self.create_hiberintegrity_dm_dev(hiberintegrity_key)
            .context(format!(
                "Failed to create '{}' DM device",
                Self::HIBERINTEGRITY
            ))?;
        self.create_hiberimage_integrity_dm_dev(format_integrity_dev)
            .context(format!(
                "Failed to create '{}' DM device",
                Self::HIBERIMAGE_INTEGRITY
            ))?;
        self.create_hiberimage_dm_dev(hiberimage_key)
    }

    pub fn teardown_hiberimage(&self) -> Result<()> {
        if DeviceMapper::device_exists(Self::HIBERIMAGE) {
            info!("Tearing down hiberimage");
        }

        for dev in [
            Self::HIBERIMAGE,
            Self::HIBERIMAGE_INTEGRITY,
            Self::HIBERINTEGRITY,
        ] {
            if DeviceMapper::device_exists(dev) {
                DeviceMapper::remove_device(dev)?;
            }
        }

        for lv in [Self::HIBERIMAGE, Self::HIBERINTEGRITY] {
            if lv_exists(&self.vg_name, lv)? {
                lv_remove(&self.vg_name, lv)?;
            }
        }

        Ok(())
    }

    // Thicken the hiberimage LV. Needs to be called before the hibernate
    // image is written.
    pub fn thicken_hiberimage(&self) -> Result<()> {
        let size = Self::get_volume_size(HibernateVolume::Image);
        let path = lv_path(&self.vg_name, Self::HIBERIMAGE);

        thicken_thin_volume(path, size)
            .context(format!("Failed to thicken '{}' volume", Self::HIBERIMAGE))
    }

    // Lock down the DM devices that comprise the hiberimage. This involves
    // setting the UUID of the DM devices to 'dm_locked-<name>', which
    // indicates the kernel that certain operations are not permitted on
    // this DM device. As an additional layer of protection the device
    // nodes of the DM devices are removed.
    pub fn lockdown_hiberimage(&self) -> Result<()> {
        for name in [
            Self::HIBERIMAGE,
            Self::HIBERINTEGRITY,
            Self::HIBERIMAGE_INTEGRITY,
        ] {
            let uuid = format!("dm_locked-{name}");

            DeviceMapper::set_device_uuid(name, &uuid)?;

            // Delete the device node and the symlink in /dev/mapper
            for path in [
                DeviceMapper::device_path(name)?,
                PathBuf::from(format!("/dev/mapper/{name}")),
            ] {
                remove_file(&path).context(format!("Failed to unlink {}", path.display()))?;
            }
        }

        Ok(())
    }

    /// Mount the hibermeta LV if it isn't already mounted
    pub fn mount_hibermeta(&mut self) -> Result<ActiveMount> {
        if get_device_mounted_at_dir(HIBERMETA_DIR).is_ok() {
            return Err(HibernateError::HibernateVolumeError())
                .context(format!("{HIBERMETA_DIR} is already mounted"));
        }

        let hibermeta_dir = Path::new(HIBERMETA_DIR);
        let path = lv_path(&self.vg_name, HIBERMETA_VOLUME_NAME);
        mount_filesystem(path.as_path(), hibermeta_dir, "ext2", 0, "")?;

        Ok(ActiveMount::new(hibermeta_dir))
    }

    /// Returns the free space in the thinpool.
    pub fn get_free_thinpool_space(&self) -> Result<u64> {
        get_free_thinpool_space(&self.vg_name)
    }

    /// Check whether the 'hiberimage' DM device exists.
    pub fn hiberimage_exists(&self) -> bool {
        DeviceMapper::device_exists(Self::HIBERIMAGE)
    }

    pub fn is_hiberimage_thickened(&self) -> Result<bool> {
        let usage_percent = get_thin_volume_usage_percent(&self.vg_name, HIBERIMAGE_VOLUME_NAME)?;

        Ok(usage_percent >= 99)
    }

    /// Create the hibermeta volume.
    fn create_hibermeta_lv(&mut self) -> Result<()> {
        self.create_lv(HibernateVolume::Meta)?;

        let path = lv_path(&self.vg_name, HIBERMETA_VOLUME_NAME);
        // Use -K to tell mkfs not to run a discard on the block device, which
        // would destroy all the nice thickening done above.
        checked_command_output(Command::new(MKFS_EXT2_PATH).arg("-K").arg(path))
            .context("Cannot format hibermeta volume")?;

        Ok(())
    }

    /// Create snapshot storage files for all active LVs.
    fn create_dm_snapshot_cow_files(&self) -> Result<()> {
        let snapshot_dir = snapshot_dir();
        if !snapshot_dir.exists() {
            debug!("Creating snapshot directory");
            create_dir(&snapshot_dir).context("Failed to create snapshot directory")?;
        }

        let active_lvs = get_lvs(&self.vg_name)?;
        let zeroes = [0u8; SIZE_4K as usize];
        for lv_name in &active_lvs {
            // Skip certain LVs.
            let mut skip_lv = false;
            for skipped in NO_SNAPSHOT_LVS {
                if lv_name.starts_with(skipped) {
                    skip_lv = true;
                    break;
                }
            }

            if skip_lv {
                continue;
            }

            let snapshot_size = if lv_name == "unencrypted" {
                UNENCRYPTED_SNAPSHOT_SIZE
            } else {
                SNAPSHOT_SIZE
            };

            let path = snapshot_file_path(lv_name);
            if path.exists() {
                info!("Reinitializing snapshot for LV: {}", lv_name);
            } else {
                info!("Creating snapshot for LV: {}", lv_name);
            }

            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .open(&path)
                .context(format!("Failed to open snapshot file: {}", path.display()))?;

            // Clear out the snapshot if it exists for some reason so we don't
            // accidentally attach stale data.
            file.write_all(&zeroes)?;
            file.set_len(snapshot_size)?;
        }

        for snap_name in Self::get_snapshot_file_names()? {
            if !active_lvs.contains(&snap_name.to_string()) {
                info!("Removing old snapshot: {}", &snap_name);
                delete_snapshot(&snap_name).context("Failed to delete old snapshot")?;
            }
        }

        Ok(())
    }

    /// Set up dm-snapshots for the stateful LVs.
    pub fn setup_stateful_snapshots(&mut self) -> Result<()> {
        self.create_dm_snapshot_cow_files()?;

        for lv_name in Self::get_snapshot_file_names()? {
            self.setup_snapshot(&lv_name)?;
        }

        Ok(())
    }

    /// Set up a dm-snapshot for a single named LV.
    fn setup_snapshot(&mut self, name: &str) -> Result<()> {
        info!("Setting up snapshot for LV: {}", name);
        let path = snapshot_file_path(name);
        let loop_path = Self::setup_loop_device(path)?;
        let activated_lv = ActivatedLogicalVolume::new(&self.vg_name, name)
            .context(format!("Failed to activate LV: {}", name))?;
        let origin_lv = read_link(lv_path(&self.vg_name, name))?;
        Self::setup_dm_snapshot(origin_lv, loop_path, name, DM_SNAPSHOT_CHUNK_SIZE)
            .context(format!("Failed to setup dm-snapshot for {}", name))?;

        // The snapshot is set up, don't try to deactivate the LV underneath it.
        if let Some(mut lv) = activated_lv {
            lv.dont_deactivate();
        }

        Ok(())
    }

    /// Set up a loop device for the given file and return the path to it.
    fn setup_loop_device<P: AsRef<OsStr>>(file_path: P) -> Result<PathBuf> {
        let output = checked_command_output(Command::new(LOSETUP_PATH).args([
            "--show",
            "-f",
            &file_path.as_ref().to_string_lossy(),
        ]))
        .context("Cannot create loop device")?;

        Ok(PathBuf::from(
            String::from_utf8_lossy(&output.stdout).trim(),
        ))
    }

    /// Set up a dm-snapshot origin and snapshot. Example:
    ///   dmsetup create stateful-origin --table \
    ///     "0 ${STATE_SIZE} snapshot-origin ${STATE_DEV}"
    ///   dmsetup create stateful-rw --table \
    ///     "0 ${STATE_SIZE} snapshot ${STATE_DEV} ${COW_LOOP} P 8"
    fn setup_dm_snapshot<P: AsRef<OsStr>>(
        origin: P,
        snapshot: P,
        name: &str,
        chunk_size: usize,
    ) -> Result<()> {
        let size_sectors = get_blockdev_size(Path::new(&origin))? / SECTOR_SIZE;
        let origin_string = origin.as_ref().to_string_lossy();
        let snapshot_string = snapshot.as_ref().to_string_lossy();
        let origin_table = format!("0 {} snapshot-origin {}", size_sectors, &origin_string);
        debug!("Creating snapshot origin: {}", &origin_table);
        DeviceMapper::create_device(&format!("{name}-origin"), &origin_table)
            .context(format!("Cannot setup snapshot-origin for {}", name))?;

        let snapshot_table = format!(
            "0 {} snapshot {} {} P {}",
            size_sectors, &origin_string, &snapshot_string, chunk_size
        );
        debug!("Creating snapshot table: {}", &snapshot_table);
        DeviceMapper::create_device(&format!("{name}-rw"), &snapshot_table)
            .context(format!("Cannot setup dm-snapshot for {}", name))?;

        Ok(())
    }

    /// Create monitor threads for each dm-snapshot set up by hiberman that
    /// triggers a resume abort if the snapshot gets too full.
    pub fn monitor_stateful_snapshots(&self) -> Result<Vec<DmSnapshotSpaceMonitor>> {
        let mut monitors = vec![];
        for name in Self::get_snapshot_file_names()? {
            let snapshot_name = format!("{}-rw", name);
            // Only monitor snapshots that are actually set up, which
            // resume-init may not set up if the cookie was set to EmergencyReboot.
            if get_dm_status(&snapshot_name).is_ok() {
                monitors.push(DmSnapshotSpaceMonitor::new(&snapshot_name)?);
            }
        }

        Ok(monitors)
    }

    /// Kick off merges of all dm-snapshots managed by hiberman, and wait for
    /// them to complete. Takes in a vector of space monitor threads which will
    /// be stopped once the merge has commenced.
    pub fn merge_stateful_snapshots(
        &mut self,
        monitors: &mut [DmSnapshotSpaceMonitor],
    ) -> Result<()> {
        if !snapshot_dir().exists() {
            info!("No snapshot directory, skipping merges");
            return Ok(());
        }

        // First make the thinpool writable. If this fails, the merges below
        // won't work either, so don't try.
        self.make_thinpool_rw()
            .context("Failed to make thinpool RW")?;
        let mut snapshots = vec![];
        let mut bad_snapshots = vec![];
        let mut result = Ok(());
        for name in Self::get_snapshot_file_names()? {
            let snapshot = match DmSnapshotMerge::new(&name) {
                Ok(o) => match o {
                    Some(s) => s,
                    None => {
                        continue;
                    }
                },
                Err(e) => {
                    // Upon failure to kick off the merge for a snapshot, record
                    // it, but still try to complete the merges for the other
                    // snapshots.
                    error!("Failed to setup snapshot merge for {}: {:?}", name, e);
                    result = Err(e);
                    bad_snapshots.push(name.to_string());
                    continue;
                }
            };

            snapshots.push(snapshot);
        }

        // With the merge underway, the snapshots won't get any fuller. Stop the
        // monitor threads since they're no longer needed, and would start
        // logging errors if the snapshot devices were deleted out from under
        // them.
        debug!("Stopping monitor threads");
        for monitor in monitors.iter_mut() {
            monitor.stop();
        }

        // Wait for the merges that were successfully started to complete.
        wait_for_snapshots_merge(&mut snapshots, MERGE_TIMEOUT_MS)?;

        // Clear the hibernate cookie now that all snapshots have progressed as
        // far as they can towards completion.
        set_hibernate_cookie::<PathBuf>(None, HibernateCookieValue::NoResume)
            .context("Failed to clear the hibernate cookie")?;

        // Now delete the all snapshots.
        let mut delete_result = Ok(());
        for snapshot in snapshots {
            if let Err(e) = delete_snapshot(&snapshot.name) {
                error!("Failed to delete snapshot: {}", snapshot.name);
                delete_result = Err(e);
            }
        }

        for name in bad_snapshots {
            if let Err(e) = delete_snapshot(&name) {
                error!("Failed to delete bad snapshot: {}", name);
                delete_result = Err(e);
            }
        }

        // Return the merge setup error first, or the delete error second.
        result.and(delete_result)
    }

    /// Set the thinpool mode for the current volume group.
    fn set_thinpool_mode(&self, mode: ThinpoolMode) -> Result<()> {
        let (name, table) = Self::get_thinpool_table()?;
        let mut thinpool_config = ThinpoolConfig::new(&table)?;
        match mode {
            ThinpoolMode::ReadOnly => thinpool_config.add_option("read_only"),
            ThinpoolMode::ReadWrite => thinpool_config.remove_option("read_only"),
        }

        let new_table = thinpool_config.to_table();
        let _suspended_device = SuspendedDmDevice::new(&name);
        DeviceMapper::reload_device_table(&name, &new_table)
    }

    /// Get the thinpool volume name and table line.
    fn get_thinpool_table() -> Result<(String, String)> {
        let line = dmsetup_checked_output(Command::new(DMSETUP_PATH).args([
            "table",
            "--target",
            "thin-pool",
        ]))
        .context("Failed to get dm target line for thin-pool")?;

        let trimmed_line = line.trim();
        if trimmed_line.contains('\n') {
            return Err(HibernateError::DeviceMapperError(
                "More than one thin-pool".to_string(),
            ))
            .context("Failed to get thinpool table");
        }

        let split: Vec<&str> = trimmed_line.split(':').collect();
        if split.len() < 2 {
            return Err(HibernateError::DeviceMapperError(
                "Bad dmsetup table line".to_string(),
            ))
            .context("Failed to get thinpool table");
        }

        Ok((split[0].to_string(), split[1..].join(":")))
    }

    /// Return a list of strings describing the file names in the snapshot
    /// directory.
    fn get_snapshot_file_names() -> Result<Vec<String>> {
        let snapshot_dir = snapshot_dir();
        if !snapshot_dir.exists() {
            return Ok(vec![]);
        }

        let mut files = vec![];
        let snapshot_files = read_dir(snapshot_dir)?;
        for snap_entry in snapshot_files {
            let snap_name_entry = snap_entry?.file_name();
            files.push(snap_name_entry.to_string_lossy().to_string());
        }

        Ok(files)
    }

    /// Get the desired size of a given hibernate volume type.
    fn get_volume_size(volume_type: HibernateVolume) -> u64 {
        let hiberimage_size = get_ram_size() / 2;

        match volume_type {
            HibernateVolume::Image => hiberimage_size,

            HibernateVolume::Integrity => {
                let num_pages = hiberimage_size / get_page_size() as u64;

                // Eight 512 byte sectors are required for the superblock and eight
                // padding sectors.
                let initial_size = (8 + 8) * SECTOR_SIZE;

                roundup_mutiple(
                    initial_size + num_pages * AES_GCM_INTEGRITY_BYTES_PER_BLOCK,
                    SIZE_1M,
                )
            }

            HibernateVolume::Meta => 16 * SIZE_1M,
        }
    }

    /// Create a logical volume if it doesn't exist yet, otherwise activate it
    /// (if needed).
    fn create_or_activate_lv(&self, volume_type: HibernateVolume) -> Result<()> {
        let lv_props = Self::get_volume_properties(volume_type);

        if lv_exists(&self.vg_name, &lv_props.name)? {
            debug!("Activating '{}' volume", &lv_props.name);

            activate_lv(&self.vg_name, &lv_props.name)?;
        } else {
            self.create_lv(volume_type)?;
        }

        Ok(())
    }

    /// Create a logical volume.
    fn create_lv(&self, volume_type: HibernateVolume) -> Result<()> {
        let lv_props = Self::get_volume_properties(volume_type);

        debug!("Creating '{}' logical volume", lv_props.name);

        let start = Instant::now();

        // All space in the single volume group is allocated to a thinpool,
        // so we can't create regular LVs. Instead create a thin volume and
        // thicken it if/when needed.
        create_thin_volume(&self.vg_name, lv_props.size, &lv_props.name)
            .context(format!("Failed to create thin volume '{}'", lv_props.name))?;

        if lv_props.thicken_at_creation {
            let path = lv_path(&self.vg_name, &lv_props.name);
            thicken_thin_volume(path, lv_props.size)
                .context(format!("Failed to thicken volume '{}'", lv_props.name))?;
        }

        log_io_duration(
            &format!("Created '{}' logical volume", lv_props.name),
            lv_props.size,
            start.elapsed(),
        );

        Ok(())
    }

    /// Get the properties of a logical volume for hibernate.
    fn get_volume_properties(volume_type: HibernateVolume) -> VolumeProperties {
        let size = Self::get_volume_size(volume_type);

        match volume_type {
            HibernateVolume::Image => VolumeProperties {
                name: HIBERIMAGE_VOLUME_NAME.to_string(),
                size,
                // Postpone thickening of the large volume until hibernation is imminent.
                thicken_at_creation: false,
            },

            HibernateVolume::Integrity => VolumeProperties {
                name: HIBERINTEGRITY_VOLUME_NAME.to_string(),
                size,
                thicken_at_creation: true,
            },

            HibernateVolume::Meta => VolumeProperties {
                name: HIBERMETA_VOLUME_NAME.to_string(),
                size,
                thicken_at_creation: true,
            },
        }
    }

    /// Create the dm-crypt device 'hiberintegrity' for dm-integrity data (on top
    /// of the logical volume with the same name).
    fn create_hiberintegrity_dm_dev(&self, key_data: &[u8]) -> Result<()> {
        let key_desc = "dmcrypt:hiberintegrity";

        keyctl_add_key(key_desc, key_data)?;

        let backing_dev = lv_path(&self.vg_name, Self::HIBERINTEGRITY);
        let backing_dev_nr_sectors = get_blockdev_size(&backing_dev)? / SECTOR_SIZE;
        let table = format!(
            "0 {backing_dev_nr_sectors} crypt capi:ctr(aes)-plain64 :32:logon:{key_desc} \
                             0 {} 0 4 no_read_workqueue no_write_workqueue \
                             sector_size:{SIZE_4K} iv_large_sectors",
            backing_dev.display()
        );

        let res = DeviceMapper::create_device(Self::HIBERINTEGRITY, &table);

        // Now that the device is set up we can remove the key again from the kernel key ring.
        keyctl_remove_key(key_desc)?;

        res
    }

    /// Create the dm-integrity device 'hiberimage_hiberintegrity' (on top of
    /// the logical volume 'hiberimage').
    fn create_hiberimage_integrity_dm_dev(&self, format_device: bool) -> Result<()> {
        let backing_dev = lv_path(&self.vg_name, Self::HIBERIMAGE);
        let backing_dev_nr_sectors = get_blockdev_size(&backing_dev)? / SECTOR_SIZE;
        let meta_data_dev = DeviceMapper::device_path(Self::HIBERINTEGRITY).unwrap();

        if format_device {
            // Inititialize the first blocks of the integrity device with
            // zeroes to tell the kernel to format it. The exact number of
            // blocks that needs to be zeroed isn't well documented, 1MB
            // should be more than enough.
            zero_init_blockdev(Path::new(&meta_data_dev), SIZE_1M).context(format!(
                "zero initialization of {} failed",
                meta_data_dev.display()
            ))?;
        }

        let table = format!(
            "0 {backing_dev_nr_sectors} integrity {} 0 \
                             {AES_GCM_INTEGRITY_BYTES_PER_BLOCK} D 2 block_size:{SIZE_4K} \
                             meta_device:{}",
            backing_dev.display(),
            meta_data_dev.display()
        );

        DeviceMapper::create_device(Self::HIBERIMAGE_INTEGRITY, &table)
    }

    /// Create the dm-crypt device 'hiberimage' for the hibernation image (on top of the
    /// dm-integrity device 'hiberimage_integrity'.
    fn create_hiberimage_dm_dev(&self, key_data: &[u8]) -> Result<()> {
        let key_desc = "dmcrypt:hiberimage";

        keyctl_add_key(key_desc, key_data)?;

        let backing_dev = DeviceMapper::device_path(Self::HIBERIMAGE_INTEGRITY).unwrap();
        let backing_dev_nr_sectors = get_blockdev_size(&backing_dev)? / SECTOR_SIZE;
        let table = format!(
            "0 {backing_dev_nr_sectors} crypt capi:gcm(aes)-random :32:logon:{key_desc} \
                             0 {} 0 5 allow_discards no_read_workqueue \
                             no_write_workqueue sector_size:{SIZE_4K} \
                             integrity:{AES_GCM_INTEGRITY_BYTES_PER_BLOCK}:aead",
            backing_dev.display()
        );

        let res = DeviceMapper::create_device(Self::HIBERIMAGE, &table);

        // Now that the device is set up we can remove the key again from the kernel key ring.
        keyctl_remove_key(key_desc)?;

        res
    }
}

fn roundup_mutiple(val: u64, alignment: u64) -> u64 {
    ((val + alignment - 1) / alignment) * alignment
}

fn get_blockdev_size(path: &Path) -> Result<u64> {
    let args = vec![String::from("--getsz"), path.to_string_lossy().to_string()];

    // TODO: use BLKGETSIZE ioctl to get the block size
    let out = checked_command_output(Command::new("/sbin/blockdev").args(args)).context(
        format!("Failed to get size of '{}'", path.to_string_lossy()),
    )?;

    let sectors = String::from_utf8_lossy(&out.stdout).trim().parse::<u64>()?;
    Ok(sectors * SECTOR_SIZE)
}

fn zero_init_blockdev(path: &Path, num_bytes: u64) -> Result<()> {
    let mut f = OpenOptions::new().write(true).open(path)?;

    let mut bytes_left = num_bytes;
    let zeroes_4k = [0_u8; SIZE_4K as usize];

    while bytes_left > 0 {
        let mut data = vec![];

        // add full 4k blocks to the vector
        for _ in 0..(bytes_left / SIZE_4K) {
            data.push(IoSlice::new(&zeroes_4k));
        }

        if bytes_left % SIZE_4K != 0 {
            let remaining_bytes = &zeroes_4k[0..(bytes_left % SIZE_4K) as usize];
            data.push(IoSlice::new(remaining_bytes));
        }

        let bytes_written = f.write_vectored(&data)?;
        bytes_left -= bytes_written as u64;
    }

    Ok(())
}

/// Log a metric for the 'hibermeta' file system status.
fn log_file_system_status(status: FileSystemStatus) {
    let mut metrics_logger = METRICS_LOGGER.lock().unwrap();

    metrics_logger.log_enum_metric(
        "Platform.Hibernate.FileSystem.Hibermeta.FileSystemStatus",
        status as isize,
        FileSystemStatus::Count as isize - 1,
    );
}

/// Tracks and active mount and unmounts it when the instance is dropped.
pub struct ActiveMount {
    mountpoint: PathBuf,
    is_mounted: bool,
}

impl ActiveMount {
    /// Create a new ActiveMount
    fn new<P: AsRef<OsStr>>(mountpoint: P) -> Self {
        ActiveMount {
            mountpoint: PathBuf::from(Path::new(&mountpoint)),
            is_mounted: true,
        }
    }

    /// Unmount the active mount
    pub fn unmount(&mut self) -> Result<()> {
        self.is_mounted = false;
        unmount_filesystem(&self.mountpoint)
    }
}

impl Drop for ActiveMount {
    /// Unmounts the active mount if it is still mounted
    fn drop(&mut self) {
        if self.is_mounted {
            self.unmount().unwrap();
        }
    }
}

/// Object that tracks the lifetime of a temporarily suspended dm-target, and
/// resumes it when the object is dropped.
struct SuspendedDmDevice {
    name: String,
}

impl SuspendedDmDevice {
    pub fn new(name: &str) -> Result<Self> {
        DeviceMapper::suspend_device(name)?;

        Ok(Self {
            name: name.to_string(),
        })
    }
}

impl Drop for SuspendedDmDevice {
    fn drop(&mut self) {
        if let Err(e) = DeviceMapper::resume_device(&self.name) {
            error!("{e}");
        }
    }
}

/// Function that waits for a vector of references to DmSnapshotMerge objects to
/// finish. Returns an error if any failed, and waits with a timeout for any
/// that did not fail.
fn wait_for_snapshots_merge(snapshots: &mut Vec<DmSnapshotMerge>, timeout_ms: u32) -> Result<()> {
    info!("Waiting for {} snapshots to merge", snapshots.len());
    let mut remaining_ms: i64 = timeout_ms.into();
    let mut result = Ok(());
    loop {
        let mut all_done = true;
        for snapshot in &mut *snapshots {
            if snapshot.complete || snapshot.error {
                continue;
            }

            all_done = false;
            if let Err(e) = snapshot.check_merge_progress() {
                error!("Failed to check snapshot {}: {:?}", snapshot.name, e);
                result = Err(e);
            }
        }

        if all_done {
            break;
        }

        if remaining_ms <= 0 {
            return result.and(
                Err(HibernateError::MergeTimeoutError())
                    .context("Timed out waiting for snapshot merges"),
            );
        }

        // Wait long enough that this thread isn't busy spinning and real I/O
        // progress can be made, but not so long that our I/O rate measurements
        // would be significantly skewed by the wait period remainder.
        thread::sleep(Duration::from_millis(50));
        remaining_ms -= 50;
    }

    result
}

/// Object that tracks an in-progress dm-snapshot merge.
struct DmSnapshotMerge {
    pub name: String,
    pub complete: bool,
    pub error: bool,
    snapshot_name: String,
    origin_majmin: String,
    start: Instant,
    starting_sectors: u64,
}

impl DmSnapshotMerge {
    // Begin the process of merging a given snapshot into its origin. Returns
    // None if the given snapshot doesn't exist.
    pub fn new(name: &str) -> Result<Option<Self>> {
        let origin_name = format!("{}-origin", name);
        let snapshot_name = format!("{}-rw", name);
        let start = Instant::now();

        // If the snapshot path doesn't exist, there's nothing to merge.
        // Consider this a success.
        if !DeviceMapper::device_exists(&snapshot_name) {
            return Ok(None);
        }

        // Get the count of data sectors in the snapshot for later I/O rate
        // logging.
        let starting_sectors =
            get_snapshot_data_sectors(&snapshot_name).context("Failed to get snapshot size")?;

        // Get the origin table, which points at the "real" block device, for
        // later.
        let origin_table = DeviceMapper::get_device_table(&origin_name)?;

        // Get the snapshot table line, and substitute snapshot for
        // snapshot-merge, which (once installed) will kick off the merge
        // process in the kernel.
        let snapshot_table = DeviceMapper::get_device_table(&snapshot_name)?;
        let snapshot_table = snapshot_table.replace(" snapshot ", " snapshot-merge ");

        // Suspend both the origin and the snapshot. Be careful, as the stateful
        // volumes may now hang if written to (by loggers, for example). The
        // SuspendedDmDevice objects ensure the devices get resumed even if this
        // function bails out early.
        let suspended_origin =
            SuspendedDmDevice::new(&origin_name).context("Failed to suspend origin")?;
        let suspended_snapshot =
            SuspendedDmDevice::new(&snapshot_name).context("Failed to suspend snapshot")?;

        // With both devices suspended, replace the table to begin the merge process.
        DeviceMapper::reload_device_table(&snapshot_name, &snapshot_table)?;

        // If that worked, resume the devices (by dropping the suspend object),
        // then remove the origin.
        drop(suspended_origin);
        drop(suspended_snapshot);
        DeviceMapper::remove_device(&origin_name)?;

        // Delete the loop device backing the snapshot.
        let snapshot_majmin = get_nth_element(&snapshot_table, 4)?;
        if let Some(loop_path) = majmin_to_loop_path(snapshot_majmin) {
            delete_loop_device(&loop_path).context("Failed to delete loop device")?;
        } else {
            warn!("Warning: Underlying device for dm target {} is not a loop device, skipping loop deletion",
                  snapshot_majmin);
        }

        let origin_majmin = get_nth_element(&origin_table, 3)?.to_string();
        Ok(Some(Self {
            name: name.to_string(),
            start,
            snapshot_name,
            origin_majmin,
            starting_sectors,
            complete: false,
            error: false,
        }))
    }

    /// Check on the progress of the async merge happening. On success, returns
    /// the number of sectors remaining to merge.
    pub fn check_merge_progress(&mut self) -> Result<u64> {
        if self.complete {
            return Ok(0);
        }

        let result = self.check_and_complete_merge();
        if result.is_err() {
            self.error = true;
        }

        result
    }

    /// Inner routine to check the merge.
    fn check_and_complete_merge(&mut self) -> Result<u64> {
        let data_sectors = get_snapshot_data_sectors(&self.snapshot_name)?;
        if data_sectors == 0 {
            self.complete_post_merge()?;
            self.complete = true;
        }

        Ok(data_sectors)
    }

    /// Perform the post-merge dm-table operations to convert the merged
    /// snapshot to a snapshot origin.
    fn complete_post_merge(&mut self) -> Result<()> {
        // Now that the snapshot is fully synced back into the origin, replace
        // that entry with a snapshot-origin for the "real" underlying physical
        // block device. This is done so the copy-on-write store can be released
        // and deleted if needed.
        //
        // For those wondering what happens to writes that occur after the "wait
        // for merge" is complete but before the device is suspended below:
        // future writes to the merging snapshot go straight down to the disk
        // if they were clean in the merging snapshot. So the amount of data in
        // the snapshot only ever shrinks, it doesn't continue to grow once it's
        // begun merging. Since the disk now sees every write passing through,
        // this switcharoo doesn't create any inconsistencies.
        let suspended_snapshot =
            SuspendedDmDevice::new(&self.snapshot_name).context("Failed to suspend snapshot")?;

        let snapshot_table = DeviceMapper::get_device_table(&self.snapshot_name)?;
        let origin_size = get_nth_element(&snapshot_table, 1)?;
        let origin_table = format!("0 {} snapshot-origin {}", origin_size, self.origin_majmin);
        DeviceMapper::reload_device_table(&self.snapshot_name, &origin_table)?;

        drop(suspended_snapshot);

        // Rename the dm target, which doesn't serve any functional purpose, but
        // serves as a useful breadcrumb during debugging and in feedback reports.
        let merged_name = format!("{}-merged", self.name);
        DeviceMapper::rename_device(&self.snapshot_name, &merged_name)?;

        // Victory log!
        log_io_duration(
            &format!("Merged {} snapshot", &self.snapshot_name),
            self.starting_sectors * 512,
            self.start.elapsed(),
        );

        Ok(())
    }
}

impl Drop for DmSnapshotMerge {
    fn drop(&mut self) {
        // Print an error if the caller never waited for this merge.
        if !self.complete && !self.error {
            error!("Never waited on merge for {}", self.name);
        }
    }
}

/// Return the number of data sectors in the snapshot.
/// See https://www.kernel.org/doc/Documentation/device-mapper/snapshot.txt
fn get_snapshot_data_sectors(name: &str) -> Result<u64> {
    let status = get_dm_status(name).context(format!("Failed to get dm status for {}", name))?;
    let allocated_element =
        get_nth_element(&status, 3).context("Failed to get dm status allocated element")?;

    let allocated = allocated_element.split('/').next().unwrap();
    let metadata =
        get_nth_element(&status, 4).context("Failed to get dm status metadata element")?;

    let allocated: u64 = allocated
        .parse()
        .context("Failed to parse dm-snapshot allocated field")?;

    let metadata: u64 = metadata
        .parse()
        .context("Failed to parse dm-snapshot metadata fielf")?;

    Ok(allocated - metadata)
}

/// Return the number of used data sectors, and the total number of data
/// sectors. See
/// https://www.kernel.org/doc/Documentation/device-mapper/snapshot.txt
pub fn get_snapshot_size(name: &str) -> Result<(u64, u64)> {
    let status = get_dm_status(name).context(format!("Failed to get dm status for {}", name))?;
    let allocated_element =
        get_nth_element(&status, 3).context("Failed to get dm status allocated element")?;

    // Oops, the snapshot filled fully up and got deactivated by the kernel.
    if allocated_element == "Invalid" {
        return Ok((100, 100));
    }

    let mut slash_elements = allocated_element.split('/');
    let allocated = slash_elements
        .next()
        .context("Failed to get dm-snapshot allocated sectors")?;
    let total = slash_elements
        .next()
        .context("Failed to get dm-snapshot total sectors")?;

    let allocated: u64 = allocated
        .parse()
        .context("Failed to parse dm-snapshot allocated field")?;

    let total: u64 = total
        .parse()
        .context("Failed to parse dm-snapshot total field")?;
    Ok((allocated, total))
}

/// Delete a snapshot.
fn delete_snapshot(name: &str) -> Result<()> {
    let snapshot_file_path = snapshot_file_path(name);
    info!("Deleting {}", snapshot_file_path.display());
    remove_file(snapshot_file_path).context("Failed to delete snapshot file")
}

/// Get the dm status line for a particular target.
fn get_dm_status(target: &str) -> Result<String> {
    dmsetup_checked_output(Command::new(DMSETUP_PATH).args(["status", target]))
        .context(format!("Failed to get dm status line for {}", target))
}

/// Delete a loop device.
fn delete_loop_device(dev: &str) -> Result<()> {
    checked_command(Command::new(LOSETUP_PATH).args(["-d", dev]))
        .context(format!("Failed to delete loop device: {}", dev))
}

/// Run a dmsetup command and return the output as a trimmed String.
fn dmsetup_checked_output(command: &mut Command) -> Result<String> {
    let output =
        checked_command_output(command).context("Failed to run dmsetup and collect output")?;

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Get a loop device path like /dev/loop4 out of a major:minor string like
/// 7:4.
fn majmin_to_loop_path(majmin: &str) -> Option<String> {
    if !majmin.starts_with("7:") {
        return None;
    }

    let mut split = majmin.split(':');
    split.next();
    let loop_num: i32 = split.next().unwrap().parse().unwrap();
    Some(format!("/dev/loop{}", loop_num))
}

/// Return the file path backing the loop device backing a dm-snapshot
/// region for the given name.
fn snapshot_file_path(name: &str) -> PathBuf {
    snapshot_dir().join(name)
}

/// Return the snapshot directory.
fn snapshot_dir() -> PathBuf {
    Path::new("/run/hibernate/snapshots").to_path_buf()
}

/// Separate a string by whitespace, and return the n-th element, or an error
/// if the string doesn't contain that many elements.
fn get_nth_element(s: &str, n: usize) -> Result<&str> {
    let elements: Vec<&str> = s.split_whitespace().collect();
    if elements.len() <= n {
        return Err(HibernateError::IndexOutOfRangeError())
            .context(format!("Failed to get element {} in {}", n, s));
    }

    Ok(elements[n])
}

/// Define the number of elements in a thin-pool target before the options.
const THINPOOL_CONFIG_COUNT: usize = 7;

/// Define the configuration for a thin-pool dm target.
struct ThinpoolConfig {
    config: String,
    options: Vec<String>,
}

impl ThinpoolConfig {
    pub fn new(table: &str) -> Result<Self> {
        let elements: Vec<&str> = table.split_whitespace().collect();
        // Fail if there aren't enough fields.
        if elements.len() <= THINPOOL_CONFIG_COUNT {
            return Err(HibernateError::IndexOutOfRangeError())
                .context(format!("Got too few thinpool configs: {}", elements.len()));
        }

        // Fail if something other than a thin-pool target was given.
        if elements[2] != "thin-pool" {
            return Err(HibernateError::DeviceMapperError(
                "Not a thin-pool".to_string(),
            ))
            .context("Failed to parse thinpool config");
        }

        // Fail if the option count isn't valid, or if there is extra stuff on
        // the end, since this code doesn't retain that.
        let option_count: usize = elements[THINPOOL_CONFIG_COUNT].parse()?;
        if THINPOOL_CONFIG_COUNT + option_count + 1 != elements.len() {
            return Err(HibernateError::DeviceMapperError(
                "Unexpected thin-pool elements on the end".to_string(),
            ))
            .context("Failed to parse thinpool config");
        }

        Ok(Self {
            config: elements[..THINPOOL_CONFIG_COUNT].join(" "),
            options: elements[(THINPOOL_CONFIG_COUNT + 1)..]
                .iter()
                .map(|v| v.to_string())
                .collect(),
        })
    }

    /// Add an option to the thinpool config if it doesn't already exist.
    pub fn add_option(&mut self, option: &str) {
        let option = option.to_string();
        if !self.options.contains(&option) {
            self.options.push(option)
        }
    }

    /// Remove an option from the thinpool config.
    pub fn remove_option(&mut self, option: &str) {
        // Retain every value in the options that doesn't match the given option.
        self.options.retain(|x| x != option);
    }

    /// Convert this config to a dm-table line.
    pub fn to_table(&self) -> String {
        format!(
            "{} {} {}",
            &self.config,
            self.options.len(),
            self.options.join(" ")
        )
    }
}
