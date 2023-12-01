// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INIT_CLOBBER_STATE_H_
#define INIT_CLOBBER_STATE_H_

#include <sys/stat.h>

#include <functional>
#include <memory>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/time/time.h>
#include <brillo/blkdev_utils/lvm.h>
#include <brillo/process/process.h>

#include "init/clobber_ui.h"
#include "init/crossystem.h"

constexpr char kThinpool[] = "thinpool";
constexpr char kUnencrypted[] = "unencrypted";

class ClobberState {
 public:
  struct Arguments {
    // Run in the context of a factory flow, do not reboot when done.
    bool factory_wipe = false;
    // Less thorough data destruction.
    bool fast_wipe = false;
    // Don't delete the non-active set of kernel/root partitions.
    bool keepimg = false;
    // Preserve some files.
    bool safe_wipe = false;
    // Preserve rollback data.
    bool rollback_wipe = false;
    // Preserve initial reason for triggering clobber, if available.
    // Assume that the reason string is already sanitized by session
    // manager (non-alphanumeric characters replaced with '_').
    std::string reason = "";
    // Setup the stateful partition using a thin logical volume.
    bool setup_lvm = false;
    // Run in the context of an RMA flow. Additionally save the RMA
    // state file.
    bool rma_wipe = false;
    // Preserve the flag file used to skip some OOBE screens during the Chromad
    // to cloud migration.
    bool ad_migration_wipe = false;
    // Preserve LVM stateful without wiping entire stateful partition.
    // (Only supported/enforced on LVM stateful devices)
    bool preserve_lvs = false;
  };

  // The index of each partition within the gpt partition table.
  struct PartitionNumbers {
    int stateful = -1;
    int root_a = -1;
    int root_b = -1;
    int kernel_a = -1;
    int kernel_b = -1;
  };

  struct DeviceWipeInfo {
    // Paths under /dev for the various devices to wipe.
    base::FilePath stateful_partition_device;
    // Devices using logical volumes on the stateful partition will use a
    // logical volume on top of the stateful partition device.
    base::FilePath stateful_filesystem_device;
    base::FilePath inactive_root_device;
    base::FilePath inactive_kernel_device;

    // Is the stateful device backed by an MTD flash device.
    bool is_mtd_flash = false;
    // The partition number for the currently booted kernel partition.
    int active_kernel_partition = -1;
  };

  struct PreserveLogicalVolumesWipeInfo {
    std::string lv_name;
    bool preserve = false;
    bool zero = false;

    struct Hash {
      auto operator()(const PreserveLogicalVolumesWipeInfo& info) const {
        // Use the logical volume name for uniqueness.
        return std::hash<std::string>{}(info.lv_name);
      }
    };

    bool operator==(const PreserveLogicalVolumesWipeInfo& o) const {
      // Again, use the logical volume name for uniqueness.
      return this->lv_name == o.lv_name;
    }
  };
  using PreserveLogicalVolumesWipeInfos =
      std::unordered_set<PreserveLogicalVolumesWipeInfo,
                         PreserveLogicalVolumesWipeInfo::Hash>;

  // Extracts ClobberState's arguments from argv.
  static Arguments ParseArgv(int argc, char const* const argv[]);

  // Attempts to increment the contents of `path` by 1. If the contents cannot
  // be read, or if the contents are not an integer, writes '1' to the file.
  static bool IncrementFileCounter(const base::FilePath& path);

  // Attempts to write the last powerwash time to `path`.
  // The `time` is that when the device have powerwash completed.
  static bool WriteLastPowerwashTime(const base::FilePath& path,
                                     const base::Time& time);

  // Given a list of files to preserve (relative to `preserved_files_root`),
  // creates a tar file containing those files at `tar_file_path`.
  // The directory structure of the preserved files is preserved.
  static int PreserveFiles(const base::FilePath& preserved_files_root,
                           const std::vector<base::FilePath>& preserved_files,
                           const base::FilePath& tar_file_path);

  // Splits a device path, for example /dev/mmcblk0p1, /dev/sda3,
  // /dev/ubiblock9_0 into the base device and partition numbers,
  // which would be respectively /dev/mmcblk0p, 1; /dev/sda, 3; and
  // /dev/ubiblock, 9.
  // Returns true on success.
  static bool GetDevicePathComponents(const base::FilePath& device,
                                      std::string* base_device_out,
                                      int* partition_out);

  // Determine the devices to be wiped and their properties, and populate
  // `wipe_info_out` with the results. Returns true if successful.
  static bool GetDevicesToWipe(const base::FilePath& root_disk,
                               const base::FilePath& root_device,
                               const PartitionNumbers& partitions,
                               DeviceWipeInfo* wipe_info_out);

  static bool WipeMTDDevice(const base::FilePath& device_path,
                            const PartitionNumbers& partitions);

  // Wipe `device_path`, showing a progress UI using `ui`.
  //
  // If `fast` is true, wipe `device_path` using a less-thorough but much faster
  // wipe. Not all blocks are guaranteed to be overwritten, so this should be
  // reserved for situations when there is no concern of data leakage.
  // A progress indicator will not be displayed if `fast` mode is enabled.
  static bool WipeBlockDevice(const base::FilePath& device_path,
                              ClobberUi* ui,
                              bool fast,
                              bool discard);

  // Removes well-known keys from the VPD.
  static void RemoveVpdKeys();

  void CreateUnencryptedStatefulLV(const brillo::VolumeGroup& vg,
                                   const brillo::Thinpool& thinpool,
                                   uint64_t lv_size);

  std::optional<uint64_t> GetPartitionSize(const base::FilePath& base_device);

  // Creates the necessary LVM devices specifically for preserving logical
  // volumes option during clobber.
  void CreateLogicalVolumeStackForPreserved();

  // Creates the necessary LVM devices.
  void CreateLogicalVolumeStack();

  // Removes the necessary LVM devices.
  void RemoveLogicalVolumeStack();

  // Safe wipe of logical volumes.
  // Returns false if there are any failures during the safe wiping
  // (zeroing/preserving/removing) of individual logical volumes.
  bool PreserveLogicalVolumesWipe(const PreserveLogicalVolumesWipeInfos& infos);
  bool ProcessInfo(const brillo::VolumeGroup& vg,
                   const PreserveLogicalVolumesWipeInfo& info);

  ClobberState(const Arguments& args,
               std::unique_ptr<CrosSystem> cros_system,
               std::unique_ptr<ClobberUi> ui,
               std::unique_ptr<brillo::LogicalVolumeManager> lvm);

  // Run the clobber state routine.
  int Run();

  bool IsInDeveloperMode();

  bool MarkDeveloperMode();

  // Attempt to switch rotational drives and drives that support
  // secure_erase_file to a fast wipe by taking some (secure) shortcuts.
  void AttemptSwitchToFastWipe(bool is_rotational);

  // If the stateful filesystem is available and the disk is rotational, do some
  // best-effort content shredding. Since on a rotational disk the filesystem is
  // not mounted with "data=journal", writes really do overwrite the block
  // contents (unlike on an SSD).
  void ShredRotationalStatefulFiles();

  // Wipe encryption key information from the stateful partition for supported
  // devices.
  bool WipeKeysets();

  // Forces a delay, writing progress to the TTY.  This is used to prevent
  // developer mode transitions from happening too quickly.
  virtual void ForceDelay();

  // Returns vector of files to be preserved. All FilePaths are relative to
  // stateful_.
  std::vector<base::FilePath> GetPreservedFilesList();

  // Determines if the given device (under `dev_`) is backed by a rotational
  // hard drive.
  // Returns true if it can conclusively determine it's rotational,
  // otherwise false.
  bool IsRotational(const base::FilePath& device_path);

  void SetArgsForTest(const Arguments& args);
  Arguments GetArgsForTest();
  void SetStatefulForTest(const base::FilePath& stateful_path);
  void SetDevForTest(const base::FilePath& dev_path);
  void SetSysForTest(const base::FilePath& sys_path);

  void SetLogicalVolumeManagerForTesting(
      std::unique_ptr<brillo::LogicalVolumeManager> lvm) {
    lvm_ = std::move(lvm);
  }

  void SetWipeInfoForTesting(const DeviceWipeInfo& wipe_info) {
    wipe_info_ = wipe_info;
  }

 protected:
  // These functions are marked protected so they can be overridden for tests.

  // Wrapper around stat(2).
  virtual int Stat(const base::FilePath& path, struct stat* st);

  // Wrapper around secure_erase_file::SecureErase(const base::FilePath&).
  virtual bool SecureErase(const base::FilePath& path);

  // Wrapper around secure_erase_file::DropCaches(). Must be called after
  // a call to SecureEraseFile. Files are only securely deleted if DropCaches
  // returns true.
  virtual bool DropCaches();

  // Wrapper around ioctl(_, BLKGETSIZE64, _). From cryptohome::Platform.
  virtual uint64_t GetBlkSize(const base::FilePath& device_size);

  // Generates a random volume group name for the stateful partition.
  virtual std::string GenerateRandomVolumeGroupName();

 private:
  bool ClearBiometricSensorEntropy();

  // Perform media-dependent wipe of the device based on if the device is
  // an MTD device or not.
  // `device_path` should be the path under /dev/, e.g. /dev/sda3, /dev/ubi5_0.
  // `discard` to discard the blocks after wiping.
  virtual bool WipeDevice(const base::FilePath& device_name,
                          bool discard = false);

  // Makes a new filesystem on `stateful_filesystem_device`.
  int CreateStatefulFileSystem(const std::string& stateful_filesystem_device);

  void Reboot();

  // Helper to wrap calls removing logical volumes and device level wipes.
  void ResetStatefulPartition();

  // Returns the argument list for preserved wipe of LVM.
  PreserveLogicalVolumesWipeInfos PreserveLogicalVolumesWipeArgs();

  Arguments args_;
  std::unique_ptr<CrosSystem> cros_system_;
  std::unique_ptr<ClobberUi> ui_;
  base::FilePath stateful_;
  base::FilePath dev_;
  base::FilePath sys_;
  PartitionNumbers partitions_;
  base::FilePath root_disk_;
  DeviceWipeInfo wipe_info_;
  base::TimeTicks wipe_start_time_;
  std::unique_ptr<brillo::LogicalVolumeManager> lvm_;

  // Must be last in member variable list.
  base::WeakPtrFactory<ClobberState> weak_ptr_factory_;
};

#endif  // INIT_CLOBBER_STATE_H_
