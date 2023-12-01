// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "init/clobber_state.h"

#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#include <base/check.h>

// Keep after <sys/mount.h> to avoid build errors.
#include <linux/fs.h>

#include <algorithm>
#include <cstdlib>
#include <memory>
#include <optional>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <base/bits.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <brillo/blkdev_utils/get_backing_block_device.h>
#include <brillo/blkdev_utils/lvm.h>
#include <brillo/blkdev_utils/storage_device.h>
#include <brillo/blkdev_utils/storage_utils.h>
#include <brillo/files/file_util.h>
#include <brillo/process/process.h>
#include <crypto/random.h>
#include <rootdev/rootdev.h>
#include <chromeos/secure_erase_file/secure_erase_file.h>

#include "init/crossystem.h"
#include "init/utils.h"

namespace {

constexpr char kStatefulPath[] = "/mnt/stateful_partition";
constexpr char kPowerWashCountPath[] = "unencrypted/preserve/powerwash_count";
constexpr char kLastPowerWashTimePath[] =
    "unencrypted/preserve/last_powerwash_time";
constexpr char kRmaStateFilePath[] = "unencrypted/rma-data/state";
constexpr char kClobberLogPath[] = "/tmp/clobber-state.log";
constexpr char kBioWashPath[] = "/usr/bin/bio_wash";
constexpr char kPreservedFilesTarPath[] = "/tmp/preserve.tar";
constexpr char kStatefulClobberLogPath[] = "unencrypted/clobber.log";
constexpr char kMountEncryptedPath[] = "/usr/sbin/mount-encrypted";
constexpr char kRollbackFileForPstorePath[] =
    "/var/lib/oobe_config_save/data_for_pstore";
constexpr char kPstoreInputPath[] = "/dev/pmsg0";
// Keep file names in sync with update_engine prefs.
constexpr char kLastPingDate[] = "last-active-ping-day";
constexpr char kLastRollcallDate[] = "last-roll-call-ping-day";
constexpr char kUpdateEnginePrefsPath[] = "/var/lib/update_engine/prefs/";
constexpr char kUpdateEnginePreservePath[] =
    "unencrypted/preserve/update_engine/prefs/";
constexpr char kChromadMigrationSkipOobePreservePath[] =
    "unencrypted/preserve/chromad_migration_skip_oobe";
// CrOS Private Computing (go/chromeos-data-pc) will save the device last
// active dates in different use cases into a file.
constexpr char kPsmDeviceActiveLocalPrefPath[] =
    "/var/lib/private_computing/last_active_dates";
constexpr char kPsmDeviceActivePreservePath[] =
    "unencrypted/preserve/last_active_dates";

// Size of string for volume group name.
constexpr int kVolumeGroupNameSize = 16;

// The presence of this file indicates that crash report collection across
// clobber is disabled in developer mode.
constexpr char kDisableClobberCrashCollectionPath[] =
    "/run/disable-clobber-crash-collection";
// The presence of this file indicates that the kernel supports ext4 directory
// level encryption.
constexpr char kExt4DircryptoSupportedPath[] =
    "/sys/fs/ext4/features/encryption";

constexpr char kUbiRootDisk[] = "/dev/mtd0";
constexpr char kUbiDevicePrefix[] = "/dev/ubi";
constexpr char kUbiDeviceStatefulFormat[] = "/dev/ubi%d_0";

constexpr base::TimeDelta kMinClobberDuration = base::Minutes(5);

// |strip_partition| attempts to remove the partition number from the result.
base::FilePath GetRootDevice(bool strip_partition) {
  char buf[PATH_MAX];
  int ret = rootdev(buf, PATH_MAX, /*use_slave=*/true, strip_partition);
  if (ret == 0) {
    return base::FilePath(buf);
  } else {
    return base::FilePath();
  }
}

// Calculate the maximum number of bad blocks per 1024 blocks for UBI.
int CalculateUBIMaxBadBlocksPer1024(int partition_number) {
  // The max bad blocks per 1024 is based on total device size,
  // not the partition size.
  int mtd_size = 0;
  utils::ReadFileToInt(base::FilePath("/sys/class/mtd/mtd0/size"), &mtd_size);

  int erase_size;
  utils::ReadFileToInt(base::FilePath("/sys/class/mtd/mtd0/erasesize"),
                       &erase_size);

  int block_count = mtd_size / erase_size;

  int reserved_error_blocks = 0;
  base::FilePath reserved_for_bad(base::StringPrintf(
      "/sys/class/ubi/ubi%d/reserved_for_bad", partition_number));
  utils::ReadFileToInt(reserved_for_bad, &reserved_error_blocks);
  return reserved_error_blocks * 1024 / block_count;
}

bool GetBlockCount(const base::FilePath& device_path,
                   int64_t block_size,
                   int64_t* block_count_out) {
  if (!block_count_out)
    return false;

  brillo::ProcessImpl dumpe2fs;
  dumpe2fs.AddArg("/sbin/dumpe2fs");
  dumpe2fs.AddArg("-h");
  dumpe2fs.AddArg(device_path.value());

  dumpe2fs.RedirectOutputToMemory(true);
  if (dumpe2fs.Run() == 0) {
    std::string output = dumpe2fs.GetOutputString(STDOUT_FILENO);
    size_t label = output.find("Block count");
    size_t value_start = output.find_first_of("0123456789", label);
    size_t value_end = output.find_first_not_of("0123456789", value_start);

    if (value_start != std::string::npos && value_end != std::string::npos) {
      int64_t block_count;
      if (base::StringToInt64(
              output.substr(value_start, value_end - value_start),
              &block_count)) {
        *block_count_out = block_count;
        return true;
      }
    }
  }

  // Fallback if using dumpe2fs failed. This interface always returns a count
  // of sectors, not blocks, so we must convert to a block count.
  // Per "include/linux/types.h", Linux always considers sectors to be
  // 512 bytes long.
  base::FilePath fp("/sys/class/block");
  fp = fp.Append(device_path.BaseName());
  fp = fp.Append("size");
  std::string sector_count_str;
  if (base::ReadFileToString(fp, &sector_count_str)) {
    base::TrimWhitespaceASCII(sector_count_str, base::TRIM_ALL,
                              &sector_count_str);
    int64_t sector_count;
    if (base::StringToInt64(sector_count_str, &sector_count)) {
      *block_count_out = sector_count * 512 / block_size;
      return true;
    }
  }
  return false;
}

void AppendToLog(const std::string_view& source, const std::string& contents) {
  if (!base::AppendToFile(base::FilePath(kClobberLogPath), contents)) {
    PLOG(ERROR) << "Appending " << source << " to clobber-state log failed";
  }
}

// Attempt to save logs from the boot when the clobber happened into the
// stateful partition.
void CollectClobberCrashReports() {
  brillo::ProcessImpl crash_reporter_early_collect;
  crash_reporter_early_collect.AddArg("/sbin/crash_reporter");
  crash_reporter_early_collect.AddArg("--early");
  crash_reporter_early_collect.AddArg("--log_to_stderr");
  crash_reporter_early_collect.AddArg("--preserve_across_clobber");
  crash_reporter_early_collect.AddArg("--boot_collect");
  if (crash_reporter_early_collect.Run() != 0)
    LOG(WARNING) << "Unable to collect logs and crashes from current run.";

  return;
}

bool MountEncryptedStateful() {
  brillo::ProcessImpl mount_encstateful;
  mount_encstateful.AddArg(kMountEncryptedPath);
  if (mount_encstateful.Run() != 0) {
    PLOG(ERROR) << "Failed to mount encrypted stateful.";
    return false;
  }
  return true;
}

void UnmountEncryptedStateful() {
  for (int attempts = 0; attempts < 10; ++attempts) {
    brillo::ProcessImpl umount_encstateful;
    umount_encstateful.AddArg(kMountEncryptedPath);
    umount_encstateful.AddArg("umount");
    if (umount_encstateful.Run()) {
      return;
    }
  }
  PLOG(ERROR) << "Failed to unmount encrypted stateful.";
}

void UnmountStateful(const base::FilePath& stateful) {
  LOG(INFO) << "Unmounting stateful partition";
  for (int attempts = 0; attempts < 10; ++attempts) {
    int ret = umount(stateful.value().c_str());
    if (ret) {
      // Disambiguate failures from busy or already unmounted stateful partition
      // from other generic failures.
      if (errno == EBUSY) {
        PLOG(ERROR) << "Failed to unmount busy stateful partition";
        base::PlatformThread::Sleep(base::Milliseconds(200));
        continue;
      } else if (errno != EINVAL) {
        PLOG(ERROR) << "Unable to unmount " << stateful;
      } else {
        PLOG(INFO) << "Stateful partition already unmounted";
      }
    }
    return;
  }
}

void MoveRollbackFileToPstore() {
  const base::FilePath file_for_pstore(kRollbackFileForPstorePath);

  std::string data;
  if (!base::ReadFileToString(file_for_pstore, &data)) {
    if (errno != ENOENT) {
      PLOG(ERROR) << "Failed to read rollback data for pstore.";
    }
    return;
  }

  if (!base::AppendToFile(base::FilePath(kPstoreInputPath), data + "\n")) {
    if (errno == ENOENT) {
      PLOG(WARNING)
          << "Could not write rollback data because /dev/pmsg0 does not exist.";
    } else {
      PLOG(ERROR) << "Failed to write rollback data to pstore.";
    }
  }
  // The rollback file will be lost on tpm reset, so we do not need to
  // delete it manually.
}

// Minimal physical volume size (1 default sized extent).
constexpr uint64_t kMinStatefulPartitionSizeMb = 4;
// Percent size of thinpool compared to the physical volume.
constexpr size_t kThinpoolSizePercent = 98;
// thin_metadata_size estimates <2% of the thinpool size can be used safely to
// store metadata for up to 200 logical volumes.
constexpr size_t kThinpoolMetadataSizePercent = 1;
// Create thin logical volumes at 95% of the thinpool's size.
constexpr size_t kLogicalVolumeSizePercent = 95;

}  // namespace

// static
ClobberState::Arguments ClobberState::ParseArgv(int argc,
                                                char const* const argv[]) {
  Arguments args;
  if (argc <= 1)
    return args;

  // Due to historical usage, the command line parsing is a bit weird.
  // We split the first argument into multiple keywords.
  std::vector<std::string> split_args = base::SplitString(
      argv[1], " ", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  for (int i = 2; i < argc; ++i)
    split_args.push_back(argv[i]);

  for (const std::string& arg : split_args) {
    if (arg == "factory") {
      args.factory_wipe = true;
      // Factory mode implies fast wipe.
      args.fast_wipe = true;
    } else if (arg == "fast") {
      args.fast_wipe = true;
    } else if (arg == "keepimg") {
      args.keepimg = true;
    } else if (arg == "safe") {
      args.safe_wipe = true;
    } else if (arg == "rollback") {
      args.rollback_wipe = true;
    } else if (base::StartsWith(
                   arg, "reason=", base::CompareCase::INSENSITIVE_ASCII)) {
      args.reason = arg;
    } else if (arg == "setup_lvm") {
      args.setup_lvm = true;
    } else if (arg == "rma") {
      args.rma_wipe = true;
    } else if (arg == "ad_migration") {
      args.ad_migration_wipe = true;
    } else if (arg == "preserve_lvs") {
      args.preserve_lvs = true;
    }
  }

  if (USE_LVM_STATEFUL_PARTITION) {
    args.setup_lvm = true;
  }

  return args;
}

// static
bool ClobberState::IncrementFileCounter(const base::FilePath& path) {
  int value;
  if (!utils::ReadFileToInt(path, &value) || value < 0 || value >= INT_MAX) {
    return base::WriteFile(path, "1\n", 2) == 2;
  }

  std::string new_value = std::to_string(value + 1);
  new_value.append("\n");
  return new_value.size() ==
         base::WriteFile(path, new_value.c_str(), new_value.size());
}

// static
bool ClobberState::WriteLastPowerwashTime(const base::FilePath& path,
                                          const base::Time& time) {
  return base::WriteFile(path, base::StringPrintf("%ld\n", time.ToTimeT()));
}

// static
int ClobberState::PreserveFiles(
    const base::FilePath& preserved_files_root,
    const std::vector<base::FilePath>& preserved_files,
    const base::FilePath& tar_file_path) {
  // Remove any stale tar files from previous clobber-state runs.
  brillo::DeleteFile(tar_file_path);

  // We want to preserve permissions and recreate the directory structure
  // for all of the files in |preserved_files|. In order to do so we run tar
  // --no-recursion and specify the names of each of the parent directories.
  // For example for home/.shadow/install_attributes.pb
  // we pass to tar home, home/.shadow, home/.shadow/install_attributes.pb.
  std::vector<std::string> paths_to_tar;
  for (const base::FilePath& path : preserved_files) {
    // All paths should be relative to |preserved_files_root|.
    if (path.IsAbsolute()) {
      LOG(WARNING) << "Non-relative path " << path.value()
                   << " passed to PreserveFiles, ignoring.";
      continue;
    }
    if (!base::PathExists(preserved_files_root.Append(path)))
      continue;
    base::FilePath current = path;
    while (current != base::FilePath(base::FilePath::kCurrentDirectory)) {
      // List of paths is built in an order that is reversed from what we want
      // (parent directories first), but will then be passed to tar in reverse
      // order.
      //
      // e.g. for home/.shadow/install_attributes.pb, |paths_to_tar| will have
      // home/.shadow/install_attributes.pb, then home/.shadow, then home.
      paths_to_tar.push_back(current.value());
      current = current.DirName();
    }
  }

  // We can't create an empty tar file.
  if (paths_to_tar.size() == 0) {
    LOG(INFO)
        << "PreserveFiles found no files to preserve, no tar file created.";
    return 0;
  }

  brillo::ProcessImpl tar;
  tar.AddArg("/bin/tar");
  tar.AddArg("-c");
  tar.AddStringOption("-f", tar_file_path.value());
  tar.AddStringOption("-C", preserved_files_root.value());
  tar.AddArg("--no-recursion");
  tar.AddArg("--");

  // Add paths in reverse order because we built up the list of paths backwards.
  for (auto it = paths_to_tar.rbegin(); it != paths_to_tar.rend(); ++it) {
    tar.AddArg(*it);
  }
  return tar.Run();
}

// static
bool ClobberState::GetDevicePathComponents(const base::FilePath& device,
                                           std::string* base_device_out,
                                           int* partition_out) {
  if (!partition_out || !base_device_out)
    return false;
  const std::string& path = device.value();

  // MTD devices sometimes have a trailing "_0" after the partition which
  // we should ignore.
  std::string mtd_suffix = "_0";
  size_t suffix_index = path.length();
  if (base::EndsWith(path, mtd_suffix, base::CompareCase::SENSITIVE)) {
    suffix_index = path.length() - mtd_suffix.length();
  }

  size_t last_non_numeric =
      path.find_last_not_of("0123456789", suffix_index - 1);

  // If there are no non-numeric characters, this is a malformed device.
  if (last_non_numeric == std::string::npos) {
    return false;
  }

  std::string partition_number_string =
      path.substr(last_non_numeric + 1, suffix_index - (last_non_numeric + 1));
  int partition_number;
  if (!base::StringToInt(partition_number_string, &partition_number)) {
    return false;
  }
  *partition_out = partition_number;
  *base_device_out = path.substr(0, last_non_numeric + 1);
  return true;
}

bool ClobberState::IsRotational(const base::FilePath& device_path) {
  if (!dev_.IsParent(device_path)) {
    LOG(ERROR) << "Non-device given as argument to IsRotational: "
               << device_path.value();
    return false;
  }

  // Since there doesn't seem to be a good way to get from a partition name
  // to the base device name beyond simple heuristics, just find the device
  // with the same major number but with minor 0.
  struct stat st;
  if (Stat(device_path, &st) != 0) {
    return false;
  }
  unsigned int major_device_number = major(st.st_rdev);

  base::FileEnumerator enumerator(dev_, /*recursive=*/true,
                                  base::FileEnumerator::FileType::FILES);
  for (base::FilePath base_device_path = enumerator.Next();
       !base_device_path.empty(); base_device_path = enumerator.Next()) {
    if (Stat(base_device_path, &st) == 0 && S_ISBLK(st.st_mode) &&
        major(st.st_rdev) == major_device_number && minor(st.st_rdev) == 0) {
      // |base_device_path| must be the base device for |device_path|.
      base::FilePath rotational_file = sys_.Append("block")
                                           .Append(base_device_path.BaseName())
                                           .Append("queue/rotational");

      int value;
      if (utils::ReadFileToInt(rotational_file, &value)) {
        return value == 1;
      }
    }
  }
  return false;
}

// static
bool ClobberState::GetDevicesToWipe(
    const base::FilePath& root_disk,
    const base::FilePath& root_device,
    const ClobberState::PartitionNumbers& partitions,
    ClobberState::DeviceWipeInfo* wipe_info_out) {
  if (!wipe_info_out) {
    LOG(ERROR) << "wipe_info_out must be non-null";
    return false;
  }

  if (partitions.root_a < 0 || partitions.root_b < 0 ||
      partitions.kernel_a < 0 || partitions.kernel_b < 0 ||
      partitions.stateful < 0) {
    LOG(ERROR) << "Invalid partition numbers for GetDevicesToWipe";
    return false;
  }

  if (root_disk.empty()) {
    LOG(ERROR) << "Invalid root disk for GetDevicesToWipe";
    return false;
  }

  if (root_device.empty()) {
    LOG(ERROR) << "Invalid root device for GetDevicesToWipe";
    return false;
  }

  std::string base_device;
  int active_root_partition;
  if (!GetDevicePathComponents(root_device, &base_device,
                               &active_root_partition)) {
    LOG(ERROR) << "Extracting partition number and base device from "
                  "root_device failed: "
               << root_device.value();
    return false;
  }

  ClobberState::DeviceWipeInfo wipe_info;
  if (active_root_partition == partitions.root_a) {
    wipe_info.inactive_root_device =
        base::FilePath(base_device + std::to_string(partitions.root_b));
    wipe_info.inactive_kernel_device =
        base::FilePath(base_device + std::to_string(partitions.kernel_b));
    wipe_info.active_kernel_partition = partitions.kernel_a;
  } else if (active_root_partition == partitions.root_b) {
    wipe_info.inactive_root_device =
        base::FilePath(base_device + std::to_string(partitions.root_a));
    wipe_info.inactive_kernel_device =
        base::FilePath(base_device + std::to_string(partitions.kernel_a));
    wipe_info.active_kernel_partition = partitions.kernel_b;
  } else {
    LOG(ERROR) << "Active root device partition number ("
               << active_root_partition
               << ") does not match either root partition number: "
               << partitions.root_a << ", " << partitions.root_b;
    return false;
  }

  base::FilePath kernel_device;
  if (root_disk == base::FilePath(kUbiRootDisk)) {
    /*
     * WARNING: This code has not been sufficiently tested and almost certainly
     * does not work. If you are adding support for MTD flash, you would be
     * well served to review it and add test coverage.
     */

    // Special casing for NAND devices.
    wipe_info.is_mtd_flash = true;
    wipe_info.stateful_partition_device = base::FilePath(
        base::StringPrintf(kUbiDeviceStatefulFormat, partitions.stateful));

    // On NAND, kernel is stored on /dev/mtdX.
    if (active_root_partition == partitions.root_a) {
      kernel_device =
          base::FilePath("/dev/mtd" + std::to_string(partitions.kernel_a));
    } else if (active_root_partition == partitions.root_b) {
      kernel_device =
          base::FilePath("/dev/mtd" + std::to_string(partitions.kernel_b));
    }

    /*
     * End of untested MTD code.
     */
  } else {
    wipe_info.stateful_partition_device =
        base::FilePath(base_device + std::to_string(partitions.stateful));

    if (active_root_partition == partitions.root_a) {
      kernel_device =
          base::FilePath(base_device + std::to_string(partitions.kernel_a));
    } else if (active_root_partition == partitions.root_b) {
      kernel_device =
          base::FilePath(base_device + std::to_string(partitions.kernel_b));
    }
  }

  *wipe_info_out = wipe_info;
  return true;
}

// static
bool ClobberState::WipeMTDDevice(
    const base::FilePath& device_path,
    const ClobberState::PartitionNumbers& partitions) {
  /*
   * WARNING: This code has not been sufficiently tested and almost certainly
   * does not work. If you are adding support for MTD flash, you would be
   * well served to review it and add test coverage.
   */

  if (!base::StartsWith(device_path.value(), kUbiDevicePrefix,
                        base::CompareCase::SENSITIVE)) {
    LOG(ERROR) << "Cannot wipe device " << device_path.value();
    return false;
  }

  std::string base_device;
  int partition_number;
  if (!GetDevicePathComponents(device_path, &base_device, &partition_number)) {
    LOG(ERROR) << "Getting partition number from device failed: "
               << device_path.value();
    return false;
  }

  std::string partition_name;
  if (partition_number == partitions.stateful) {
    partition_name = "STATE";
  } else if (partition_number == partitions.root_a) {
    partition_name = "ROOT-A";
  } else if (partition_number == partitions.root_b) {
    partition_name = "ROOT-B";
  } else {
    partition_name = base::StringPrintf("UNKNOWN_%d", partition_number);
    LOG(ERROR) << "Do not know how to name UBI partition for "
               << device_path.value();
  }

  std::string physical_device =
      base::StringPrintf("/dev/ubi%d", partition_number);
  struct stat st;
  stat(physical_device.c_str(), &st);
  if (!S_ISCHR(st.st_mode)) {
    // Try to attach the volume to obtain info about it.
    brillo::ProcessImpl ubiattach;
    ubiattach.AddArg("/bin/ubiattach");
    ubiattach.AddIntOption("-m", partition_number);
    ubiattach.AddIntOption("-d", partition_number);
    ubiattach.RedirectOutputToMemory(true);
    ubiattach.Run();
    AppendToLog("ubiattach", ubiattach.GetOutputString(STDOUT_FILENO));
  }

  int max_bad_blocks_per_1024 =
      CalculateUBIMaxBadBlocksPer1024(partition_number);

  int volume_size;
  base::FilePath data_bytes(base::StringPrintf(
      "/sys/class/ubi/ubi%d_0/data_bytes", partition_number));
  utils::ReadFileToInt(data_bytes, &volume_size);

  brillo::ProcessImpl ubidetach;
  ubidetach.AddArg("/bin/ubidetach");
  ubidetach.AddIntOption("-d", partition_number);
  ubidetach.RedirectOutputToMemory(true);
  int detach_ret = ubidetach.Run();
  AppendToLog("ubidetach", ubidetach.GetOutputString(STDOUT_FILENO));
  if (detach_ret) {
    LOG(ERROR) << "Detaching MTD volume failed with code " << detach_ret;
  }

  brillo::ProcessImpl ubiformat;
  ubiformat.AddArg("/bin/ubiformat");
  ubiformat.AddArg("-y");
  ubiformat.AddIntOption("-e", 0);
  ubiformat.AddArg(base::StringPrintf("/dev/mtd%d", partition_number));
  ubiformat.RedirectOutputToMemory(true);
  int format_ret = ubiformat.Run();
  AppendToLog("ubiformat", ubiformat.GetOutputString(STDOUT_FILENO));
  if (format_ret) {
    LOG(ERROR) << "Formatting MTD volume failed with code " << format_ret;
  }

  // We need to attach so that we could set max beb/1024 and create a volume.
  // After a volume is created, we don't need to specify max beb/1024 anymore.
  brillo::ProcessImpl ubiattach;
  ubiattach.AddArg("/bin/ubiattach");
  ubiattach.AddIntOption("-d", partition_number);
  ubiattach.AddIntOption("-m", partition_number);
  ubiattach.AddIntOption("--max-beb-per1024", max_bad_blocks_per_1024);
  ubiattach.RedirectOutputToMemory(true);
  int attach_ret = ubiattach.Run();
  AppendToLog("ubiattach", ubiattach.GetOutputString(STDOUT_FILENO));
  if (attach_ret) {
    LOG(ERROR) << "Reattaching MTD volume failed with code " << attach_ret;
  }

  brillo::ProcessImpl ubimkvol;
  ubimkvol.AddArg("/bin/ubimkvol");
  ubimkvol.AddIntOption("-s", volume_size);
  ubimkvol.AddStringOption("-N", partition_name);
  ubimkvol.AddArg(physical_device);
  ubimkvol.RedirectOutputToMemory(true);
  int mkvol_ret = ubimkvol.Run();
  AppendToLog("ubimkvol", ubimkvol.GetOutputString(STDOUT_FILENO));
  if (mkvol_ret) {
    LOG(ERROR) << "Making MTD volume failed with code " << mkvol_ret;
  }

  return detach_ret == 0 && format_ret == 0 && attach_ret == 0 &&
         mkvol_ret == 0;

  /*
   * End of untested MTD code.
   */
}

// static
bool ClobberState::WipeBlockDevice(const base::FilePath& device_path,
                                   ClobberUi* ui,
                                   bool fast,
                                   bool discard) {
  const int write_block_size = 4 * 1024 * 1024;
  int64_t to_write = 0;

  struct stat st;
  if (stat(device_path.value().c_str(), &st) == -1) {
    PLOG(ERROR) << "Unable to stat " << device_path.value();
    return false;
  }

  if (fast) {
    to_write = write_block_size;
  } else {
    // Wipe the filesystem size if we can determine it. Full partition wipe
    // takes a long time on 16G SSD or rotating media.
    int64_t block_size = st.st_blksize;
    int64_t block_count;
    if (!GetBlockCount(device_path, block_size, &block_count)) {
      LOG(ERROR) << "Unable to get block count for " << device_path.value();
      return false;
    }
    to_write = block_count * block_size;
    LOG(INFO) << "Filesystem block size: " << block_size;
    LOG(INFO) << "Filesystem block count: " << block_count;
  }

  LOG(INFO) << "Wiping block device " << device_path.value()
            << (fast ? " (fast) " : "");
  LOG(INFO) << "Number of bytes to write: " << to_write;

  base::File device(open(device_path.value().c_str(), O_WRONLY | O_SYNC));
  if (!device.IsValid()) {
    PLOG(ERROR) << "Unable to open " << device_path.value();
    return false;
  }

  // Don't display progress in fast mode since it runs so quickly.
  bool display_progress = !fast;
  base::ScopedClosureRunner stop_wipe_ui;
  if (display_progress) {
    if (ui->StartWipeUi(to_write)) {
      stop_wipe_ui.ReplaceClosure(
          base::BindOnce([](ClobberUi* ui) { ui->StopWipeUi(); }, ui));
    } else {
      display_progress = false;
    }
  }

  uint64_t total_written = 0;

  // We call wiping in chunks 5% (1/20th) of the disk size so that we can
  // update progress as we go. Round up the chunk size to a multiple of 128MiB,
  // since the wiping ioctl requires that its arguments are aligned to at least
  // 512 bytes.
  const uint64_t zero_block_size = base::bits::AlignUp(
      static_cast<uint64_t>(to_write / 20), uint64_t{128 * 1024 * 1024});
  const uint64_t zero_block_size_1mib = base::bits::AlignUp(
      static_cast<uint64_t>(to_write / 20), uint64_t{1024 * 1024});

  base::FilePath base_dev =
      brillo::GetBackingPhysicalDeviceForBlock(st.st_rdev);
  std::unique_ptr<brillo::StorageDevice> storage_device =
      brillo::GetStorageDevice(base_dev);
  while (total_written < to_write) {
    uint64_t write_size = std::min(zero_block_size, to_write - total_written);
    // For `discard` case, chunk smaller for first 128MiB wipes.
    if (discard && total_written < zero_block_size) {
      write_size = std::min(zero_block_size_1mib, to_write - total_written);
    }
    if (!storage_device->WipeBlkDev(device_path, total_written, write_size,
                                    false, discard)) {
      break;
    }
    total_written += write_size;
    if (display_progress) {
      ui->UpdateWipeProgress(total_written);
    }
  }

  if (total_written == to_write) {
    LOG(INFO) << "Successfully zeroed " << to_write << " bytes on "
              << device_path.value();
    return true;
  }
  LOG(INFO) << "Reverting to manual wipe for bytes " << total_written
            << " through " << to_write;

  const std::vector<char> buffer(write_block_size, '\0');
  while (total_written < to_write) {
    int write_size = std::min(static_cast<uint64_t>(write_block_size),
                              to_write - total_written);
    int64_t bytes_written = device.WriteAtCurrentPos(buffer.data(), write_size);
    if (bytes_written < 0) {
      PLOG(ERROR) << "Failed to write to " << device_path.value();
      LOG(ERROR) << "Wrote " << total_written << " bytes before failing";
      return false;
    }
    if (discard && !storage_device->DiscardBlockDevice(
                       device_path, total_written, write_size)) {
      PLOG(ERROR) << "Failed to discard blocks of " << device_path.value()
                  << " at offset=" << total_written << " size=" << write_size;
      return false;
    }
    total_written += bytes_written;
    if (display_progress) {
      ui->UpdateWipeProgress(total_written);
    }
  }
  LOG(INFO) << "Successfully wrote " << total_written << " bytes to "
            << device_path.value();

  return true;
}

// static
void ClobberState::RemoveVpdKeys() {
  constexpr std::array<const char*, 1> keys_to_remove{
      // This key is used for caching the feature level.
      // Need to remove it, as it must be recalculated when re-entering normal
      // mode.
      "feature_device_info",
  };
  for (auto key : keys_to_remove) {
    brillo::ProcessImpl vpd;
    vpd.AddArg("/usr/sbin/vpd");
    vpd.AddStringOption("-i", "RW_VPD");
    vpd.AddStringOption("-d", key);
    // Do not report failures as the key might not even exist in the VPD.
    vpd.RedirectOutputToMemory(true);
    vpd.Run();
    AppendToLog("vpd", vpd.GetOutputString(STDOUT_FILENO));
  }
}

ClobberState::ClobberState(const Arguments& args,
                           std::unique_ptr<CrosSystem> cros_system,
                           std::unique_ptr<ClobberUi> ui,
                           std::unique_ptr<brillo::LogicalVolumeManager> lvm)
    : args_(args),
      cros_system_(std::move(cros_system)),
      ui_(std::move(ui)),
      stateful_(kStatefulPath),
      dev_("/dev"),
      sys_("/sys"),
      lvm_(std::move(lvm)),
      weak_ptr_factory_(this) {}

std::vector<base::FilePath> ClobberState::GetPreservedFilesList() {
  std::vector<std::string> stateful_paths;
  // Preserve these files in safe mode. (Please request a privacy review before
  // adding files.)
  //
  // - unencrypted/preserve/update_engine/prefs/rollback-happened: Contains a
  //   boolean value indicating whether a rollback has happened since the last
  //   update check where device policy was available. Needed to avoid forced
  //   updates after rollbacks (device policy is not yet loaded at this time).
  if (args_.safe_wipe) {
    stateful_paths.push_back(kPowerWashCountPath);
    stateful_paths.push_back(
        "unencrypted/preserve/tpm_firmware_update_request");
    stateful_paths.push_back(std::string(kUpdateEnginePreservePath) +
                             "rollback-happened");
    stateful_paths.push_back(std::string(kUpdateEnginePreservePath) +
                             "rollback-version");

    stateful_paths.push_back(std::string(kUpdateEnginePreservePath) +
                             std::string(kLastPingDate));
    stateful_paths.push_back(std::string(kUpdateEnginePreservePath) +
                             std::string(kLastRollcallDate));
    // Preserve the device last active dates to Private Set Computing (psm).
    stateful_paths.push_back(kPsmDeviceActivePreservePath);

    // For the Chromad to cloud migration, we store a flag file to indicate that
    // some OOBE screens should be skipped after the device is powerwashed.
    if (args_.ad_migration_wipe) {
      stateful_paths.push_back(kChromadMigrationSkipOobePreservePath);
    }

    // Preserve pre-installed demo mode resources for offline Demo Mode.
    std::string demo_mode_resources_dir =
        "unencrypted/cros-components/offline-demo-mode-resources/";
    stateful_paths.push_back(demo_mode_resources_dir + "image.squash");
    stateful_paths.push_back(demo_mode_resources_dir + "imageloader.json");
    stateful_paths.push_back(demo_mode_resources_dir + "imageloader.sig.1");
    stateful_paths.push_back(demo_mode_resources_dir + "imageloader.sig.2");
    stateful_paths.push_back(demo_mode_resources_dir + "manifest.fingerprint");
    stateful_paths.push_back(demo_mode_resources_dir + "manifest.json");
    stateful_paths.push_back(demo_mode_resources_dir + "table");

    // For rollback wipes, we preserve additional data as defined in
    // oobe_config/rollback_data.proto.
    if (args_.rollback_wipe) {
      // Devices produced >= 2023 use the new rollback data
      // ("rollback_data_tpm") encryption.
      stateful_paths.push_back("unencrypted/preserve/rollback_data_tpm");
      // TODO(b/263065223) Preservation of the old format ("rollback_data") can
      // be removed when all devices produced before 2023 are EOL.
      stateful_paths.push_back("unencrypted/preserve/rollback_data");
    }

    // Preserve the latest GSC crash ID to prevent uploading previously seen GSC
    // crashes on every boot.
    stateful_paths.push_back("unencrypted/preserve/gsc_prev_crash_log_id");
  }

  // Preserve RMA state file in RMA mode.
  if (args_.rma_wipe) {
    stateful_paths.push_back(kRmaStateFilePath);
  }

  // Test images in the lab enable certain extra behaviors if the
  // .labmachine flag file is present.  Those behaviors include some
  // important recovery behaviors (cf. the recover_duts upstart job).
  // We need those behaviors to survive across power wash, otherwise,
  // the current boot could wind up as a black hole.
  int debug_build;
  if (cros_system_->GetInt(CrosSystem::kDebugBuild, &debug_build) &&
      debug_build == 1) {
    stateful_paths.push_back(".labmachine");
  }

  std::vector<base::FilePath> preserved_files;
  for (const std::string& path : stateful_paths) {
    preserved_files.push_back(base::FilePath(path));
  }

  if (args_.factory_wipe) {
    base::FileEnumerator crx_enumerator(
        stateful_.Append("unencrypted/import_extensions/extensions"), false,
        base::FileEnumerator::FileType::FILES, "*.crx");
    for (base::FilePath name = crx_enumerator.Next(); !name.empty();
         name = crx_enumerator.Next()) {
      preserved_files.push_back(
          base::FilePath("unencrypted/import_extensions/extensions")
              .Append(name.BaseName()));
    }

    base::FileEnumerator dlc_enumerator(
        stateful_.Append("unencrypted/dlc-factory-images"), false,
        base::FileEnumerator::DIRECTORIES);
    for (base::FilePath dir = dlc_enumerator.Next(); !dir.empty();
         dir = dlc_enumerator.Next()) {
      base::FilePath dlc_image_path =
          base::FilePath("unencrypted/dlc-factory-images")
              .Append(dir.BaseName())
              .Append("package")
              .Append("dlc.img");
      if (base::PathExists(stateful_.Append(dlc_image_path))) {
        preserved_files.push_back(dlc_image_path);
      }
    }
  }

  return preserved_files;
}

// Use a random 16 character name for the volume group.
std::string ClobberState::GenerateRandomVolumeGroupName() {
  const char kCharset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  unsigned char vg_random_value[kVolumeGroupNameSize];
  crypto::RandBytes(vg_random_value, kVolumeGroupNameSize);

  std::string vg_name(kVolumeGroupNameSize, '0');
  for (int i = 0; i < kVolumeGroupNameSize; ++i) {
    vg_name[i] = kCharset[vg_random_value[i] % 36];
  }
  return vg_name;
}

void ClobberState::RemoveLogicalVolumeStack() {
  // For logical volume stateful partition, deactivate the volume group before
  // wiping the device.
  std::optional<brillo::PhysicalVolume> pv = lvm_->GetPhysicalVolume(
      base::FilePath(wipe_info_.stateful_partition_device));
  if (!pv || !pv->IsValid()) {
    LOG(WARNING) << "Failed to get physical volume.";
    return;
  }
  std::optional<brillo::VolumeGroup> vg = lvm_->GetVolumeGroup(*pv);
  if (!vg || !vg->IsValid()) {
    LOG(WARNING) << "Failed to get volume group.";
    return;
  }

  LOG(INFO) << "Deactivating volume group.";
  vg->Deactivate();
  LOG(INFO) << "Removing volume group.";
  vg->Remove();
  LOG(INFO) << "Removing physical volume.";
  pv->Remove();
}

bool ClobberState::ProcessInfo(const brillo::VolumeGroup& vg,
                               const PreserveLogicalVolumesWipeInfo& info) {
  auto lv = lvm_->GetLogicalVolume(vg, info.lv_name);
  if (!lv || !lv->IsValid()) {
    LOG(INFO) << "Skipping over logical volume: " << info.lv_name;
    return true;
  }

  // Zero the logical volume.
  if (info.zero) {
    if (!WipeDevice(lv->GetPath(), /*discard=*/true)) {
      LOG(ERROR) << "Failed to wipe logical volume: " << info.lv_name;
      return false;
    }
  }

  // Preserve the logical volume.
  if (info.preserve) {
    LOG(INFO) << "Preserving logical volume: " << info.lv_name;
  } else if (!lv->Remove()) {
    LOG(ERROR) << "Failed to remove logical volume: " << info.lv_name;
    return false;
  }

  return true;
}

bool ClobberState::PreserveLogicalVolumesWipe(
    const PreserveLogicalVolumesWipeInfos& infos) {
  auto pv = lvm_->GetPhysicalVolume({wipe_info_.stateful_partition_device});
  if (!pv || !pv->IsValid()) {
    LOG(WARNING) << "Failed to get physical volume.";
    return false;
  }
  auto vg = lvm_->GetVolumeGroup(*pv);
  if (!vg || !vg->IsValid()) {
    LOG(WARNING) << "Failed to get volume group.";
    return false;
  }

  // Remove all logical volumes we don't need to handle with care.
  for (auto& lv : lvm_->ListLogicalVolumes(*vg)) {
    const auto& lv_raw_name = lv.GetRawName();
    auto it = infos.find({.lv_name = lv_raw_name});
    bool found = it != infos.end();

    if (found)
      continue;

    if (!lv.Remove()) {
      LOG(ERROR) << "Failed to remove logical volume: " << lv_raw_name;
      return false;
    }
  }

  // We must handle logical volume with additional care based on the
  // `PreserveLogicalVolumesWipeInfo`.
  for (const auto& info : infos) {
    if (info.lv_name == kUnencrypted)
      continue;
    if (!ProcessInfo(*vg, info))
      return false;
  }
  // Note: Always process unencrypted stateful last.
  // This is so when there are crashes, the powerwash file is still accessible
  // within unencrypted logical volume to go through and perform the powerwash
  // again.
  {
    auto lv_name = kUnencrypted;
    auto info_it = infos.find({.lv_name = lv_name});
    if (info_it == infos.end()) {
      LOG(ERROR) << "Missing " << lv_name
                 << " in preserve logical volumes wipe info.";
      return false;
    }
    if (!ProcessInfo(*vg, *info_it))
      return false;
  }

  auto old_vg_name = vg->GetName();
  auto new_vg_name = GenerateRandomVolumeGroupName();
  if (!vg->Rename(new_vg_name)) {
    LOG(ERROR) << "Failed to rename volume group from=" << old_vg_name
               << " to=" << new_vg_name;
    return false;
  }

  return true;
}

void ClobberState::CreateUnencryptedStatefulLV(const brillo::VolumeGroup& vg,
                                               const brillo::Thinpool& thinpool,
                                               uint64_t lv_size) {
  base::Value::Dict lv_config;
  lv_config.Set("name", kUnencrypted);
  lv_config.Set("size", base::NumberToString(lv_size));

  std::optional<brillo::LogicalVolume> lv =
      lvm_->CreateLogicalVolume(vg, thinpool, lv_config);
  if (!lv || !lv->IsValid()) {
    LOG(ERROR) << "Failed to create " << kUnencrypted << " logical volume.";
    return;
  }

  lv->Activate();
}

std::optional<uint64_t> ClobberState::GetPartitionSize(
    const base::FilePath& base_device) {
  uint64_t partition_size = GetBlkSize(base_device) / (1024 * 1024);
  if (partition_size < kMinStatefulPartitionSizeMb) {
    LOG(ERROR) << "Invalid partition size (" << partition_size
               << ") for: " << base_device.value();
    return std::nullopt;
  }
  return {partition_size};
}

void ClobberState::CreateLogicalVolumeStackForPreserved() {
  std::optional<uint64_t> partition_size =
      GetPartitionSize(wipe_info_.stateful_partition_device);
  if (!partition_size) {
    LOG(ERROR) << "Failed to get partition size.";
    return;
  }

  auto pv = lvm_->GetPhysicalVolume({wipe_info_.stateful_partition_device});
  if (!pv || !pv->IsValid()) {
    LOG(WARNING) << "Failed to get physical volume.";
    return;
  }

  auto vg = lvm_->GetVolumeGroup(*pv);
  if (!vg || !vg->IsValid()) {
    LOG(WARNING) << "Failed to get volume group.";
    return;
  }

  wipe_info_.stateful_filesystem_device = base::FilePath(
      base::StringPrintf("/dev/%s/unencrypted", vg->GetName().c_str()));

  std::optional<brillo::Thinpool> thinpool = lvm_->GetThinpool(*vg, kThinpool);
  if (!thinpool || !thinpool->IsValid()) {
    LOG(ERROR) << "Failed to get thinpool.";
    return;
  }

  int64_t thinpool_size = partition_size.value() * kThinpoolSizePercent / 100;
  uint64_t lv_size = thinpool_size * kLogicalVolumeSizePercent / 100;
  CreateUnencryptedStatefulLV(*vg, *thinpool, lv_size);
}

void ClobberState::CreateLogicalVolumeStack() {
  base::FilePath base_device = wipe_info_.stateful_partition_device;
  std::string vg_name = GenerateRandomVolumeGroupName();
  wipe_info_.stateful_filesystem_device = base::FilePath(
      base::StringPrintf("/dev/%s/unencrypted", vg_name.c_str()));

  // Get partition size to determine the sizes of the thin pool and the
  // logical volume. Use partition size in megabytes: thinpool (and logical
  // volume) sizes need to be a multiple of 512.
  std::optional<uint64_t> partition_size = GetPartitionSize(base_device);
  if (!partition_size) {
    LOG(ERROR) << "Failed to get partition size.";
    return;
  }

  std::optional<brillo::PhysicalVolume> pv =
      lvm_->CreatePhysicalVolume(base_device);

  if (!pv || !pv->IsValid()) {
    LOG(ERROR) << "Failed to create physical volume.";
    return;
  }

  std::optional<brillo::VolumeGroup> vg = lvm_->CreateVolumeGroup(*pv, vg_name);
  if (!vg || !vg->IsValid()) {
    LOG(ERROR) << "Failed to create volume group.";
    return;
  }

  vg->Activate();

  base::Value thinpool_config(base::Value::Type::DICT);
  int64_t thinpool_size = partition_size.value() * kThinpoolSizePercent / 100;
  int64_t thinpool_metadata_size =
      thinpool_size * kThinpoolMetadataSizePercent / 100;
  auto& dict = thinpool_config.GetDict();
  dict.Set("name", kThinpool);
  dict.Set("size", base::NumberToString(thinpool_size));
  dict.Set("metadata_size", base::NumberToString(thinpool_metadata_size));

  std::optional<brillo::Thinpool> thinpool =
      lvm_->CreateThinpool(*vg, thinpool_config);
  if (!thinpool || !thinpool->IsValid()) {
    LOG(ERROR) << "Failed to create thinpool.";
    return;
  }

  uint64_t lv_size = thinpool_size * kLogicalVolumeSizePercent / 100;
  CreateUnencryptedStatefulLV(*vg, *thinpool, lv_size);
}

int ClobberState::CreateStatefulFileSystem(
    const std::string& stateful_filesystem_device) {
  brillo::ProcessImpl mkfs;
  if (wipe_info_.is_mtd_flash) {
    mkfs.AddArg("/sbin/mkfs.ubifs");
    mkfs.AddArg("-y");
    mkfs.AddStringOption("-x", "none");
    mkfs.AddIntOption("-R", 0);
    mkfs.AddArg(stateful_filesystem_device);
  } else {
    mkfs.AddArg("/sbin/mkfs.ext4");
    // Check if encryption is supported. If yes, enable the flag during mkfs.
    if (base::PathExists(base::FilePath(kExt4DircryptoSupportedPath)))
      mkfs.AddStringOption("-O", "encrypt");
    mkfs.AddArg(stateful_filesystem_device);
    // TODO(wad) tune2fs.
  }
  mkfs.RedirectOutputToMemory(true);
  LOG(INFO) << "Creating stateful file system";
  int ret = mkfs.Run();
  AppendToLog("mkfs.ubifs", mkfs.GetOutputString(STDOUT_FILENO));
  return ret;
}

int ClobberState::Run() {
  DCHECK(cros_system_);

  wipe_start_time_ = base::TimeTicks::Now();

  // Defer callback to relocate log file back to stateful partition so that it
  // will be preserved after a reboot.
  base::ScopedClosureRunner relocate_clobber_state_log(base::BindRepeating(
      [](base::FilePath stateful_path) {
        base::Move(base::FilePath(kClobberLogPath),
                   stateful_path.Append("unencrypted/clobber-state.log"));
      },
      stateful_));

  // Check if this powerwash was triggered by a session manager request.
  // StartDeviceWipe D-Bus call is restricted to "chronos" so it is probably
  // safe to assume that such requests were initiated by the user.
  bool user_triggered_powerwash =
      (args_.reason.find("session_manager_dbus_request") != std::string::npos);

  // Allow crash preservation across clobber if the device is in developer mode.
  // For testing purposes, use a tmpfs path to disable collection.
  bool preserve_dev_mode_crash_reports =
      IsInDeveloperMode() &&
      !base::PathExists(base::FilePath(kDisableClobberCrashCollectionPath));

  // Check if sensitive files should be preserved. Sensitive files should be
  // preserved if any of the following conditions are met:
  // 1. The device is in developer mode and crash report collection is allowed.
  // 2. The request doesn't originate from a user-triggered powerwash.
  bool preserve_sensitive_files =
      !user_triggered_powerwash || preserve_dev_mode_crash_reports;

  // True if we should ensure that this powerwash takes at least 5 minutes.
  // Saved here because we may switch to using a fast wipe later, but we still
  // want to enforce the delay in that case.
  bool should_force_delay = !args_.fast_wipe && !args_.factory_wipe;

  LOG(INFO) << "Beginning clobber-state run";
  LOG(INFO) << "Factory wipe: " << args_.factory_wipe;
  LOG(INFO) << "Fast wipe: " << args_.fast_wipe;
  LOG(INFO) << "Keepimg: " << args_.keepimg;
  LOG(INFO) << "Safe wipe: " << args_.safe_wipe;
  LOG(INFO) << "Rollback wipe: " << args_.rollback_wipe;
  LOG(INFO) << "Reason: " << args_.reason;
  LOG(INFO) << "RMA wipe: " << args_.rma_wipe;
  LOG(INFO) << "AD migration wipe: " << args_.ad_migration_wipe;

  // Most effective means of destroying user data is run at the start: Throwing
  // away the key to encrypted stateful by requesting the TPM to be cleared at
  // next boot.
  if (!cros_system_->SetInt(CrosSystem::kClearTpmOwnerRequest, 1)) {
    LOG(ERROR) << "Requesting TPM wipe via crossystem failed";
  }

  // In cases where biometric sensors are available, reset the internal entropy
  // used by those sensors for encryption, to render related data/templates etc.
  // undecipherable.
  if (!ClearBiometricSensorEntropy()) {
    LOG(ERROR) << "Clearing biometric sensor internal entropy failed";
  }

  // Try to mount encrypted stateful to save some files from there.
  bool encrypted_stateful_mounted = false;

  // Update Engine and OOBE config utilities require preservation of files in
  // /var across powerwash. Attempt to mount the encrypted stateful partition
  // if:
  // 1. The encrypted stateful partition is enabled on the device.
  // 2. clobber-state is not running in factory mode: mount-encrypted is not
  //    accessible within the factory environment.
  // Failure to mount the encrypted stateful partition prevents the preservation
  // of these files across powerwash, but functionally does not affect clobber.
  encrypted_stateful_mounted =
      USE_ENCRYPTED_STATEFUL && !args_.factory_wipe && MountEncryptedStateful();

  if (args_.safe_wipe) {
    IncrementFileCounter(stateful_.Append(kPowerWashCountPath));
    if (encrypted_stateful_mounted) {
      base::FilePath preserve_path =
          stateful_.Append(kUpdateEnginePreservePath);
      base::FilePath prefs_path(kUpdateEnginePrefsPath);
      base::CopyFile(prefs_path.Append(kLastPingDate),
                     preserve_path.Append(kLastPingDate));
      base::CopyFile(prefs_path.Append(kLastRollcallDate),
                     preserve_path.Append(kLastRollcallDate));

      // Preserve the psm device active dates when the device is powerwashed.
      base::FilePath psm_local_pref_file(kPsmDeviceActiveLocalPrefPath);
      base::FilePath psm_preserved_pref_file(
          stateful_.Append(kPsmDeviceActivePreservePath));
      base::CopyFile(psm_local_pref_file, psm_preserved_pref_file);
    }
  }

  // Clear clobber log if needed.
  if (!preserve_sensitive_files) {
    brillo::DeleteFile(stateful_.Append(kStatefulClobberLogPath));
  }

  std::vector<base::FilePath> preserved_files = GetPreservedFilesList();
  for (const base::FilePath& fp : preserved_files) {
    LOG(INFO) << "Preserving file: " << fp.value();
  }

  base::FilePath preserved_tar_file(kPreservedFilesTarPath);
  int ret = PreserveFiles(stateful_, preserved_files, preserved_tar_file);
  if (ret) {
    LOG(ERROR) << "Preserving files failed with code " << ret;
  }

  if (encrypted_stateful_mounted) {
    // Preserve a rollback data file separately as it's sensitive and must not
    // be stored unencrypted on the hard drive.
    if (args_.rollback_wipe) {
      MoveRollbackFileToPstore();
    }
    UnmountEncryptedStateful();
  }

  // As we move factory wiping from release image to factory test image,
  // clobber-state will be invoked directly under a tmpfs. GetRootDevice cannot
  // report correct output under such a situation. Therefore, the output is
  // preserved then assigned to environment variables ROOT_DEV/ROOT_DISK for
  // clobber-state. For other cases, the environment variables will be empty and
  // it falls back to using GetRootDevice.
  const char* root_disk_cstr = getenv("ROOT_DISK");
  if (root_disk_cstr != nullptr) {
    root_disk_ = base::FilePath(root_disk_cstr);
  } else {
    root_disk_ = GetRootDevice(/*strip_partition=*/true);
  }

  // Special casing for NAND devices
  if (base::StartsWith(root_disk_.value(), kUbiDevicePrefix,
                       base::CompareCase::SENSITIVE)) {
    root_disk_ = base::FilePath(kUbiRootDisk);
  }

  base::FilePath root_device;
  const char* root_device_cstr = getenv("ROOT_DEV");
  if (root_device_cstr != nullptr) {
    root_device = base::FilePath(root_device_cstr);
  } else {
    root_device = GetRootDevice(/*strip_partition=*/false);
  }

  LOG(INFO) << "Root disk: " << root_disk_.value();
  LOG(INFO) << "Root device: " << root_device.value();

  partitions_.stateful = utils::GetPartitionNumber(root_disk_, "STATE");
  partitions_.root_a = utils::GetPartitionNumber(root_disk_, "ROOT-A");
  partitions_.root_b = utils::GetPartitionNumber(root_disk_, "ROOT-B");
  partitions_.kernel_a = utils::GetPartitionNumber(root_disk_, "KERN-A");
  partitions_.kernel_b = utils::GetPartitionNumber(root_disk_, "KERN-B");

  if (!GetDevicesToWipe(root_disk_, root_device, partitions_, &wipe_info_)) {
    LOG(ERROR) << "Getting devices to wipe failed, aborting run";
    return 1;
  }

  // Determine if stateful partition's device is backed by a rotational disk.
  bool is_rotational = false;
  if (!wipe_info_.is_mtd_flash) {
    is_rotational = IsRotational(wipe_info_.stateful_partition_device);
  }

  LOG(INFO) << "Stateful device: "
            << wipe_info_.stateful_partition_device.value();
  LOG(INFO) << "Inactive root device: "
            << wipe_info_.inactive_root_device.value();
  LOG(INFO) << "Inactive kernel device: "
            << wipe_info_.inactive_kernel_device.value();

  brillo::ProcessImpl log_preserve;
  log_preserve.AddArg("/sbin/clobber-log");
  log_preserve.AddArg("--preserve");
  log_preserve.AddArg("clobber-state");

  if (args_.factory_wipe)
    log_preserve.AddArg("factory");
  if (args_.fast_wipe)
    log_preserve.AddArg("fast");
  if (args_.keepimg)
    log_preserve.AddArg("keepimg");
  if (args_.safe_wipe)
    log_preserve.AddArg("safe");
  if (args_.rollback_wipe)
    log_preserve.AddArg("rollback");
  if (!args_.reason.empty())
    log_preserve.AddArg(args_.reason);
  if (args_.rma_wipe)
    log_preserve.AddArg("rma");
  if (args_.ad_migration_wipe)
    log_preserve.AddArg("ad_migration");

  log_preserve.RedirectOutputToMemory(true);
  log_preserve.Run();
  AppendToLog("clobber-log", log_preserve.GetOutputString(STDOUT_FILENO));

  AttemptSwitchToFastWipe(is_rotational);

  // Make sure the stateful partition has been unmounted.
  UnmountStateful(stateful_);

  base::ScopedClosureRunner reset_stateful(base::BindOnce(
      &ClobberState::ResetStatefulPartition, weak_ptr_factory_.GetWeakPtr()));

  if (args_.preserve_lvs) {
    if (!PreserveLogicalVolumesWipe(PreserveLogicalVolumesWipeArgs())) {
      args_.preserve_lvs = false;
      LOG(WARNING) << "Preserve logical voluems wipe failed "
                   << "(falling back to default LVM stateful wipe).";
    } else {
      LOG(INFO) << "Preserve logical volumes, skipping device level wipe.";
      reset_stateful.ReplaceClosure(base::DoNothing());
    }
  }

  reset_stateful.RunAndReset();

  // `preserve_lvs` precedence check over `setup_lvm`.
  if (args_.preserve_lvs) {
    CreateLogicalVolumeStackForPreserved();
  } else if (args_.setup_lvm) {
    CreateLogicalVolumeStack();
  } else {
    // Set up the stateful filesystem on top of the stateful partition.
    wipe_info_.stateful_filesystem_device =
        wipe_info_.stateful_partition_device;
  }

  ret = CreateStatefulFileSystem(wipe_info_.stateful_filesystem_device.value());
  if (ret)
    LOG(ERROR) << "Unable to create stateful file system. Error code: " << ret;

  // Mount the fresh image for last minute additions.
  std::string file_system_type = wipe_info_.is_mtd_flash ? "ubifs" : "ext4";
  if (mount(wipe_info_.stateful_filesystem_device.value().c_str(),
            stateful_.value().c_str(), file_system_type.c_str(), 0,
            nullptr) != 0) {
    PLOG(ERROR) << "Unable to mount stateful partition at "
                << stateful_.value();
  }

  if (base::PathExists(preserved_tar_file)) {
    brillo::ProcessImpl tar;
    tar.AddArg("/bin/tar");
    tar.AddStringOption("-C", stateful_.value());
    tar.AddArg("-x");
    tar.AddStringOption("-f", preserved_tar_file.value());
    tar.RedirectOutputToMemory(true);
    ret = tar.Run();
    AppendToLog("tar", tar.GetOutputString(STDOUT_FILENO));
    if (ret != 0) {
      LOG(WARNING) << "Restoring preserved files failed with code " << ret;
    }
    base::WriteFile(stateful_.Append("unencrypted/.powerwash_completed"), "",
                    0);
    // TODO(b/190143108) Add one unit test in the context of
    // ClobberState::Run() to check the powerwash time file existence.
    if (!WriteLastPowerwashTime(stateful_.Append(kLastPowerWashTimePath),
                                base::Time::Now())) {
      PLOG(WARNING) << "Write the last_powerwash_time to file failed";
    }
  }

  brillo::ProcessImpl log_restore;
  log_restore.AddArg("/sbin/clobber-log");
  log_restore.AddArg("--restore");
  log_restore.AddArg("clobber-state");
  log_restore.RedirectOutputToMemory(true);
  ret = log_restore.Run();
  AppendToLog("clobber-log", log_restore.GetOutputString(STDOUT_FILENO));
  if (ret != 0) {
    LOG(WARNING) << "Restoring clobber.log failed with code " << ret;
  }

  // Attempt to collect crashes into the reboot vault crash directory. Do not
  // collect crashes if this is a user triggered or a factory powerwash.
  if (preserve_sensitive_files && !args_.factory_wipe) {
    if (utils::CreateEncryptedRebootVault())
      CollectClobberCrashReports();
  }

  // Remove keys that may alter device state.
  RemoveVpdKeys();

  if (!args_.keepimg) {
    utils::EnsureKernelIsBootable(root_disk_,
                                  wipe_info_.active_kernel_partition);
    WipeDevice(wipe_info_.inactive_root_device);
    WipeDevice(wipe_info_.inactive_kernel_device);
  }

  // Ensure that we've run for at least 5 minutes if this run requires it.
  if (should_force_delay) {
    ForceDelay();
  }

  // Check if we're in developer mode, and if so, create developer mode marker
  // file so that we don't run clobber-state again after reboot.
  if (!MarkDeveloperMode()) {
    LOG(ERROR) << "Creating developer mode marker file failed.";
  }

  // Schedule flush of filesystem caches to disk.
  sync();

  LOG(INFO) << "clobber-state has completed";
  relocate_clobber_state_log.RunAndReset();

  // Factory wipe should stop here.
  if (args_.factory_wipe)
    return 0;

  // If everything worked, reboot.
  Reboot();
  // This return won't actually be reached unless reboot fails.
  return 0;
}

bool ClobberState::IsInDeveloperMode() {
  std::string firmware_name;
  int dev_mode_flag;
  return cros_system_->GetInt(CrosSystem::kDevSwitchBoot, &dev_mode_flag) &&
         dev_mode_flag == 1 &&
         cros_system_->GetString(CrosSystem::kMainFirmwareActive,
                                 &firmware_name) &&
         firmware_name != "recovery";
}

bool ClobberState::MarkDeveloperMode() {
  if (IsInDeveloperMode())
    return base::WriteFile(stateful_.Append(".developer_mode"), "", 0) == 0;

  return true;
}

void ClobberState::AttemptSwitchToFastWipe(bool is_rotational) {
  // On a non-fast wipe, rotational drives take too long. Override to run them
  // through "fast" mode. Sensitive contents should already
  // be encrypted.
  if (!args_.fast_wipe && is_rotational) {
    LOG(INFO) << "Stateful device is on rotational disk, shredding files";
    ShredRotationalStatefulFiles();
    args_.fast_wipe = true;
    LOG(INFO) << "Switching to fast wipe";
  }

  // For drives that support secure erasure, wipe the keysets,
  // and then run the drives through "fast" mode.
  //
  // Note: currently only eMMC-based SSDs are supported.
  if (!args_.fast_wipe) {
    LOG(INFO) << "Attempting to wipe encryption keysets";
    if (WipeKeysets()) {
      LOG(INFO) << "Wiping encryption keysets succeeded";
      args_.fast_wipe = true;
      LOG(INFO) << "Switching to fast wipe";
    } else {
      LOG(INFO) << "Wiping encryption keysets failed";
    }
  }
}

void ClobberState::ShredRotationalStatefulFiles() {
  // Directly remove things that are already encrypted (which are also the
  // large things), or are static from images.
  brillo::DeleteFile(stateful_.Append("encrypted.block"));
  brillo::DeletePathRecursively(stateful_.Append("var_overlay"));
  brillo::DeletePathRecursively(stateful_.Append("dev_image"));

  base::FileEnumerator shadow_files(
      stateful_.Append("home/.shadow"),
      /*recursive=*/true, base::FileEnumerator::FileType::DIRECTORIES);
  for (base::FilePath path = shadow_files.Next(); !path.empty();
       path = shadow_files.Next()) {
    if (path.BaseName() == base::FilePath("vault")) {
      brillo::DeletePathRecursively(path);
    }
  }

  // Shred everything else. We care about contents not filenames, so do not
  // use "-u" since metadata updates via fdatasync dominate the shred time.
  // Note that if the count-down is interrupted, the reset file continues
  // to exist, which correctly continues to indicate a needed wipe.
  brillo::ProcessImpl shred;
  shred.AddArg("/usr/bin/shred");
  shred.AddArg("--force");
  shred.AddArg("--zero");
  base::FileEnumerator stateful_files(stateful_, /*recursive=*/true,
                                      base::FileEnumerator::FileType::FILES);
  for (base::FilePath path = stateful_files.Next(); !path.empty();
       path = stateful_files.Next()) {
    shred.AddArg(path.value());
  }
  shred.RedirectOutputToMemory(true);
  shred.Run();
  AppendToLog("shred", shred.GetOutputString(STDOUT_FILENO));

  sync();
}

bool ClobberState::WipeKeysets() {
  std::vector<std::string> key_files{
      "encrypted.key", "encrypted.needs-finalization",
      "home/.shadow/cryptohome.key", "home/.shadow/salt",
      "home/.shadow/salt.sum"};
  bool found_file = false;
  for (const std::string& str : key_files) {
    base::FilePath path = stateful_.Append(str);
    if (base::PathExists(path)) {
      found_file = true;
      if (!SecureErase(path)) {
        LOG(ERROR) << "Securely erasing file failed: " << path.value();
        return false;
      }
    }
  }

  // Delete files named 'master' in directories contained in '.shadow'.
  base::FileEnumerator directories(stateful_.Append("home/.shadow"),
                                   /*recursive=*/false,
                                   base::FileEnumerator::FileType::DIRECTORIES);
  for (base::FilePath dir = directories.Next(); !dir.empty();
       dir = directories.Next()) {
    base::FileEnumerator files(dir, /*recursive=*/false,
                               base::FileEnumerator::FileType::FILES);
    for (base::FilePath file = files.Next(); !file.empty();
         file = files.Next()) {
      if (file.RemoveExtension().BaseName() == base::FilePath("master")) {
        found_file = true;
        if (!SecureErase(file)) {
          LOG(ERROR) << "Securely erasing file failed: " << file.value();
          return false;
        }
      }
    }
  }

  // If no files were found, then we can't say whether or not secure erase
  // works. Assume it doesn't.
  if (!found_file) {
    LOG(WARNING) << "No files existed to attempt secure erase";
    return false;
  }

  return DropCaches();
}

void ClobberState::ForceDelay() {
  base::TimeDelta elapsed = base::TimeTicks::Now() - wipe_start_time_;
  LOG(INFO) << "Clobber has already run for " << elapsed.InSeconds()
            << " seconds";
  base::TimeDelta remaining = kMinClobberDuration - elapsed;
  if (remaining <= base::Seconds(0)) {
    LOG(INFO) << "Skipping forced delay";
    return;
  }
  LOG(INFO) << "Forcing a delay of " << remaining.InSeconds() << " seconds";
  if (!ui_->ShowCountdownTimer(remaining)) {
    // If showing the timer failed, we still want to make sure that we don't
    // run for less than |kMinClobberDuration|.
    base::PlatformThread::Sleep(remaining);
  }
}

// Wrapper around secure_erase_file::SecureErase(const base::FilePath&).
bool ClobberState::SecureErase(const base::FilePath& path) {
  return secure_erase_file::SecureErase(path);
}

// Wrapper around secure_erase_file::DropCaches(). Must be called after
// a call to SecureEraseFile. Files are only securely deleted if DropCaches
// returns true.
bool ClobberState::DropCaches() {
  return secure_erase_file::DropCaches();
}

uint64_t ClobberState::GetBlkSize(const base::FilePath& device) {
  base::ScopedFD fd(HANDLE_EINTR(
      open(device.value().c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "open " << device.value();
    return 0;
  }

  uint64_t size;
  if (ioctl(fd.get(), BLKGETSIZE64, &size)) {
    PLOG(ERROR) << "ioctl(BLKGETSIZE): " << device.value();
    return 0;
  }
  return size;
}

bool ClobberState::WipeDevice(const base::FilePath& device_path, bool discard) {
  if (wipe_info_.is_mtd_flash) {
    return WipeMTDDevice(device_path, partitions_);
  } else {
    return WipeBlockDevice(device_path, ui_.get(), args_.fast_wipe, discard);
  }
}

void ClobberState::SetArgsForTest(const ClobberState::Arguments& args) {
  args_ = args;
}

ClobberState::Arguments ClobberState::GetArgsForTest() {
  return args_;
}

void ClobberState::SetStatefulForTest(const base::FilePath& stateful_path) {
  stateful_ = stateful_path;
}

void ClobberState::SetDevForTest(const base::FilePath& dev_path) {
  dev_ = dev_path;
}

void ClobberState::SetSysForTest(const base::FilePath& sys_path) {
  sys_ = sys_path;
}

int ClobberState::Stat(const base::FilePath& path, struct stat* st) {
  return stat(path.value().c_str(), st);
}

bool ClobberState::ClearBiometricSensorEntropy() {
  if (base::PathExists(base::FilePath(kBioWashPath))) {
    brillo::ProcessImpl bio_wash;
    bio_wash.AddArg(kBioWashPath);
    return bio_wash.Run() == 0;
  }
  // Return true here so that we don't report spurious failures on platforms
  // without the bio_wash executable.
  return true;
}

void ClobberState::Reboot() {
  brillo::ProcessImpl proc;
  proc.AddArg("/sbin/shutdown");
  proc.AddArg("-r");
  proc.AddArg("now");
  int ret = proc.Run();
  if (ret == 0) {
    // Wait for reboot to finish (it's an async call).
    sleep(60 * 60 * 24);
  }
  // If we've reached here, reboot (probably) failed.
  LOG(ERROR) << "Requesting reboot failed with failure code " << ret;
}

void ClobberState::ResetStatefulPartition() {
  // Attempt to remove the logical volume stack unconditionally: this covers the
  // situation where a device may rollback to a version that doesn't support
  // the LVM stateful partition setup.
  RemoveLogicalVolumeStack();

  // Destroy user data: wipe the stateful partition.
  if (!WipeDevice(wipe_info_.stateful_partition_device)) {
    LOG(ERROR) << "Unable to wipe device "
               << wipe_info_.stateful_partition_device.value();
  }
}

ClobberState::PreserveLogicalVolumesWipeInfos
ClobberState::PreserveLogicalVolumesWipeArgs() {
  // TODO(b/222344877): Add DLC logical volumes here.
  return {
      {
          .lv_name = kThinpool,
          .preserve = true,
          .zero = false,
      },
      {
          .lv_name = kUnencrypted,
          .preserve = false,
          .zero = true,
      },
  };
}
