// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <vector>

#include <base/files/file.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <brillo/file_utils.h>
#include <brillo/process/process.h>
#include <brillo/userdb_utils.h>

#include "tpm2-simulator/constants.h"
#include "tpm2-simulator/tpm_nvchip_utils.h"

namespace {

constexpr char kNVChipPath[] = "NVChip";
constexpr size_t kNVChipSize = 1024 * 1024;  // 1MB.
constexpr char kWoringDirectory[] = ".";

// The old NVChip size that need to migrate to new format.
constexpr size_t kOldNVChipSize = 16384;

struct NVChipMigrateData {
  std::string chip_data;
};

bool Tune2Fs(const base::FilePath& file, const std::vector<std::string>& opts) {
  brillo::ProcessImpl tune_process;
  tune_process.AddArg("/sbin/tune2fs");
  for (const auto& arg : opts)
    tune_process.AddArg(arg);

  tune_process.AddArg(file.value());

  // Close unused file descriptors in child process.
  tune_process.SetCloseUnusedFileDescriptors(true);

  // Avoid polluting the parent process' stdout.
  tune_process.RedirectOutput("/dev/null");

  int rc = tune_process.Run();
  if (rc != 0) {
    LOG(ERROR) << "Can't tune ext4: " << file.value() << ", error: " << rc;
    return false;
  }
  return true;
}

bool FormatExt4(const base::FilePath& file) {
  brillo::ProcessImpl format_process;
  format_process.AddArg("/sbin/mkfs.ext4");

  format_process.AddArg(file.value());

  // No need to emit output.
  format_process.AddArg("-q");

  // Close unused file descriptors in child process.
  format_process.SetCloseUnusedFileDescriptors(true);

  // Avoid polluting the parent process' stdout.
  format_process.RedirectOutput("/dev/null");

  int rc = format_process.Run();
  if (rc != 0) {
    LOG(ERROR) << "Can't format '" << file.value()
               << "' as ext4, exit status: " << rc;
    return false;
  }

  // Tune the formatted filesystem:
  // -c 0: Disable max mount count checking.
  // -i 0: Disable filesystem checking.
  return Tune2Fs(file, {"-c", "0", "-i", "0"});
}

bool MountLoopbackFile(const base::FilePath& file,
                       const base::FilePath& mount_point) {
  brillo::ProcessImpl mount_process;
  mount_process.AddArg("/bin/mount");

  mount_process.AddArg("-o");
  mount_process.AddArg("loop");

  mount_process.AddArg(file.value());
  mount_process.AddArg(mount_point.value());

  // Close unused file descriptors in child process.
  mount_process.SetCloseUnusedFileDescriptors(true);

  // Avoid polluting the parent process' stdout.
  mount_process.RedirectOutput("/dev/null");

  int rc = mount_process.Run();
  if (rc != 0) {
    LOG(ERROR) << "Can't mount '" << file.value() << "' to '"
               << mount_point.value() << "', exit status: " << rc;
    return false;
  }
  return true;
}

bool ChownDirectoryContents(const base::FilePath& dir, uid_t uid, gid_t gid) {
  base::FileEnumerator ent_enum(dir, false, base::FileEnumerator::FILES);
  for (base::FilePath path = ent_enum.Next(); !path.empty();
       path = ent_enum.Next()) {
    if (HANDLE_EINTR(chown(path.value().c_str(), uid, gid)) < 0) {
      PLOG(ERROR) << "Failed to chown " << path.value();
      return false;
    }
  }
  return true;
}

bool PrepareMigrateNVChip(const base::FilePath& chip_path,
                          int64_t chip_size,
                          NVChipMigrateData* migrate_data) {
  if (chip_size == kOldNVChipSize) {
    if (!base::ReadFileToString(chip_path, &migrate_data->chip_data)) {
      LOG(ERROR) << "Failed to read the NVChip.";
      return false;
    }
    if (migrate_data->chip_data.size() != kOldNVChipSize) {
      LOG(ERROR) << "Unknown NVChip size after read.";
      return false;
    }
    if (!brillo::WriteStringToFile(chip_path, std::string(kNVChipSize, '\0'))) {
      LOG(ERROR) << "Failed to create the NVChip.";
      return false;
    }
    if (!FormatExt4(chip_path)) {
      LOG(ERROR) << "Failed to format the NVChip to ext4.";
      return false;
    }
    return true;
  } else {
    LOG(ERROR) << "Unknown NVChip size.";
    return false;
  }
}

bool MigrateNVChip(const base::FilePath& chip_path,
                   const base::FilePath& mount_point,
                   const NVChipMigrateData& migrate_data) {
  base::FilePath new_chip_path = mount_point.Append(kNVChipPath);
  if (!brillo::WriteStringToFile(new_chip_path, migrate_data.chip_data)) {
    LOG(ERROR) << "Failed to create the NVChip.";
    return false;
  }
  return true;
}

}  // namespace

namespace tpm2_simulator {

bool MountAndEnterNVChip() {
  base::FilePath chip_path(kNVChipPath);
  base::FilePath mount_point(kNVChipMountPoint);
  if (!base::PathExists(chip_path)) {
    if (!brillo::WriteStringToFile(chip_path, std::string(kNVChipSize, '\0'))) {
      LOG(ERROR) << "Failed to create the NVChip.";
      return false;
    }
    if (!FormatExt4(chip_path)) {
      LOG(ERROR) << "Failed to format the NVChip to ext4.";
      return false;
    }
  }

  int64_t chip_size = 0;
  if (!base::GetFileSize(chip_path, &chip_size)) {
    LOG(ERROR) << "Failed to get NVChip size.";
    return false;
  }

  bool migrate_nvchip = chip_size != kNVChipSize;
  NVChipMigrateData migrate_data;

  if (migrate_nvchip) {
    if (!PrepareMigrateNVChip(chip_path, chip_size, &migrate_data)) {
      LOG(ERROR) << "Failed to prepare migrate NVChip.";
      return false;
    }
  }

  if (!base::PathExists(mount_point)) {
    if (!base::CreateDirectory(mount_point)) {
      LOG(ERROR) << "Failed to create the NVChip mount point.";
      return false;
    }
  }

  uid_t uid;
  gid_t gid;
  if (!brillo::userdb::GetUserInfo(kSimulatorUser, &uid, &gid)) {
    LOG(ERROR) << "Failed to lookup the user name.";
    return false;
  }
  if (HANDLE_EINTR(chown(chip_path.value().c_str(), uid, gid)) < 0) {
    PLOG(ERROR) << "Failed to chown the NVChip.";
    return false;
  }
  if (HANDLE_EINTR(chown(mount_point.value().c_str(), uid, gid)) < 0) {
    PLOG(ERROR) << "Failed to chown the NVChip mount point.";
    return false;
  }

  if (HANDLE_EINTR(unshare(CLONE_NEWNS)) < 0) {
    PLOG(ERROR) << "Failed to unshare.";
    return false;
  }

  if (!MountLoopbackFile(chip_path, mount_point)) {
    LOG(ERROR) << "Failed to mount the NVChip.";
    return false;
  }

  if (HANDLE_EINTR(chown(mount_point.value().c_str(), uid, gid)) < 0) {
    PLOG(ERROR) << "Failed to chown the NVChip mount point after mount.";
    return false;
  }

  if (migrate_nvchip) {
    if (!MigrateNVChip(chip_path, mount_point, migrate_data)) {
      LOG(ERROR) << "Failed to migrate NVChip.";
      return false;
    }
  }

  if (HANDLE_EINTR(chdir(mount_point.value().c_str())) < 0) {
    PLOG(ERROR) << "Failed to enter the mount point.";
    return false;
  }

  return true;
}

bool CorrectWorkingDirectoryFilesOwner() {
  uid_t uid;
  gid_t gid;
  if (!brillo::userdb::GetUserInfo(kSimulatorUser, &uid, &gid)) {
    LOG(ERROR) << "Failed to lookup the user name.";
    return false;
  }

  if (!ChownDirectoryContents(base::FilePath(kWoringDirectory), uid, gid)) {
    LOG(ERROR)
        << "Failed to chown the NVChip mount point contents after mount.";
    return false;
  }

  return true;
}

}  // namespace tpm2_simulator
