// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "minios/logger.h"

#include <sys/mount.h>

#include <string>
#include <utility>

#include <base/files/file_util.h>
#include <base/logging.h>

namespace minios {

namespace {

// Only use after a successful mount.
struct ScopedUnmounterTraits {
  static Logger* InvalidValue() { return nullptr; }
  static void Free(Logger* logger) {
    if (logger)
      logger->Unmount();
  }
};
using ScopedUnmounter = base::ScopedGeneric<Logger*, ScopedUnmounterTraits>;

}  // namespace

const char kLogPath[] = "/var/log";
const char kMiniOSLogsDirectory[] = "minios_logs";

Logger::Logger(std::unique_ptr<DiskUtil> disk_util,
               std::unique_ptr<brillo::Platform> platform,
               const base::FilePath& root_path)
    : disk_util_(std::move(disk_util)),
      platform_(std::move(platform)),
      root_path_(root_path) {}

void Logger::Unmount() {
  if (!platform_->Unmount(GetMountPath(), /*lazy=*/false,
                          /*was_busy=*/nullptr)) {
    PLOG(WARNING) << "Failed to unmount the mount path "
                  << GetMountPath().value();
  }
}

bool Logger::DumpLogsIntoStateful() {
  // Get the fixed drive path on disk.
  const base::FilePath& drive = disk_util_->GetFixedDrive();
  if (drive.empty()) {
    LOG(ERROR) << "Could not retrieve fixed drive.";
    return false;
  }

  // Check if stateful partition path exists.
  base::FilePath stateful_path = disk_util_->GetStatefulPartition(drive);
  if (stateful_path.empty()) {
    LOG(ERROR) << "Stateful partition doesn't exist.";
    return false;
  }

  // Create a temporary directory to mount stateful partition onto.
  if (!tmp_mount_.CreateUniqueTempDir()) {
    PLOG(ERROR) << "Failed to create unique temporary directory to mount on";
    return false;
  }

  // Mount stateful partition onto the temporary directory.
  if (platform_->Mount(stateful_path.value().c_str(),
                       GetMountPath().value().c_str(), "ext4", MS_SILENT,
                       nullptr) != 0) {
    PLOG(ERROR) << "Failed to mount stateful partition "
                << stateful_path.value() << " at " << GetMountPath().value();
    return false;
  }
  // Must always unmount the stateful partition after a mount.
  ScopedUnmounter unmounter(this);

  // Create a miniOS log directory and copy the logs over.
  const auto minios_logs_path = GetMountPath().Append(kMiniOSLogsDirectory);
  if (!base::PathExists(minios_logs_path) &&
      !base::CreateDirectory(minios_logs_path)) {
    PLOG(ERROR)
        << "Failed to create minios_log directory in stateful partition at "
        << stateful_path.value();
    return false;
  }

  if (!base::CopyDirectory(root_path_, minios_logs_path, /*recursive=*/true)) {
    PLOG(ERROR) << "Failed to copy logs from " << root_path_.value() << " into "
                << minios_logs_path.value();
    return false;
  }

  return true;
}

base::FilePath Logger::GetMountPath() {
  return tmp_mount_.GetPath();
}

}  // namespace minios
