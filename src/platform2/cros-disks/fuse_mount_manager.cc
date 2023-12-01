// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/fuse_mount_manager.h"

#include <sys/mount.h>

#include <utility>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <brillo/process/process_reaper.h>

#include "cros-disks/drivefs_helper.h"
#include "cros-disks/fusebox_helper.h"
#include "cros-disks/platform.h"
#include "cros-disks/quote.h"
#include "cros-disks/smbfs_helper.h"
#include "cros-disks/sshfs_helper.h"
#include "cros-disks/uri.h"

namespace cros_disks {

FUSEMountManager::FUSEMountManager(const std::string& mount_root,
                                   const std::string& working_dirs_root,
                                   Platform* platform,
                                   Metrics* metrics,
                                   brillo::ProcessReaper* process_reaper)
    : MountManager(mount_root, platform, metrics, process_reaper),
      working_dirs_root_(working_dirs_root) {}

FUSEMountManager::~FUSEMountManager() {
  UnmountAll();
}

bool FUSEMountManager::Initialize() {
  if (!MountManager::Initialize())
    return false;

  if (!platform()->CreateDirectory(working_dirs_root_)) {
    PLOG(ERROR) << "Cannot create writable FUSE directory "
                << quote(working_dirs_root_);
    return false;
  }

  if (!platform()->SetOwnership(working_dirs_root_, getuid(), getgid()) ||
      !platform()->SetPermissions(working_dirs_root_, 0755)) {
    PLOG(ERROR) << "Cannot set up writable FUSE directory "
                << quote(working_dirs_root_);
    return false;
  }

  // Register specific FUSE mount helpers here.
  RegisterHelper(std::make_unique<DrivefsHelper>(platform(), process_reaper()));
  RegisterHelper(std::make_unique<FuseBoxHelper>(platform(), process_reaper()));
  RegisterHelper(std::make_unique<SshfsHelper>(
      platform(), process_reaper(), base::FilePath(working_dirs_root_)));
  RegisterHelper(std::make_unique<SmbfsHelper>(platform(), process_reaper()));

  return true;
}

std::unique_ptr<MountPoint> FUSEMountManager::DoMount(
    const std::string& source,
    const std::string& fuse_type,
    const std::vector<std::string>& options,
    const base::FilePath& mount_path,
    MountError* error) {
  CHECK(!mount_path.empty()) << "Invalid mount path argument";

  Uri uri = Uri::Parse(source);
  CHECK(uri.valid()) << "Source " << quote(source) << " is not a URI";

  base::FilePath dir_name;
  const Mounter* selected_helper = nullptr;
  for (const auto& helper : helpers_) {
    if (helper->CanMount(source, options, &dir_name)) {
      selected_helper = helper.get();
      break;
    }
  }

  if (!selected_helper) {
    LOG(ERROR) << "Cannot find FUSE module for " << fuse_type << " "
               << redact(source);
    *error = MountError::kUnknownFilesystem;
    return nullptr;
  }

  std::unique_ptr<MountPoint> mountpoint =
      selected_helper->Mount(source, mount_path, options, error);
  LOG_IF(ERROR, *error != MountError::kSuccess)
      << "Cannot mount " << fuse_type << " " << redact(source) << ": "
      << *error;

  return mountpoint;
}

bool FUSEMountManager::CanMount(const std::string& source) const {
  base::FilePath dir;
  for (const auto& helper : helpers_) {
    if (helper->CanMount(source, {}, &dir))
      return true;
  }
  return false;
}

std::string FUSEMountManager::SuggestMountPath(
    const std::string& source) const {
  Uri uri = Uri::Parse(source);
  if (!uri.valid()) {
    return "";
  }

  base::FilePath dir;
  for (const auto& helper : helpers_) {
    if (helper->CanMount(source, {}, &dir))
      return mount_root().Append(dir).value();
  }
  base::FilePath base_name = base::FilePath(source).BaseName();
  return mount_root().Append(base_name).value();
}

void FUSEMountManager::RegisterHelper(std::unique_ptr<Mounter> helper) {
  helpers_.push_back(std::move(helper));
}

}  // namespace cros_disks
