// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/system_mounter.h"

#include <errno.h>
#include <sys/mount.h>

#include <string>
#include <utility>

#include <base/logging.h>
#include <base/containers/util.h>
#include <base/strings/string_util.h>

#include "cros-disks/mount_options.h"
#include "cros-disks/mount_point.h"
#include "cros-disks/platform.h"

namespace cros_disks {

namespace {

constexpr uint64_t kExternalDiskMountFlags =
    MS_NODEV | MS_NOSUID | MS_NOEXEC | MS_NOSYMFOLLOW | MS_DIRSYNC;

}  // namespace

SystemMounter::SystemMounter(const Platform* platform,
                             std::string filesystem_type,
                             bool read_only,
                             std::vector<std::string> options)
    : platform_(platform),
      filesystem_type_(std::move(filesystem_type)),
      flags_(kExternalDiskMountFlags | (read_only ? MS_RDONLY : 0)),
      options_(std::move(options)) {}

SystemMounter::~SystemMounter() = default;

std::unique_ptr<MountPoint> SystemMounter::Mount(
    const std::string& source,
    const base::FilePath& target_path,
    std::vector<std::string> params,
    MountError* error) const {
  uint64_t flags = flags_;

  // We only care about "ro" here.
  if (IsReadOnlyMount(params)) {
    flags |= MS_RDONLY;
  }

  std::vector<std::string> options = options_;
  *error = ParseParams(std::move(params), &options);
  if (*error != MountError::kSuccess) {
    return nullptr;
  }

  std::string option_string;
  if (!JoinParamsIntoOptions(options, &option_string)) {
    *error = MountError::kInvalidMountOptions;
    return nullptr;
  }

  return MountPoint::Mount({.mount_path = target_path,
                            .source = source,
                            .filesystem_type = filesystem_type_,
                            .flags = flags,
                            .data = option_string},
                           platform_, error);
}

bool SystemMounter::CanMount(const std::string& source,
                             const std::vector<std::string>& /*params*/,
                             base::FilePath* suggested_dir_name) const {
  if (source.empty()) {
    *suggested_dir_name = base::FilePath("disk");
  } else {
    *suggested_dir_name = base::FilePath(source).BaseName();
  }
  return true;
}

MountError SystemMounter::ParseParams(
    std::vector<std::string> /*params*/,
    std::vector<std::string>* /*mount_options*/) const {
  return MountError::kSuccess;
}

}  // namespace cros_disks
