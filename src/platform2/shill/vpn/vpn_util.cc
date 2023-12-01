// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/vpn_util.h"

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include <memory>
#include <utility>

#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <base/strings/stringprintf.h>

#include "shill/net/process_manager.h"

namespace shill {

class VPNUtilImpl : public VPNUtil {
 public:
  bool WriteConfigFile(const base::FilePath& filename,
                       const std::string& contents) const override;
  bool PrepareConfigDirectory(
      const base::FilePath& directory_path) const override;
  std::pair<base::ScopedFD, base::FilePath> WriteAnonymousConfigFile(
      const std::string& contents) const override;
  base::ScopedTempDir CreateScopedTempDir(
      const base::FilePath& parent_path) const override;
};

bool VPNUtilImpl::WriteConfigFile(const base::FilePath& filename,
                                  const std::string& contents) const {
  if (!base::WriteFile(filename, contents)) {
    LOG(ERROR) << "Failed to write config file";
    return false;
  }

  if (chmod(filename.value().c_str(), S_IRUSR | S_IRGRP) != 0) {
    PLOG(ERROR) << "Failed to make config file group-readable";
    return false;
  }

  if (chown(filename.value().c_str(), -1, kVPNGid) != 0) {
    PLOG(ERROR) << "Failed to change gid of config file";
    return false;
  }

  return true;
}

bool VPNUtilImpl::PrepareConfigDirectory(
    const base::FilePath& directory_path) const {
  if (!base::DirectoryExists(directory_path) &&
      !base::CreateDirectory(directory_path)) {
    PLOG(ERROR) << "Unable to create configuration directory  "
                << directory_path.value();
    return false;
  }

  if (chown(directory_path.value().c_str(), -1, VPNUtil::kVPNGid) != 0) {
    PLOG(ERROR) << "Failed to change owner group of configuration directory "
                << directory_path.value();
    base::DeletePathRecursively(directory_path);
    return false;
  }

  if (chmod(directory_path.value().c_str(), S_IRWXU | S_IRGRP | S_IXGRP)) {
    LOG(ERROR) << "Failed to set permissions on " << directory_path.value();
    base::DeletePathRecursively(directory_path);
    return false;
  }

  return true;
}

std::pair<base::ScopedFD, base::FilePath> VPNUtilImpl::WriteAnonymousConfigFile(
    const std::string& contents) const {
  // The first parameter is the name of this file. This name is only used for
  // debugging purposes, and it does not have any side effect that multiple
  // files share the same name
  int fd = memfd_create("vpn_file", /*flags=*/0);
  if (fd == -1) {
    PLOG(ERROR) << "Failed to create file with memfd_create";
    return {};
  }

  base::ScopedFD scoped_fd(fd);
  if (!base::WriteFileDescriptor(fd, contents)) {
    PLOG(ERROR) << "Failed to write config file";
    return {};
  }

  base::FilePath path(base::StringPrintf("/proc/self/fd/%d", fd));
  return {std::move(scoped_fd), path};
}

base::ScopedTempDir VPNUtilImpl::CreateScopedTempDir(
    const base::FilePath& parent_path) const {
  base::ScopedTempDir temp_dir;

  if (!temp_dir.CreateUniqueTempDirUnderPath(parent_path)) {
    PLOG(ERROR) << "Failed to create temp dir under path " << parent_path;
    return base::ScopedTempDir{};
  }

  if (chmod(temp_dir.GetPath().value().c_str(), S_IRWXU | S_IRWXG) != 0) {
    PLOG(ERROR) << "Failed to change the permission of temp dir";
    return base::ScopedTempDir{};
  }

  if (chown(temp_dir.GetPath().value().c_str(), -1, VPNUtil::kVPNGid) != 0) {
    PLOG(ERROR) << "Failed to change gid of temp dir";
    return base::ScopedTempDir{};
  }
  return temp_dir;
}

std::unique_ptr<VPNUtil> VPNUtil::New() {
  return std::make_unique<VPNUtilImpl>();
}

// static
bool VPNUtil::CheckKernelVersion(const base::Version& minimum_version) {
  struct utsname buf;
  if (uname(&buf) != 0) {
    return false;
  }
  // Extract the numeric part of release string
  std::string version = base::SplitString(
      buf.release, "-", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY)[0];
  base::Version kernel_version = base::Version(version);
  return kernel_version.IsValid() && kernel_version >= minimum_version;
}

// static
ProcessManager::MinijailOptions VPNUtil::BuildMinijailOptions(
    uint64_t capmask) {
  ProcessManager::MinijailOptions options;
  options.user = VPNUtil::kVPNUser;
  options.group = VPNUtil::kVPNGroup;
  options.capmask = capmask;
  options.inherit_supplementary_groups = true;
  return options;
}

}  // namespace shill
