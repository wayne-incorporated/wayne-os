// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/fake_vpn_util.h"

#include <base/files/file_util.h>
#include <base/logging.h>

namespace shill {

bool FakeVPNUtil::WriteConfigFile(const base::FilePath& filename,
                                  const std::string& contents) const {
  if (!base::WriteFile(filename, contents)) {
    LOG(ERROR) << "Failed to write config file";
    return false;
  }
  if (chmod(filename.value().c_str(), S_IRUSR | S_IRGRP) != 0) {
    PLOG(ERROR) << "Failed to make config file group-readable";
    return false;
  }
  return true;
}

bool FakeVPNUtil::PrepareConfigDirectory(
    const base::FilePath& directory_path) const {
  if (!base::DirectoryExists(directory_path) &&
      !base::CreateDirectory(directory_path)) {
    PLOG(ERROR) << "Unable to create configuration directory  "
                << directory_path.value();
    return false;
  }
  if (chmod(directory_path.value().c_str(), S_IRWXU | S_IRGRP | S_IXGRP)) {
    LOG(ERROR) << "Failed to set permissions on " << directory_path.value();
    base::DeletePathRecursively(directory_path);
    return false;
  }
  return true;
}

std::pair<base::ScopedFD, base::FilePath> FakeVPNUtil::WriteAnonymousConfigFile(
    const std::string& contents) const {
  return VPNUtil::New()->WriteAnonymousConfigFile(contents);
}

base::ScopedTempDir FakeVPNUtil::CreateScopedTempDir(
    const base::FilePath& parent_path) const {
  base::ScopedTempDir temp_dir;
  if (!temp_dir.CreateUniqueTempDirUnderPath(parent_path)) {
    LOG(ERROR) << "Failed to create temp dir under path " << parent_path;
    return base::ScopedTempDir{};
  }
  return temp_dir;
}

}  // namespace shill
