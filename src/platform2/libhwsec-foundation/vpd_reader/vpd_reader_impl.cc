// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/vpd_reader/vpd_reader_impl.h"

#include <optional>
#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>

namespace hwsec_foundation {

namespace {
constexpr char kDefaultVpdRoPath[] = "/sys/firmware/vpd/ro";
}  // namespace

VpdReaderImpl::VpdReaderImpl(const std::string& vpd_ro_path)
    : vpd_ro_path_(vpd_ro_path) {}

VpdReaderImpl::VpdReaderImpl() : VpdReaderImpl(kDefaultVpdRoPath) {}

std::optional<std::string> VpdReaderImpl::Get(const std::string& key) {
  const base::FilePath path(vpd_ro_path_ + '/' + key);
  if (!base::PathExists(path)) {
    LOG(ERROR) << __func__ << ": " << path << " doesn't exist.";
    return std::nullopt;
  }
  std::string value;
  if (base::ReadFileToString(path, &value)) {
    if (value.empty()) {
      LOG(WARNING) << __func__ << ": Value of " << key << " is empty.";
    }
    return value;
  }
  LOG(ERROR) << __func__ << ": Error reading " << path;
  return std::nullopt;
}

}  // namespace hwsec_foundation
