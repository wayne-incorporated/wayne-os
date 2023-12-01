// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/network/proc_fs_stub.h"

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>

namespace shill {

namespace {
constexpr char kIPFlagTemplate[] = "/proc/sys/net/%s/conf/%s/%s";
constexpr char kIPFlagVersion4[] = "ipv4";
constexpr char kIPFlagVersion6[] = "ipv6";
}  // namespace

ProcFsStub::ProcFsStub(const std::string& interface_name)
    : interface_name_(interface_name) {}

bool ProcFsStub::SetIPFlag(IPAddress::Family family,
                           const std::string& flag,
                           const std::string& value) {
  std::string ip_version;
  if (family == IPAddress::kFamilyIPv4) {
    ip_version = kIPFlagVersion4;
  } else if (family == IPAddress::kFamilyIPv6) {
    ip_version = kIPFlagVersion6;
  } else {
    NOTIMPLEMENTED();
  }
  base::FilePath flag_file(
      base::StringPrintf(kIPFlagTemplate, ip_version.c_str(),
                         interface_name_.c_str(), flag.c_str()));
  if (!base::PathExists(flag_file.DirName())) {
    // If the directory containing the flag file does not exist it means the
    // interface is already removed. Returning silently without an ERROR log.
    return false;
  }
  if (base::WriteFile(flag_file, value.c_str(), value.length()) !=
      static_cast<int>(value.length())) {
    LOG(ERROR) << "IP flag write failed: " << value << " to "
               << flag_file.value();
    return false;
  }

  return true;
}
}  // namespace shill
