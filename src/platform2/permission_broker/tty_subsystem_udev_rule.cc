// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/tty_subsystem_udev_rule.h"

#include <grp.h>
#include <libudev.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <vector>

using std::string;

namespace permission_broker {

// static
std::string TtySubsystemUdevRule::GetDevNodeGroupName(udev_device* device) {
  const char* const devnode = udev_device_get_devnode(device);
  if (devnode == nullptr) {
    return "";
  }

  // Get gid for |devnode|.
  struct stat st;
  int ret = stat(devnode, &st);
  if (ret < 0) {
    return "";
  }

  // Get buffer size for getgrgid_r().
  int64_t getgr_res = sysconf(_SC_GETGR_R_SIZE_MAX);
  if (getgr_res < 0) {
    return "";
  }

  // Get group name.
  struct group gr;
  struct group* pgr = nullptr;
  size_t getgr_size = static_cast<size_t>(getgr_res);
  std::vector<char> getgr_buf(getgr_size);
  ret = getgrgid_r(st.st_gid, &gr, getgr_buf.data(), getgr_buf.size(), &pgr);
  if (ret != 0 || pgr == nullptr) {
    return "";
  }

  return string(pgr->gr_name);
}

TtySubsystemUdevRule::TtySubsystemUdevRule(const string& name) : Rule(name) {}

Rule::Result TtySubsystemUdevRule::ProcessDevice(udev_device* device) {
  const char* const subsystem = udev_device_get_subsystem(device);
  if (!subsystem || strcmp(subsystem, "tty"))
    return IGNORE;
  return ProcessTtyDevice(device);
}

}  // namespace permission_broker
