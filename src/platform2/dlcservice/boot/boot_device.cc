// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dlcservice/boot/boot_device.h"

#include <linux/limits.h>

#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <rootdev/rootdev.h>

#include "dlcservice/utils.h"

using base::FilePath;
using std::string;

namespace dlcservice {

bool BootDevice::IsRemovableDevice(const string& device) {
  string sysfs_block = SysfsBlockDevice(device);
  string removable;
  if (sysfs_block.empty() ||
      !base::ReadFileToString(JoinPaths(sysfs_block, "removable"),
                              &removable)) {
    return false;
  }
  base::TrimWhitespaceASCII(removable, base::TRIM_ALL, &removable);
  return removable == "1";
}

base::FilePath BootDevice::GetBootDevice() {
  char boot_path[PATH_MAX] = "";
  // Resolve the boot device path fully, including dereferencing through
  // dm-verity.
  int ret = rootdev(boot_path, sizeof(boot_path), true, /*full resolution*/
                    false /*do not remove partition #*/);

  if (ret < 0) {
    LOG(ERROR) << "rootdev failed to find the root device";
    return {};
  }
  LOG_IF(WARNING, ret > 0) << "rootdev found a device name with no device node";

  // This local variable is used to construct the return string and is not
  // passed around after use.
  return base::FilePath{boot_path};
}

string BootDevice::SysfsBlockDevice(const string& device) {
  FilePath device_path(device);
  if (device_path.DirName().value() != "/dev") {
    return "";
  }
  return JoinPaths("/sys/block", device_path.BaseName()).value();
}

}  // namespace dlcservice
