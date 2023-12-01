// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "discod/utils/ufs.h"

#include <string>
#include <optional>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/blkdev_utils/ufs.h>

namespace discod {

namespace {

constexpr char kSysBlock[] = "sys/block";
constexpr char kWbNode[] = "wb_on";
constexpr char kWbCapabilities[] = "capabilities/write_booster";

}  // namespace

bool IsUfs(const base::FilePath& root_device, const base::FilePath& root) {
  base::FilePath device_node =
      root.Append(kSysBlock).Append(root_device.BaseName());
  return brillo::IsUfs(device_node);
}

bool IsWriteBoosterSupported(const base::FilePath& root_device,
                             const base::FilePath& root) {
  base::FilePath device_node =
      root.Append(kSysBlock).Append(root_device.BaseName());

  if (!brillo::IsUfs(device_node)) {
    return false;
  }

  base::FilePath controller_node =
      brillo::UfsSysfsToControllerNode(device_node);
  if (controller_node.empty()) {
    return false;
  }
  base::FilePath wbcap_node = controller_node.Append(kWbCapabilities);
  std::string value;
  if (!base::ReadFileToString(wbcap_node, &value)) {
    LOG(ERROR) << "Couldn't read WriteBooster capability marker: "
               << wbcap_node;
    return false;
  }

  return value == "1\n";
}

base::FilePath GetUfsDeviceNode(const base::FilePath& root_device,
                                const base::FilePath& root) {
  base::FilePath device_node =
      root.Append(kSysBlock).Append(root_device.BaseName());

  if (!brillo::IsUfs(device_node)) {
    return base::FilePath();
  }

  VLOG(2) << "Candidade device_node=" << device_node;

  return base::PathExists(device_node) ? device_node : base::FilePath();
}

base::FilePath GetUfsWriteBoosterNode(const base::FilePath& root_device,
                                      const base::FilePath& root) {
  base::FilePath device_node =
      root.Append(kSysBlock).Append(root_device.BaseName());

  if (!brillo::IsUfs(device_node)) {
    return base::FilePath();
  }

  base::FilePath controller_node =
      brillo::UfsSysfsToControllerNode(device_node);
  if (controller_node.empty()) {
    return base::FilePath();
  }
  base::FilePath wb_node = controller_node.Append(kWbNode);

  VLOG(2) << "Candidade wb_node=" << wb_node;
  return base::PathExists(wb_node) ? wb_node : base::FilePath();
}

}  // namespace discod
