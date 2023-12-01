// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/functions/gpu.h"

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/containers/fixed_flat_set.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_util.h>
#include <minigbm/minigbm_helpers.h>

#include "runtime_probe/system/context.h"
#include "runtime_probe/utils/file_utils.h"

namespace runtime_probe {
namespace {

constexpr char kPCIDevicesPath[] = "sys/bus/pci/devices";
constexpr auto kGPUFields = base::MakeFixedFlatSet<base::StringPiece>(
    {"vendor", "device", "subsystem_vendor", "subsystem_device"});

}  // namespace

int GpuFunction::GbmDetectDeviceInfoPath(unsigned int detect_flags,
                                         const char* dev_node,
                                         ::GbmDeviceInfo* info) const {
  return ::gbm_detect_device_info_path(detect_flags, dev_node, info);
}

// If fails to call gbm library, this function will return true because:
// * If it is not work due to driver issue, it should be more likely a dGPU,
//   because we have better iGPU support.
// * Probing additional devices should be better than dropping devices
//   silently.
bool GpuFunction::IsDGPUDeviceByGBMLibrary(
    const base::FilePath& sysfs_node) const {
  base::FilePath drm_node_pattern = sysfs_node.Append("drm/renderD*");
  std::vector<base::FilePath> drm_nodes = Glob(drm_node_pattern);
  for (const auto& node : drm_nodes) {
    VLOG(1) << "Found drm node: " << node;
  }
  LOG_IF(ERROR, drm_nodes.size() >= 2)
      << "Found multiple drm nodes. Use the first one and ignore others.";
  if (drm_nodes.size() == 0) {
    LOG(ERROR) << "Cannot find any drm node from " << sysfs_node
               << ". Is the driver ready?";
    return true;
  }

  ::GbmDeviceInfo info;
  int ret = GbmDetectDeviceInfoPath(0, drm_nodes[0].value().c_str(), &info);
  if (ret) {
    LOG(ERROR) << "Cannot get gbm info from drm node " << drm_nodes[0]
               << ", return " << ret;
    return true;
  }
  VLOG(1) << "Drm node " << sysfs_node << " is discrete: "
          << (info.dev_type_flags & GBM_DEV_TYPE_FLAG_DISCRETE);
  return info.dev_type_flags & GBM_DEV_TYPE_FLAG_DISCRETE;
}

bool GpuFunction::IsDGPUDevice(const base::FilePath& sysfs_node) const {
  base::FilePath class_file = sysfs_node.Append("class");
  std::string class_value;
  if (!ReadFileToString(class_file, &class_value))
    return false;
  // 0x03 is the class code of PCI display controllers.
  // - 0x00 is the subclass code of VGA compatible controller.
  // - 0x02 is the subclass code of 3D controller (for GPU without display
  // attached.).
  if (!base::StartsWith(class_value, "0x0300") &&
      !base::StartsWith(class_value, "0x0302")) {
    return false;
  }

  return IsDGPUDeviceByGBMLibrary(sysfs_node);
}

GpuFunction::DataType GpuFunction::EvalImpl() const {
  DataType results{};

  base::FileEnumerator it(
      Context::Get()->root_dir().Append(kPCIDevicesPath), false,
      base::FileEnumerator::SHOW_SYM_LINKS | base::FileEnumerator::FILES |
          base::FileEnumerator::DIRECTORIES);
  for (auto path = it.Next(); !path.empty(); path = it.Next()) {
    if (!IsDGPUDevice(path))
      continue;
    std::optional<base::Value> res = MapFilesToDict(path, kGPUFields);
    if (res.has_value())
      results.Append(std::move(res).value());
  }

  return results;
}

}  // namespace runtime_probe
