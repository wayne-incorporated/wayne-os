// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_FUNCTIONS_GPU_H_
#define RUNTIME_PROBE_FUNCTIONS_GPU_H_

#include "runtime_probe/probe_function.h"

#include <base/files/file_path.h>

typedef struct gbm_device_info GbmDeviceInfo;

namespace runtime_probe {

// Probe gpu components.
class GpuFunction : public PrivilegedProbeFunction {
  using PrivilegedProbeFunction::PrivilegedProbeFunction;

 public:
  NAME_PROBE_FUNCTION("gpu");

 private:
  // PrivilegedProbeFunction overrides.
  DataType EvalImpl() const override;

  // Checks if sysfs_node is a dGPU device.
  bool IsDGPUDevice(const base::FilePath& sysfs_node) const;

  // Checks if sysfs_node is a dGPU device by minigbm library. If we cannot
  // get the device info, we will guess that this is a dGPU device. Most of the
  // cases the iGPU should be ready so this won't happen for iGPU.
  bool IsDGPUDeviceByGBMLibrary(const base::FilePath& sysfs_node) const;

  // For mocking.
  virtual int GbmDetectDeviceInfoPath(unsigned int detect_flags,
                                      const char* dev_node,
                                      ::GbmDeviceInfo* info) const;
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_FUNCTIONS_GPU_H_
