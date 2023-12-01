// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_FUNCTIONS_MIPI_CAMERA_H_
#define RUNTIME_PROBE_FUNCTIONS_MIPI_CAMERA_H_

#include <optional>
#include <vector>

#include "cros-camera/device_config.h"
#include "runtime_probe/probe_function.h"

namespace runtime_probe {

class MipiCameraFunction : public PrivilegedProbeFunction {
  using PrivilegedProbeFunction::PrivilegedProbeFunction;

 public:
  NAME_PROBE_FUNCTION("mipi_camera");

 private:
  DataType EvalImpl() const override;

  // For mocking.
  // The function gets MIPI camera list via |cros::DeviceConfig|.
  // @return vector of |cros::PlatformCameraInfo| if |cros::DeviceConfig|
  // is initialized successfully, std::nullopt otherwise.
  virtual std::optional<std::vector<cros::PlatformCameraInfo>>
  GetPlatformCameraInfo() const;
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_FUNCTIONS_MIPI_CAMERA_H_
