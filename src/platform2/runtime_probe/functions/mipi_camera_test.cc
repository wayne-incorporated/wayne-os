// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <gtest/gtest.h>

#include "cros-camera/device_config.h"
#include "runtime_probe/functions/mipi_camera.h"
#include "runtime_probe/utils/function_test_utils.h"

namespace runtime_probe {
namespace {

class FakeMipiCameraFunction : public MipiCameraFunction {
  using MipiCameraFunction::MipiCameraFunction;

  std::optional<std::vector<cros::PlatformCameraInfo>> GetPlatformCameraInfo()
      const override {
    return fake_cameras_;
  }

 public:
  // The fake cameras used by fake function.
  std::optional<std::vector<cros::PlatformCameraInfo>> fake_cameras_;
};

class MipiCameraFunctionTest : public BaseFunctionTest {};

cros::PlatformCameraInfo CreateEepromPlatformCameraInfo(
    std::string sysfs_name,
    std::string module_vid,
    uint16_t module_pid,
    std::string sensor_vid,
    uint16_t sensor_pid,
    std::string nvmem_path) {
  cros::EepromIdBlock id_block = {
      .module_pid = module_pid,
      .module_vid{module_vid[0], module_vid[1]},
      .sensor_vid{sensor_vid[0], sensor_vid[1]},
      .sensor_pid = sensor_pid,
  };
  cros::PlatformCameraInfo camera_info = {
      .eeprom = cros::EepromInfo{.id_block = std::move(id_block),
                                 .nvmem_path = base::FilePath(nvmem_path)},
      .sysfs_name = sysfs_name,
  };
  return camera_info;
}

cros::PlatformCameraInfo CreateV4L2PlatformCameraInfo(std::string name,
                                                      std::string vendor_id,
                                                      std::string subdev_path) {
  cros::V4L2SensorInfo v4l2_sensor = {
      .name = name,
      .vendor_id = vendor_id,
      .subdev_path = base::FilePath(subdev_path)};
  cros::PlatformCameraInfo camera_info = {.v4l2_sensor =
                                              std::move(v4l2_sensor)};
  return camera_info;
}

TEST_F(MipiCameraFunctionTest, ProbeMipiCamera) {
  auto probe_function = CreateProbeFunction<FakeMipiCameraFunction>();

  probe_function->fake_cameras_ = std::vector<cros::PlatformCameraInfo>{
      CreateEepromPlatformCameraInfo("ABC-00/ABC-1234", "TC", 1234u, "OV",
                                     4321u, "/sys/devices/XXX/nvmem"),
      CreateV4L2PlatformCameraInfo("AAAA", "BBBB",
                                   "/sys/devices/XXX/v4l-subdev0"),
  };

  auto result = probe_function->Eval();
  auto ans = CreateProbeResultFromJson(R"JSON(
    [{
      "bus_type": "mipi",
      "mipi_module_id": "TC04d2",
      "mipi_sysfs_name": "ABC-00/ABC-1234",
      "mipi_sensor_id": "OV10e1",
      "path": "/sys/devices/XXX/nvmem"
    },
    {
      "bus_type": "mipi",
      "mipi_name": "AAAA",
      "mipi_vendor": "BBBB",
      "path": "/sys/devices/XXX/v4l-subdev0"
    }]
  )JSON");
  EXPECT_EQ(result, ans);
}

TEST_F(MipiCameraFunctionTest, GetDeviceConfigFailed) {
  auto probe_function = CreateProbeFunction<FakeMipiCameraFunction>();

  // Fail to get device config.
  probe_function->fake_cameras_ = std::nullopt;

  auto result = probe_function->Eval();
  auto ans = CreateProbeResultFromJson(R"JSON(
    []
  )JSON");
  EXPECT_EQ(result, ans);
}

TEST_F(MipiCameraFunctionTest, NoCamera) {
  auto probe_function = CreateProbeFunction<FakeMipiCameraFunction>();

  // Get empty camera list.
  probe_function->fake_cameras_ = std::vector<cros::PlatformCameraInfo>{};

  auto result = probe_function->Eval();
  auto ans = CreateProbeResultFromJson(R"JSON(
    []
  )JSON");
  EXPECT_EQ(result, ans);
}

}  // namespace
}  // namespace runtime_probe
