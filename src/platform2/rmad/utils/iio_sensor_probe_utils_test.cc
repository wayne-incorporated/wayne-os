// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/utils/iio_sensor_probe_utils_impl.h"

#include <memory>
#include <set>
#include <utility>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libmems/test_fakes.h>

#include "rmad/constants.h"

namespace {

constexpr char kAccelDeviceName[] = "FakeAccelDevice";
constexpr char kFakeAccelChannels[][10] = {"accel_x", "accel_y", "accel_z",
                                           "timestamp"};

constexpr char kAnglvelDeviceName[] = "FakeAnglvelDevice";
constexpr char kFakeAnglvelChannels[][10] = {"anglvel_x", "anglvel_y",
                                             "anglvel_z", "timestamp"};

constexpr char kDeviceLocationName[] = "location";
constexpr char kDeviceLocationValue[][8] = {"base", "lid"};

}  // namespace

namespace rmad {

class IioSensorProbeUtilsImplTest : public testing::Test {
 public:
  IioSensorProbeUtilsImplTest() {}

  std::unique_ptr<IioSensorProbeUtils> CreateIioSensorProbeUtils() {
    auto iio_context = std::make_unique<libmems::fakes::FakeIioContext>();
    int id = 1;

    for (auto location : kDeviceLocationValue) {
      auto device_accel = std::make_unique<libmems::fakes::FakeIioDevice>(
          nullptr, kAccelDeviceName, id++);
      for (auto chn : kFakeAccelChannels) {
        auto channel =
            std::make_unique<libmems::fakes::FakeIioChannel>(chn, true);
        device_accel->AddChannel(std::move(channel));
      }
      EXPECT_TRUE(
          device_accel->WriteStringAttribute(kDeviceLocationName, location));
      iio_context->AddDevice(std::move(device_accel));
    }

    for (auto location : kDeviceLocationValue) {
      auto device_anglvel = std::make_unique<libmems::fakes::FakeIioDevice>(
          nullptr, kAnglvelDeviceName, id++);
      for (auto chn : kFakeAnglvelChannels) {
        auto channel =
            std::make_unique<libmems::fakes::FakeIioChannel>(chn, true);
        device_anglvel->AddChannel(std::move(channel));
      }
      EXPECT_TRUE(
          device_anglvel->WriteStringAttribute(kDeviceLocationName, location));
      iio_context->AddDevice(std::move(device_anglvel));
    }

    return std::make_unique<IioSensorProbeUtilsImpl>(std::move(iio_context));
  }
};

TEST_F(IioSensorProbeUtilsImplTest, Probe_Success) {
  auto iio_sensor_probe_utils = CreateIioSensorProbeUtils();

  std::set<RmadComponent> probed_components = iio_sensor_probe_utils->Probe();
  EXPECT_EQ(probed_components.count(RMAD_COMPONENT_BASE_ACCELEROMETER), 1);
  EXPECT_EQ(probed_components.count(RMAD_COMPONENT_BASE_GYROSCOPE), 1);
  EXPECT_EQ(probed_components.count(RMAD_COMPONENT_LID_ACCELEROMETER), 1);
  EXPECT_EQ(probed_components.count(RMAD_COMPONENT_LID_GYROSCOPE), 1);
  EXPECT_EQ(probed_components.size(), 4);
}

}  // namespace rmad
