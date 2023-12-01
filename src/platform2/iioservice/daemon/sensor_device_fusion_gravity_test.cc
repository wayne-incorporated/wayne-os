// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include <base/functional/bind.h>
#include <base/run_loop.h>
#include <base/test/task_environment.h>
#include <libmems/common_types.h>
#include <libmems/test_fakes.h>
#include <mojo/core/embedder/scoped_ipc_support.h>

#include "iioservice/daemon/sensor_device_fusion_gravity.h"
#include "iioservice/daemon/sensor_device_impl.h"
#include "iioservice/daemon/sensor_metrics_mock.h"
#include "iioservice/daemon/test_fakes.h"
#include "iioservice/mojo/sensor.mojom.h"

namespace iioservice {

namespace {

constexpr int32_t kFakeFusionId = 10000;

constexpr char kDeviceAttrName[] = "FakeDeviceAttr";
constexpr char kDeviceAttrValue[] = "FakeDeviceAttrValue\0\n\0";
constexpr char kParsedDeviceAttrValue[] = "FakeDeviceAttrValue";

constexpr double kMaxFrequency = 40.0;

constexpr int32_t kFakeAccelId = 1;
constexpr int32_t kFakeGyroId = 1;

class SensorDeviceFusionGravityTest : public ::testing::Test {
 protected:
  void SetUp() override {
    SensorMetricsMock::InitializeForTesting();

    ipc_support_ = std::make_unique<mojo::core::ScopedIPCSupport>(
        task_environment_.GetMainThreadTaskRunner(),
        mojo::core::ScopedIPCSupport::ShutdownPolicy::CLEAN);

    context_ = std::make_unique<libmems::fakes::FakeIioContext>();

    auto device = std::make_unique<libmems::fakes::FakeIioDevice>(
        nullptr, fakes::kAccelDeviceName, fakes::kAccelDeviceId);

    EXPECT_TRUE(
        device->WriteStringAttribute(libmems::kSamplingFrequencyAvailable,
                                     fakes::kFakeSamplingFrequencyAvailable));
    for (const auto& channel : libmems::fakes::kFakeAccelChns) {
      auto chn =
          std::make_unique<libmems::fakes::FakeIioChannel>(channel, true);
      device->AddChannel(std::move(chn));
    }
    EXPECT_TRUE(
        device->WriteStringAttribute(kDeviceAttrName, kDeviceAttrValue));

    device_ = device.get();
    context_->AddDevice(std::move(device));

    sensor_device_ = SensorDeviceImpl::Create(
        task_environment_.GetMainThreadTaskRunner(), context_.get());
    sensor_device_->OnDeviceAdded(device_, std::set<cros::mojom::DeviceType>{
                                               cros::mojom::DeviceType::ACCEL});

    sensor_device_fusion_ = SensorDeviceFusionGravity::Create(
        kFakeFusionId, Location::kBase,
        task_environment_.GetMainThreadTaskRunner(),
        base::BindRepeating(&SensorDeviceImpl::AddReceiver,
                            base::Unretained(sensor_device_.get())),
        kMaxFrequency, kFakeAccelId, kFakeGyroId);
    sensor_device_fusion_gravity_ =
        static_cast<SensorDeviceFusionGravity*>(sensor_device_fusion_.get());

    sensor_device_fusion_->AddReceiver(remote_.BindNewPipeAndPassReceiver());
    remote_.set_disconnect_handler(
        base::BindOnce(&SensorDeviceFusionGravityTest::OnSensorDeviceDisconnect,
                       base::Unretained(this)));
  }

  void TearDown() override {
    sensor_device_.reset();
    sensor_device_fusion_.reset();
    remote_.reset();
    SensorMetrics::Shutdown();
  }

  void OnSensorDeviceDisconnect() { remote_.reset(); }

  base::test::SingleThreadTaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME,
      base::test::TaskEnvironment::MainThreadType::IO};

  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;

  std::unique_ptr<libmems::fakes::FakeIioContext> context_;
  libmems::fakes::FakeIioDevice* device_;

  SensorDeviceImpl::ScopedSensorDeviceImpl sensor_device_ = {
      nullptr, SensorDeviceImpl::SensorDeviceImplDeleter};

  SensorDeviceFusion::ScopedSensorDeviceFusion sensor_device_fusion_ = {
      nullptr, SensorDeviceFusion::SensorDeviceFusionDeleter};
  SensorDeviceFusionGravity* sensor_device_fusion_gravity_;

  mojo::Remote<cros::mojom::SensorDevice> remote_;
};

// Despite the lack of iio gyroscope, and |sensor_device_fusion_| will be
// invalidated, attributes should be successfully retrieved.
TEST_F(SensorDeviceFusionGravityTest, GetAttributes) {
  base::RunLoop loop;

  remote_->GetAttributes(
      {kDeviceAttrName, cros::mojom::kSamplingFrequencyAvailable,
       cros::mojom::kDeviceName},
      base::BindOnce(
          [](base::RepeatingClosure closure,
             const std::vector<std::optional<std::string>>& values) {
            EXPECT_EQ(values.size(), 3u);
            EXPECT_TRUE(values[0].has_value());
            EXPECT_EQ(values[0].value().compare(kParsedDeviceAttrValue), 0);
            EXPECT_TRUE(values[1].has_value());
            EXPECT_EQ(values[1].value(),
                      GetSamplingFrequencyAvailable(
                          SensorDeviceFusionGravity::kAccelMinFrequency,
                          kMaxFrequency));
            EXPECT_TRUE(values[2].has_value());
            EXPECT_EQ(values[2].value(), SensorDeviceFusionGravity::kName);
            closure.Run();
          },
          loop.QuitClosure()));
  loop.Run();
}

TEST_F(SensorDeviceFusionGravityTest, GetChannelsAttributes) {
  base::RunLoop loop;

  std::vector<int32_t> indices;
  size_t size = GetGravityChannels().size();
  for (size_t i = 0; i < size; ++i)
    indices.push_back(i);

  remote_->GetChannelsAttributes(
      indices, {cros::mojom::kScale},
      base::BindOnce(
          [](base::RepeatingClosure closure, size_t size,
             const std::vector<std::optional<std::string>>& values) {
            EXPECT_EQ(values.size(), size);
            // Gravity device channels' attributes are not provided for now.
            for (size_t i = 0; i < size; ++i)
              EXPECT_FALSE(values[i].has_value());

            closure.Run();
          },
          loop.QuitClosure(), size));
  loop.Run();
}

}  // namespace

}  // namespace iioservice
