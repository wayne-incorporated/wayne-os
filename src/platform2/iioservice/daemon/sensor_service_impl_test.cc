// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/test/task_environment.h>
#include <libmems/test_fakes.h>

#include "iioservice/daemon/sensor_metrics_mock.h"
#include "iioservice/daemon/sensor_service_impl.h"

namespace iioservice {

namespace {

constexpr char kFakeAccelName[] = "FakeAccel";
constexpr int kFakeAccelId = 1;
constexpr char kFakeAccelChnName[] = "accel_a";

constexpr char kFakeGyroName[] = "FakeGyro";
constexpr int kFakeGyroId = 2;
constexpr char kFakeGyroChnName[] = "anglvel_a";

constexpr char kFakeLightName[] = "FakeLight";
constexpr int kFakeLightId = 3;
constexpr char kFakeLightChnName[] = "illuminance";

class FakeSensorServiceNewDevicesObserver
    : public cros::mojom::SensorServiceNewDevicesObserver {
 public:
  FakeSensorServiceNewDevicesObserver() : receiver_(this) {}

  void OnNewDeviceAdded(
      int32_t iio_device_id,
      const std::vector<cros::mojom::DeviceType>& types) override {
    iio_device_id_ = iio_device_id;
    types_ = types;
  }

  mojo::PendingRemote<cros::mojom::SensorServiceNewDevicesObserver>
  PassRemote() {
    CHECK(!receiver_.is_bound());
    return receiver_.BindNewPipeAndPassRemote();
  }

  bool CheckNewDevice(int32_t iio_device_id,
                      std::vector<cros::mojom::DeviceType> types) {
    if (!iio_device_id_.has_value() || iio_device_id_.value() != iio_device_id)
      return false;

    if (types_.size() != types.size())
      return false;

    for (size_t i = 0; i < types_.size(); ++i) {
      if (types_[i] != types[i])
        return false;
    }

    return true;
  }

 private:
  mojo::Receiver<cros::mojom::SensorServiceNewDevicesObserver> receiver_;

  std::optional<int32_t> iio_device_id_;
  std::vector<cros::mojom::DeviceType> types_;
};

class SensorServiceImplTest : public ::testing::Test {
 protected:
  void SetUp() override {
    SensorMetricsMock::InitializeForTesting();

    auto context = std::make_unique<libmems::fakes::FakeIioContext>();
    context_ = context.get();

    auto accel = std::make_unique<libmems::fakes::FakeIioDevice>(
        context_, kFakeAccelName, kFakeAccelId);
    auto gyro = std::make_unique<libmems::fakes::FakeIioDevice>(
        context_, kFakeGyroName, kFakeGyroId);

    accel->AddChannel(std::make_unique<libmems::fakes::FakeIioChannel>(
        kFakeAccelChnName, true));
    // Assign a different location attribute to avoid creating the gravity
    // device in SensorServiceImpl.
    accel->WriteStringAttribute(cros::mojom::kLocation,
                                cros::mojom::kLocationLid);
    gyro->AddChannel(std::make_unique<libmems::fakes::FakeIioChannel>(
        kFakeGyroChnName, true));

    context->AddDevice(std::move(accel));
    context->AddDevice(std::move(gyro));

    sensor_service_ = SensorServiceImpl::Create(
        task_environment_.GetMainThreadTaskRunner(), std::move(context));
    EXPECT_TRUE(sensor_service_);
  }

  void TearDown() override { SensorMetrics::Shutdown(); }

  base::test::SingleThreadTaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};

  libmems::fakes::FakeIioContext* context_;

  SensorServiceImpl::ScopedSensorServiceImpl sensor_service_ = {
      nullptr, SensorServiceImpl::SensorServiceImplDeleter};
};

TEST_F(SensorServiceImplTest, GetDeviceIds) {
  base::RunLoop loop;
  sensor_service_->GetDeviceIds(
      cros::mojom::DeviceType::ACCEL,
      base::BindOnce(
          [](base::OnceClosure closure,
             const std::vector<int32_t>& iio_device_ids) {
            EXPECT_EQ(iio_device_ids.size(), 1);
            EXPECT_EQ(iio_device_ids[0], kFakeAccelId);

            std::move(closure).Run();
          },
          loop.QuitClosure()));
  // Wait until the callback is done.
  loop.Run();
}

TEST_F(SensorServiceImplTest, GetAllDeviceIds) {
  base::RunLoop loop;
  sensor_service_->GetAllDeviceIds(base::BindOnce(
      [](base::OnceClosure closure,
         const base::flat_map<int32_t, std::vector<cros::mojom::DeviceType>>&
             iio_device_ids_types) {
        EXPECT_EQ(iio_device_ids_types.size(), 2);
        auto it_accel = iio_device_ids_types.find(kFakeAccelId);
        EXPECT_TRUE(it_accel != iio_device_ids_types.end());
        EXPECT_EQ(it_accel->second.size(), 1);
        EXPECT_EQ(it_accel->second[0], cros::mojom::DeviceType::ACCEL);

        auto it_gyro = iio_device_ids_types.find(kFakeGyroId);
        EXPECT_TRUE(it_gyro != iio_device_ids_types.end());
        EXPECT_EQ(it_gyro->second.size(), 1);
        EXPECT_EQ(it_gyro->second[0], cros::mojom::DeviceType::ANGLVEL);

        std::move(closure).Run();
      },
      loop.QuitClosure()));
  // Wait until the callback is done.
  loop.Run();
}

TEST_F(SensorServiceImplTest, OnDeviceAdded) {
  std::unique_ptr<FakeSensorServiceNewDevicesObserver> observer(
      new FakeSensorServiceNewDevicesObserver());
  sensor_service_->RegisterNewDevicesObserver(observer->PassRemote());

  auto light = std::make_unique<libmems::fakes::FakeIioDevice>(
      context_, kFakeLightName, kFakeLightId);
  light->AddChannel(std::make_unique<libmems::fakes::FakeIioChannel>(
      kFakeLightChnName, true));
  context_->AddDevice(std::move(light));

  sensor_service_->OnDeviceAdded(kFakeLightId);
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(observer->CheckNewDevice(
      kFakeLightId,
      std::vector<cros::mojom::DeviceType>{cros::mojom::DeviceType::LIGHT}));
}

class SensorServiceImplInvalidContextTest : public ::testing::Test {
 protected:
  void SetUp() override {
    SensorMetricsMock::InitializeForTesting();

    auto context = std::make_unique<libmems::fakes::FakeIioContext>();
    context_ = context.get();
    EXPECT_FALSE(context_->IsValid());

    // Initialize with an invalid context.
    sensor_service_ = SensorServiceImpl::Create(
        task_environment_.GetMainThreadTaskRunner(), std::move(context));
    EXPECT_TRUE(sensor_service_);

    auto accel = std::make_unique<libmems::fakes::FakeIioDevice>(
        context_, kFakeAccelName, kFakeAccelId);

    accel->AddChannel(std::make_unique<libmems::fakes::FakeIioChannel>(
        kFakeAccelChnName, true));

    context_->AddDevice(std::move(accel));
    EXPECT_TRUE(context_->IsValid());

    sensor_service_->OnDeviceAdded(kFakeAccelId);
  }

  void TearDown() override { SensorMetrics::Shutdown(); }

  base::test::SingleThreadTaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};

  libmems::fakes::FakeIioContext* context_;

  SensorServiceImpl::ScopedSensorServiceImpl sensor_service_ = {
      nullptr, SensorServiceImpl::SensorServiceImplDeleter};
};

TEST_F(SensorServiceImplInvalidContextTest, GetAllDeviceIds) {
  base::RunLoop loop;
  sensor_service_->GetAllDeviceIds(base::BindOnce(
      [](base::OnceClosure closure,
         const base::flat_map<int32_t, std::vector<cros::mojom::DeviceType>>&
             iio_device_ids_types) {
        EXPECT_EQ(iio_device_ids_types.size(), 1);
        auto it_accel = iio_device_ids_types.find(kFakeAccelId);
        EXPECT_TRUE(it_accel != iio_device_ids_types.end());
        EXPECT_EQ(it_accel->second.size(), 1);
        EXPECT_EQ(it_accel->second[0], cros::mojom::DeviceType::ACCEL);

        std::move(closure).Run();
      },
      loop.QuitClosure()));
  // Wait until the callback is done.
  loop.Run();
}

class SensorServiceImplTestDeviceTypesWithParam
    : public ::testing::TestWithParam<
          std::pair<std::vector<std::string>,
                    std::vector<cros::mojom::DeviceType>>> {
 protected:
  void SetUp() override {
    SensorMetricsMock::InitializeForTesting();

    std::unique_ptr<libmems::fakes::FakeIioContext> context =
        std::make_unique<libmems::fakes::FakeIioContext>();

    auto device = std::make_unique<libmems::fakes::FakeIioDevice>(
        nullptr, kFakeAccelName, kFakeAccelId);

    for (auto chn_id : GetParam().first) {
      device->AddChannel(
          std::make_unique<libmems::fakes::FakeIioChannel>(chn_id, true));
    }

    context->AddDevice(std::move(device));

    sensor_service_ = SensorServiceImpl::Create(
        task_environment_.GetMainThreadTaskRunner(), std::move(context));
    EXPECT_TRUE(sensor_service_.get());
  }

  void TearDown() override {
    sensor_service_.reset();
    SensorMetrics::Shutdown();
  }

  base::test::SingleThreadTaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};

  SensorServiceImpl::ScopedSensorServiceImpl sensor_service_ = {
      nullptr, SensorServiceImpl::SensorServiceImplDeleter};
};

TEST_P(SensorServiceImplTestDeviceTypesWithParam, DeviceTypes) {
  base::RunLoop loop;
  sensor_service_->GetAllDeviceIds(base::BindOnce(
      [](base::OnceClosure closure,
         const base::flat_map<int32_t, std::vector<cros::mojom::DeviceType>>&
             iio_device_ids_types) {
        if (GetParam().second.empty()) {
          EXPECT_TRUE(iio_device_ids_types.empty());
        } else {
          EXPECT_EQ(iio_device_ids_types.size(), 1);
          auto it = iio_device_ids_types.find(kFakeAccelId);
          EXPECT_TRUE(it != iio_device_ids_types.end());
          EXPECT_EQ(it->second.size(), GetParam().second.size());
          for (size_t i = 0; i < it->second.size(); ++i)
            EXPECT_EQ(it->second[i], GetParam().second[i]);
        }

        std::move(closure).Run();
      },
      loop.QuitClosure()));
  // Wait until the callback is done.
  loop.Run();
}

INSTANTIATE_TEST_SUITE_P(
    SensorServiceImplTestDeviceTypesWithParamRun,
    SensorServiceImplTestDeviceTypesWithParam,
    ::testing::Values(std::pair<std::vector<std::string>,
                                std::vector<cros::mojom::DeviceType>>(
                          {"accel_x"}, {cros::mojom::DeviceType::ACCEL}),
                      std::pair<std::vector<std::string>,
                                std::vector<cros::mojom::DeviceType>>(
                          {"anglvel_y"}, {cros::mojom::DeviceType::ANGLVEL}),
                      std::pair<std::vector<std::string>,
                                std::vector<cros::mojom::DeviceType>>(
                          {"illuminance"}, {cros::mojom::DeviceType::LIGHT}),
                      std::pair<std::vector<std::string>,
                                std::vector<cros::mojom::DeviceType>>(
                          {"count"}, {cros::mojom::DeviceType::COUNT}),
                      std::pair<std::vector<std::string>,
                                std::vector<cros::mojom::DeviceType>>(
                          {"magn_z"}, {cros::mojom::DeviceType::MAGN}),
                      std::pair<std::vector<std::string>,
                                std::vector<cros::mojom::DeviceType>>(
                          {"angl"}, {cros::mojom::DeviceType::ANGL}),
                      std::pair<std::vector<std::string>,
                                std::vector<cros::mojom::DeviceType>>(
                          {"pressure"}, {cros::mojom::DeviceType::BARO}),
                      std::pair<std::vector<std::string>,
                                std::vector<cros::mojom::DeviceType>>(
                          {"proximity0"}, {cros::mojom::DeviceType::PROXIMITY}),
                      std::pair<std::vector<std::string>,
                                std::vector<cros::mojom::DeviceType>>(
                          {"accel_x", "accel_y", "magn_z", "abc"},
                          {cros::mojom::DeviceType::ACCEL,
                           cros::mojom::DeviceType::MAGN}),
                      std::pair<std::vector<std::string>,
                                std::vector<cros::mojom::DeviceType>>(
                          {"accel", "anglvel", "illuminance_x", "count_y",
                           "magn", "angl_z", "pressure_x"},
                          {})));

}  // namespace

}  // namespace iioservice
