// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/sensor_service_handler.h"

#include <memory>
#include <optional>
#include <utility>

#include <base/run_loop.h>
#include <gtest/gtest.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "power_manager/powerd/system/fake_light.h"
#include "power_manager/powerd/system/fake_sensor_service.h"
#include "power_manager/powerd/testing/test_environment.h"

namespace power_manager::system {

namespace {

class FakeObserver : public SensorServiceHandlerObserver {
 public:
  explicit FakeObserver(SensorServiceHandler* sensor_service_handler)
      : SensorServiceHandlerObserver(sensor_service_handler) {}

  // SensorServiceHandlerObserver overrides:
  void OnNewDeviceAdded(
      int32_t iio_device_id,
      const std::vector<cros::mojom::DeviceType>& types) override {
    device_ids_.push_back(iio_device_id);

    if (on_new_device_added_closure_)
      on_new_device_added_closure_.Run();
  }
  void SensorServiceConnected() override { connected_ = true; }
  void SensorServiceDisconnected() override { connected_ = false; }

  std::vector<int32_t> device_ids_;
  std::optional<bool> connected_;

  base::RepeatingClosure on_new_device_added_closure_;
};

}  // namespace

class SensorServiceHandlerTest : public TestEnvironment {
 public:
  SensorServiceHandlerTest(const SensorServiceHandlerTest&) = delete;
  SensorServiceHandlerTest& operator=(const SensorServiceHandlerTest&) = delete;

  SensorServiceHandlerTest() = default;
  ~SensorServiceHandlerTest() override = default;

 protected:
  void SetUp() override {
    observer_ = std::make_unique<FakeObserver>(&sensor_service_handler_);
    ResetMojoChannel();
  }

  void ResetMojoChannel(SensorServiceHandler::OnIioSensorDisconnectCallback
                            on_iio_sensor_disconnect_callback =
                                base::DoNothing()) {
    sensor_service_.ClearReceivers();

    sensor_service_handler_.ResetSensorService(false);

    mojo::PendingRemote<cros::mojom::SensorService> pending_remote;
    sensor_service_.AddReceiver(
        pending_remote.InitWithNewPipeAndPassReceiver());
    sensor_service_handler_.SetUpChannel(
        std::move(pending_remote),
        std::move(on_iio_sensor_disconnect_callback));
  }

  void SetSensor(int32_t iio_device_id) {
    auto sensor_device =
        std::make_unique<FakeLight>(false, std::nullopt, std::nullopt);

    sensor_service_.SetSensorDevice(iio_device_id, std::move(sensor_device));
  }

  SensorServiceHandler sensor_service_handler_;
  std::unique_ptr<FakeObserver> observer_;

  FakeSensorService sensor_service_;
};

TEST_F(SensorServiceHandlerTest, DisconnectCallback) {
  base::RunLoop loop;
  ResetMojoChannel(base::BindOnce(
      [](base::OnceClosure closure, base::TimeDelta delay) {
        EXPECT_EQ(delay, base::Seconds(1));
        std::move(closure).Run();
      },
      loop.QuitClosure()));

  sensor_service_.ClearReceivers();

  // Wait until |sensor_service_handler.on_iio_sensor_disconnect_callback_| is
  // called.
  loop.Run();
}

TEST_F(SensorServiceHandlerTest, ConnectedAndAddNewDevices) {
  EXPECT_TRUE(observer_->connected_.value_or(false));

  base::RunLoop loop, loop2;

  observer_->on_new_device_added_closure_ = loop.QuitClosure();

  SetSensor(1);
  loop.Run();

  EXPECT_EQ(observer_->device_ids_.size(), 1);
  EXPECT_EQ(observer_->device_ids_[0], 1);

  auto observer2 = std::make_unique<FakeObserver>(&sensor_service_handler_);
  observer2->on_new_device_added_closure_ = loop2.QuitClosure();
  loop2.Run();

  EXPECT_EQ(observer2->device_ids_.size(), 1);
  EXPECT_EQ(observer2->device_ids_[0], 1);
}

}  // namespace power_manager::system
