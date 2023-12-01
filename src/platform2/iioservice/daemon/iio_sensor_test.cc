// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include <memory>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/run_loop.h>
#include <base/test/task_environment.h>
#include <libmems/test_fakes.h>
#include <mojo/core/embedder/scoped_ipc_support.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include "iioservice/daemon/iio_sensor.h"
#include "iioservice/mojo/cros_sensor_service.mojom.h"

namespace iioservice {

namespace {

class FakeSensorServiceImpl final : public SensorServiceImpl {
 public:
  FakeSensorServiceImpl(
      scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
      std::unique_ptr<libmems::IioContext> context)
      : SensorServiceImpl(
            std::move(ipc_task_runner),
            std::move(context),
            SensorDeviceImpl::ScopedSensorDeviceImpl(
                nullptr, SensorDeviceImpl::SensorDeviceImplDeleter)) {}

  ~FakeSensorServiceImpl() {
    // Expect |AddReceiver| is called exactly once.
    EXPECT_TRUE(receiver_.is_bound());
  }

  // SensorServiceImpl overrides:
  void AddReceiver(
      mojo::PendingReceiver<cros::mojom::SensorService> request) override {
    CHECK(!receiver_.is_bound());

    receiver_.Bind(std::move(request));
  }

 private:
  mojo::Receiver<cros::mojom::SensorService> receiver_{this};
};

class FakeIioSensor final : public IioSensor {
 public:
  using ScopedFakeIioSensor =
      std::unique_ptr<FakeIioSensor, decltype(&IioSensorDeleter)>;

  static ScopedFakeIioSensor Create(
      scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
      mojo::PendingReceiver<
          chromeos::mojo_service_manager::mojom::ServiceProvider>
          server_receiver) {
    ScopedFakeIioSensor server(new FakeIioSensor(std::move(ipc_task_runner),
                                                 std::move(server_receiver)),
                               IioSensorDeleter);

    server->SetSensorService();

    return server;
  }

 protected:
  // IioSensor overrides:
  void SetSensorService() override {
    std::unique_ptr<FakeSensorServiceImpl,
                    decltype(&SensorServiceImpl::SensorServiceImplDeleter)>
        sensor_service(new FakeSensorServiceImpl(
                           ipc_task_runner_,
                           std::make_unique<libmems::fakes::FakeIioContext>()),
                       SensorServiceImpl::SensorServiceImplDeleter);
    sensor_service_ = std::move(sensor_service);
  }

 private:
  FakeIioSensor(scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
                mojo::PendingReceiver<
                    chromeos::mojo_service_manager::mojom::ServiceProvider>
                    server_receiver)
      : IioSensor(std::move(ipc_task_runner), std::move(server_receiver)) {}
};

class IioSensorTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ipc_support_ = std::make_unique<mojo::core::ScopedIPCSupport>(
        task_environment_.GetMainThreadTaskRunner(),
        mojo::core::ScopedIPCSupport::ShutdownPolicy::CLEAN);
  }

  base::test::SingleThreadTaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};

  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;

  FakeIioSensor::ScopedFakeIioSensor server_ = {nullptr,
                                                IioSensor::IioSensorDeleter};
};

TEST_F(IioSensorTest, Request) {
  mojo::Remote<chromeos::mojo_service_manager::mojom::ServiceProvider> remote;
  server_ = FakeIioSensor::Create(task_environment_.GetMainThreadTaskRunner(),
                                  remote.BindNewPipeAndPassReceiver());

  mojo::Remote<cros::mojom::SensorService> sensor_service_remote;
  remote->Request(
      chromeos::mojo_service_manager::mojom::ProcessIdentity::New(),
      sensor_service_remote.BindNewPipeAndPassReceiver().PassPipe());

  // Test if |sensor_service_remote| is actually connected to the
  // |FakeSensorServiceImpl|.
  base::RunLoop loop;
  sensor_service_remote->GetAllDeviceIds(base::BindOnce(
      [](base::OnceClosure closure,
         const base::flat_map<int32_t, std::vector<cros::mojom::DeviceType>>&
             iio_device_ids_types) {
        EXPECT_EQ(iio_device_ids_types.size(), 0);
        std::move(closure).Run();
      },
      loop.QuitClosure()));
  // Wait until the callback is done.
  loop.Run();
}

}  // namespace

}  // namespace iioservice
