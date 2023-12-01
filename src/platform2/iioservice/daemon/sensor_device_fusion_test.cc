// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include <iterator>
#include <memory>
#include <optional>
#include <utility>

#include <base/functional/bind.h>
#include <base/notreached.h>
#include <base/rand_util.h>
#include <base/run_loop.h>
#include <base/task/sequenced_task_runner.h>
#include <base/test/task_environment.h>
#include <libmems/common_types.h>
#include <libmems/test_fakes.h>
#include <mojo/core/embedder/scoped_ipc_support.h>

#include "iioservice/daemon/common_types.h"
#include "iioservice/daemon/sensor_device_fusion.h"
#include "iioservice/daemon/sensor_device_impl.h"
#include "iioservice/daemon/sensor_metrics_mock.h"
#include "iioservice/daemon/test_fakes.h"
#include "iioservice/mojo/sensor.mojom.h"

namespace iioservice {

namespace {

constexpr int kNumFailures = 10;

constexpr char kDeviceAttrName[] = "FakeDeviceAttr";
constexpr char kDeviceAttrValue[] = "FakeDeviceAttrValue\0\n\0";
constexpr char kParsedDeviceAttrValue[] = "FakeDeviceAttrValue";

constexpr int32_t kFakeFusionId = 10000;

constexpr double kMaxFrequency = 40.0;

class FakeSensorDeviceFusion final : public SensorDeviceFusion {
 public:
  static ScopedSensorDeviceFusion Create(
      int32_t id,
      Location location,
      scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
      base::RepeatingCallback<
          void(int32_t iio_device_id,
               mojo::PendingReceiver<cros::mojom::SensorDevice> request)>
          iio_add_receiver_callback,
      double max_frequency) {
    ScopedSensorDeviceFusion device(nullptr, SensorDeviceFusionDeleter);

    device.reset(
        new FakeSensorDeviceFusion(id, location, std::move(ipc_task_runner),
                                   std::move(iio_add_receiver_callback),
                                   max_frequency, GetGravityChannels()));

    return device;
  }

  ~FakeSensorDeviceFusion() = default;

  // SensorDeviceFusion overrides:
  void GetAttributes(const std::vector<std::string>& attr_names,
                     GetAttributesCallback callback) override {
    std::move(callback).Run(std::vector<std::optional<std::string>>(
        attr_names.size(), std::nullopt));
  }
  void GetChannelsAttributes(const std::vector<int32_t>& iio_chn_indices,
                             const std::string& attr_name,
                             GetChannelsAttributesCallback callback) override {
    std::move(callback).Run(std::vector<std::optional<std::string>>(
        iio_chn_indices.size(), std::nullopt));
  }

 protected:
  void UpdateRequestedFrequency(double frequency) override {
    SensorDeviceFusion::UpdateRequestedFrequency(frequency);
  }

  FakeSensorDeviceFusion(
      int32_t id,
      Location location,
      scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
      base::RepeatingCallback<
          void(int32_t iio_device_id,
               mojo::PendingReceiver<cros::mojom::SensorDevice> request)>
          iio_add_receiver_callback,
      double max_frequency,
      std::vector<std::string> channel_ids)
      : SensorDeviceFusion(id,
                           cros::mojom::DeviceType::GRAVITY,
                           location,
                           ipc_task_runner,
                           std::move(iio_add_receiver_callback),
                           max_frequency,
                           channel_ids) {
    samples_handler_ = std::make_unique<SamplesHandlerFusion>(
        ipc_task_runner_, channel_ids,
        base::BindRepeating(&FakeSensorDeviceFusion::UpdateRequestedFrequency,
                            base::Unretained(this)));
  }
};

}  // namespace

class IioDeviceHandlerBase {
 protected:
  // |device| needs channels and attribute "sampling_frequency_available" being
  // set.
  void SetUpBase(std::unique_ptr<libmems::fakes::FakeIioDevice> device) {
    SensorMetricsMock::InitializeForTesting();

    ipc_support_ = std::make_unique<mojo::core::ScopedIPCSupport>(
        task_environment_.GetMainThreadTaskRunner(),
        mojo::core::ScopedIPCSupport::ShutdownPolicy::CLEAN);

    context_ = std::make_unique<libmems::fakes::FakeIioContext>();

    EXPECT_TRUE(
        device->WriteStringAttribute(kDeviceAttrName, kDeviceAttrValue));

    device_ = device.get();
    context_->AddDevice(std::move(device));

    sensor_device_ = SensorDeviceImpl::Create(
        task_environment_.GetMainThreadTaskRunner(), context_.get());
    sensor_device_->OnDeviceAdded(device_, std::set<cros::mojom::DeviceType>{
                                               cros::mojom::DeviceType::ACCEL});

    iio_device_handler_ =
        std::make_unique<SensorDeviceFusion::IioDeviceHandler>(
            task_environment_.GetMainThreadTaskRunner(), fakes::kAccelDeviceId,
            cros::mojom::DeviceType::ACCEL,
            base::BindRepeating(&SensorDeviceImpl::AddReceiver,
                                base::Unretained(sensor_device_.get())),
            base::BindRepeating(&IioDeviceHandlerBase::HandleAccelSample,
                                base::Unretained(this)),
            base::BindRepeating(&IioDeviceHandlerBase::OnReadFailed,
                                base::Unretained(this)),
            base::BindOnce(&IioDeviceHandlerBase::Invalidate,
                           base::Unretained(this)));
  }

  void TearDownBase() {
    sensor_device_.reset();
    SensorMetrics::Shutdown();
  }

  virtual void HandleAccelSample(std::vector<int64_t> accel_sample) = 0;
  virtual void OnReadFailed() = 0;
  virtual void Invalidate() = 0;

  std::unique_ptr<libmems::fakes::FakeIioContext> context_;
  libmems::fakes::FakeIioDevice* device_;

  base::test::SingleThreadTaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME,
      base::test::TaskEnvironment::MainThreadType::IO};

  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;

  std::unique_ptr<fakes::FakeSamplesObserver> observer_;

  SensorDeviceImpl::ScopedSensorDeviceImpl sensor_device_ = {
      nullptr, SensorDeviceImpl::SensorDeviceImplDeleter};

  std::unique_ptr<SensorDeviceFusion::IioDeviceHandler> iio_device_handler_;
};

class IioDeviceHandlerTest : public ::testing::Test,
                             public IioDeviceHandlerBase {
 protected:
  void SetUp() override {
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

    SetUpBase(std::move(device));
  }

  void TearDown() override { TearDownBase(); }

  void HandleAccelSample(std::vector<int64_t> accel_sample) override {
    EXPECT_EQ(accel_sample.size(), std::size(libmems::fakes::kFakeAccelChns));
    if (!observer_)
      return;

    libmems::IioDevice::IioSample sample;
    for (int i = 0; i < std::size(libmems::fakes::kFakeAccelChns); ++i)
      sample.emplace(i, accel_sample[i]);

    observer_->OnSampleUpdated(sample);
    if (observer_->FinishedObserving())
      closure_.Run();
  }

  void OnReadFailed() override {
    if (!observer_)
      return;

    observer_->OnErrorOccurred(cros::mojom::ObserverErrorType::READ_FAILED);
  }

  void Invalidate() override {
    NOTREACHED() << "IioDeviceHandler is invalidated";
  }

  void WaitUntilFinishObserving() {
    base::RunLoop loop;
    closure_ = loop.QuitClosure();
    loop.Run();
    EXPECT_TRUE(observer_->FinishedObserving());
  }

  // Wait until finish observing closure.
  base::RepeatingClosure closure_;
};

TEST_F(IioDeviceHandlerTest, GetAttributes) {
  base::RunLoop loop;
  // Override the sampling_frequency_available attribute.
  iio_device_handler_->SetAttribute(
      libmems::kSamplingFrequencyAvailable,
      GetSamplingFrequencyAvailable(0.0, kMaxFrequency));

  iio_device_handler_->GetAttributes(
      {kDeviceAttrName, libmems::kSamplingFrequencyAvailable},
      base::BindOnce(
          [](base::RepeatingClosure closure,
             const std::vector<std::optional<std::string>>& values) {
            EXPECT_EQ(values.size(), 2u);
            EXPECT_TRUE(values[0].has_value());
            EXPECT_EQ(values[0].value().compare(kParsedDeviceAttrValue), 0);
            EXPECT_TRUE(values[1].has_value());
            EXPECT_EQ(values[1].value().compare("0.000000 0.000000 40.000000"),
                      0);
            closure.Run();
          },
          loop.QuitClosure()));
  loop.Run();
}

TEST_F(IioDeviceHandlerTest, SetFrequencyAndReadSamples) {
  std::multiset<std::pair<int, cros::mojom::ObserverErrorType>> failures;
  for (int i = 0; i < kNumFailures; ++i) {
    int k = base::RandInt(0, std::size(libmems::fakes::kFakeAccelSamples) - 1);

    device_->AddFailedReadAtKthSample(k);
    failures.insert(
        std::make_pair(k, cros::mojom::ObserverErrorType::READ_FAILED));
  }

  double frequency = libmems::fakes::kFakeSamplingFrequency;
  observer_ = fakes::FakeSamplesObserver::Create(device_, std::move(failures),
                                                 frequency, frequency,
                                                 frequency, frequency, 0);

  base::RunLoop loop;
  iio_device_handler_->SetFrequency(
      frequency, base::BindOnce(
                     [](base::RepeatingClosure closure, double result_freq) {
                       EXPECT_EQ(result_freq,
                                 libmems::fakes::kFakeSamplingFrequency);
                       closure.Run();
                     },
                     loop.QuitClosure()));
  loop.Run();

  WaitUntilFinishObserving();
}

class IioDeviceHandlerInvalidTest : public ::testing::Test,
                                    public IioDeviceHandlerBase {
 protected:
  void SetUp() override {}

  void TearDown() override { TearDownBase(); }

  void HandleAccelSample(std::vector<int64_t> accel_sample) override {
    NOTREACHED() << "Shouldn't get any sample";
  }

  void OnReadFailed() override { NOTREACHED() << "Shouldn't get any error"; }

  void Invalidate() override {
    // IioDeviceHandler will only call Invalidate callback once.
    EXPECT_FALSE(invalid_);
    invalid_ = true;
  }

  bool invalid_ = false;
};

TEST_F(IioDeviceHandlerInvalidTest, MissingChannel) {
  auto device = std::make_unique<libmems::fakes::FakeIioDevice>(
      nullptr, fakes::kAccelDeviceName, fakes::kAccelDeviceId);

  EXPECT_TRUE(
      device->WriteStringAttribute(libmems::kSamplingFrequencyAvailable,
                                   fakes::kFakeSamplingFrequencyAvailable));
  // Missing channel timestamp
  for (int i = 0; i < std::size(libmems::fakes::kFakeAccelChns) - 1; ++i) {
    auto chn = std::make_unique<libmems::fakes::FakeIioChannel>(
        libmems::fakes::kFakeAccelChns[i], true);
    device->AddChannel(std::move(chn));
  }

  SetUpBase(std::move(device));

  iio_device_handler_->SetAttribute(
      libmems::kSamplingFrequencyAvailable,
      GetSamplingFrequencyAvailable(0.0, kMaxFrequency));

  // GetAllChannelIdsCallback will fail due to the missing channel timestamp.
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(invalid_);

  // Test the case that IioDeviceHandler::Invalidate being called more than
  // once.
  sensor_device_.reset();
  base::RunLoop().RunUntilIdle();

  iio_device_handler_->SetFrequency(
      libmems::fakes::kFakeSamplingFrequency,
      base::BindOnce([](double result_freq) {
        NOTREACHED() << "Mojo pipe SensorDevice should be reset";
      }));

  base::RunLoop loop;
  iio_device_handler_->GetAttributes(
      {kDeviceAttrName, libmems::kSamplingFrequencyAvailable},
      base::BindOnce(
          [](base::RepeatingClosure closure,
             const std::vector<std::optional<std::string>>& values) {
            EXPECT_EQ(values.size(), 2u);
            // Mojo pipe SensorDevice should be reset, so attributes should not
            // be available.
            EXPECT_FALSE(values[0].has_value());
            // The overridden attributes could still be achieved.
            EXPECT_TRUE(values[1].has_value());
            EXPECT_EQ(values[1].value().compare("0.000000 0.000000 40.000000"),
                      0);
            closure.Run();
          },
          loop.QuitClosure()));
  loop.Run();
}

class SensorDeviceFusionTest : public ::testing::Test {
 protected:
  void SetUp() override {
    SensorMetricsMock::InitializeForTesting();

    ipc_support_ = std::make_unique<mojo::core::ScopedIPCSupport>(
        task_environment_.GetMainThreadTaskRunner(),
        mojo::core::ScopedIPCSupport::ShutdownPolicy::CLEAN);

    sensor_device_fusion_ = FakeSensorDeviceFusion::Create(
        kFakeFusionId, Location::kBase,
        task_environment_.GetMainThreadTaskRunner(),
        base::RepeatingCallback<void(
            int32_t iio_device_id,
            mojo::PendingReceiver<cros::mojom::SensorDevice> request)>(),
        kMaxFrequency);

    sensor_device_fusion_->AddReceiver(remote_.BindNewPipeAndPassReceiver());
    remote_.set_disconnect_handler(
        base::BindOnce(&SensorDeviceFusionTest::OnSensorDeviceDisconnect,
                       base::Unretained(this)));
  }

  void TearDown() override {
    sensor_device_fusion_.reset();
    SensorMetrics::Shutdown();
  }

  void Invalidate() { sensor_device_fusion_->Invalidate(); }

  void OnSensorDeviceDisconnect() { remote_.reset(); }

  base::test::SingleThreadTaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME,
      base::test::TaskEnvironment::MainThreadType::IO};

  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;

  SensorDeviceFusion::ScopedSensorDeviceFusion sensor_device_fusion_ = {
      nullptr, SensorDeviceFusion::SensorDeviceFusionDeleter};

  mojo::Remote<cros::mojom::SensorDevice> remote_;
};

TEST_F(SensorDeviceFusionTest, CheckWeakPtrs) {
  remote_.reset();
  base::RunLoop().RunUntilIdle();
}

TEST_F(SensorDeviceFusionTest, SetTimeout) {
  remote_->SetTimeout(0);
}

TEST_F(SensorDeviceFusionTest, SetFrequency) {
  base::RunLoop loop;
  remote_->SetFrequency(
      libmems::fakes::kFakeSamplingFrequency,
      base::BindOnce(
          [](base::RepeatingClosure closure, double result_freq) {
            EXPECT_EQ(result_freq, libmems::fakes::kFakeSamplingFrequency);
            closure.Run();
          },
          loop.QuitClosure()));
  loop.Run();

  Invalidate();

  base::RunLoop loop2;
  remote_->SetFrequency(
      libmems::fakes::kFakeSamplingFrequency,
      base::BindOnce(
          [](base::RepeatingClosure closure, double result_freq) {
            // After SensorDeviceFusion being invalidated, SetFrequency will be
            // denied and |result_freq| in SetFrequencyCallback will be -1.
            EXPECT_EQ(result_freq, -1);
            closure.Run();
          },
          loop2.QuitClosure()));
  loop2.Run();
}

TEST_F(SensorDeviceFusionTest, SetChannels) {
  auto gravity_channel_ids = GetGravityChannels();
  remote_->GetAllChannelIds(base::BindOnce(
      [](std::vector<std::string> gravity_channel_ids,
         const std::vector<std::string>& chn_ids) {
        EXPECT_EQ(chn_ids.size(), gravity_channel_ids.size());
        for (int i = 0; i < chn_ids.size(); ++i)
          EXPECT_EQ(chn_ids[i], gravity_channel_ids[i]);
      },
      gravity_channel_ids));

  std::vector<int32_t> indices = {0, 2};
  remote_->SetChannelsEnabled(
      indices, true,
      base::BindOnce([](const std::vector<int32_t>& failed_indices) {
        EXPECT_TRUE(failed_indices.empty());
      }));

  indices.clear();
  for (int i = 0; i < gravity_channel_ids.size(); ++i)
    indices.push_back(i);

  base::RunLoop loop;
  remote_->GetChannelsEnabled(
      indices, base::BindOnce(
                   [](size_t size, base::RepeatingClosure closure,
                      const std::vector<bool>& enabled) {
                     EXPECT_EQ(enabled.size(), size);
                     for (int i = 0; i < enabled.size(); ++i)
                       EXPECT_EQ(enabled[i], i % 2 == 0);

                     closure.Run();
                   },
                   gravity_channel_ids.size(), loop.QuitClosure()));
  loop.Run();

  Invalidate();

  remote_->SetChannelsEnabled(
      indices, true,
      base::BindOnce(
          [](std::vector<int32_t> indices,
             const std::vector<int32_t>& failed_indices) {
            // After SensorDeviceFusion being invalidated, SetChannelsEnabled
            // will be denied and |failed_indices| in SetChannelsEnabledCallback
            // will be identical to the requested indices.
            EXPECT_EQ(indices.size(), failed_indices.size());
            for (size_t i = 0; i < indices.size(); ++i)
              EXPECT_EQ(indices[i], failed_indices[i]);
          },
          indices));

  base::RunLoop loop2;
  remote_->GetChannelsEnabled(
      indices, base::BindOnce(
                   [](size_t size, base::RepeatingClosure closure,
                      const std::vector<bool>& enabled) {
                     EXPECT_EQ(enabled.size(), size);
                     // Even after SensorDeviceFusion being invalidated,
                     // GetChannelsEnabled still gets the original
                     // configuration.
                     for (int i = 0; i < enabled.size(); ++i)
                       EXPECT_EQ(enabled[i], i % 2 == 0);

                     closure.Run();
                   },
                   gravity_channel_ids.size(), loop2.QuitClosure()));
  loop2.Run();
}

}  // namespace iioservice
