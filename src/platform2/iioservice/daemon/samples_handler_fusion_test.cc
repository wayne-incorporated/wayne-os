// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include <algorithm>
#include <iterator>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/rand_util.h>
#include <base/run_loop.h>
#include <base/strings/stringprintf.h>
#include <base/test/task_environment.h>
#include <libmems/common_types.h>
#include <libmems/test_fakes.h>
#include <mojo/public/cpp/bindings/receiver_set.h>

#include "iioservice/daemon/common_types.h"
#include "iioservice/daemon/samples_handler_fusion.h"
#include "iioservice/daemon/sensor_metrics_mock.h"
#include "iioservice/daemon/test_fakes.h"
#include "iioservice/mojo/sensor.mojom.h"

namespace iioservice {

namespace {

constexpr double kMinFrequency = 20.0;
constexpr double kMaxFrequency = 40.0;

constexpr double kFooFrequency = 20.0;
constexpr int kNumFailures = 10;

double FixFrequency(double frequency) {
  if (frequency < libmems::kFrequencyEpsilon)
    return 0.0;

  if (frequency > kMaxFrequency)
    return kMaxFrequency;

  return frequency;
}

double FixFrequencyWithMin(double frequency) {
  if (frequency < libmems::kFrequencyEpsilon)
    return 0.0;

  if (frequency < kMinFrequency)
    return kMinFrequency;

  if (frequency > kMaxFrequency)
    return kMaxFrequency;

  return frequency;
}

}  // namespace

class SamplesHandlerFusionTestBase
    : public cros::mojom::SensorDeviceSamplesObserver {
 public:
  mojo::PendingRemote<cros::mojom::SensorDeviceSamplesObserver> GetRemote() {
    mojo::PendingRemote<cros::mojom::SensorDeviceSamplesObserver> remote;
    receiver_set_.Add(this, remote.InitWithNewPipeAndPassReceiver());
    return remote;
  }

  // cros::mojom::SensorDeviceSamplesObserver overrides:
  void OnSampleUpdated(const libmems::IioDevice::IioSample& sample) override {
    CHECK(
        task_environment_.GetMainThreadTaskRunner()->BelongsToCurrentThread());
  }
  void OnErrorOccurred(cros::mojom::ObserverErrorType type) override {
    CHECK(
        task_environment_.GetMainThreadTaskRunner()->BelongsToCurrentThread());
    CHECK_EQ(type, cros::mojom::ObserverErrorType::FREQUENCY_INVALID);
  }

 protected:
  void SetUpBase() {
    SensorMetricsMock::InitializeForTesting();

    handler_ = std::make_unique<SamplesHandlerFusion>(
        task_environment_.GetMainThreadTaskRunner(), GetGravityChannels(),
        base::BindRepeating(
            &SamplesHandlerFusionTestBase::UpdateRequestedFrequency,
            base::Unretained(this)));
    EXPECT_TRUE(handler_);
  }

  void TearDownBase() {
    handler_.reset();
    observers_.clear();

    base::RunLoop().RunUntilIdle();

    // ClientData should be valid until |handler_| is destructed.
    clients_data_.clear();

    SensorMetrics::Shutdown();
  }

  void UpdateRequestedFrequency(double frequency) {
    frequency_ = FixFrequencyWithMin(frequency);

    // |handler_| might not exist in the d'tor.
    if (handler_)
      handler_->SetDevFrequency(frequency_);
  }

  base::test::SingleThreadTaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME,
      base::test::TaskEnvironment::MainThreadType::IO};

  double frequency_ = 0.0;
  std::vector<ClientData> clients_data_;

  std::vector<std::unique_ptr<fakes::FakeSamplesObserver>> observers_;
  std::unique_ptr<SamplesHandlerFusion> handler_;

  mojo::ReceiverSet<cros::mojom::SensorDeviceSamplesObserver> receiver_set_;
};

class SamplesHandlerFusionTest : public ::testing::Test,
                                 public SamplesHandlerFusionTestBase {
 protected:
  void SetUp() override { SetUpBase(); }

  void TearDown() override { TearDownBase(); }
};

TEST_F(SamplesHandlerFusionTest, AddClientAndRemoveClient) {
  clients_data_.emplace_back(ClientData(0));
  ClientData& client_data = clients_data_[0];

  client_data.frequency = kFooFrequency;
  client_data.enabled_chn_indices.emplace(3);  // timestamp

  handler_->AddClient(&client_data, GetRemote());

  base::RunLoop run_loop;
  fakes::FakeObserver observer(run_loop.QuitClosure());
  handler_->AddClient(&client_data, observer.GetRemote());
  // Wait until |Observer| is disconnected.
  run_loop.Run();

  handler_->RemoveClient(&client_data);
  // RemoveClient can be called multiple times.
  handler_->RemoveClient(&client_data);
}

TEST_F(SamplesHandlerFusionTest, BadDeviceWithNoSamples) {
  handler_->Invalidate();

  std::vector<double> freqs = {5.0, 0.0, 10.0, 100.0};
  clients_data_.reserve(freqs.size());

  for (size_t i = 0; i < freqs.size(); ++i) {
    clients_data_.emplace_back(ClientData(i));
    ClientData& client_data = clients_data_[i];

    // At least one channel enabled
    client_data.enabled_chn_indices.emplace(3);  // timestamp
    client_data.frequency = freqs[i];
    client_data.timeout = 0;

    std::multiset<std::pair<int, cros::mojom::ObserverErrorType>> failures;
    failures.insert(
        std::make_pair(0, cros::mojom::ObserverErrorType::FREQUENCY_INVALID));

    // To match the check in |fakes::FakeSamplesObserver| for FREQUENCY_INVALID,
    // pass frequencies as zeros.
    auto fake_observer = fakes::FakeSamplesObserver::Create(
        nullptr, std::move(failures), 0.0, 0.0, kFooFrequency, kFooFrequency);

    handler_->AddClient(&client_data, fake_observer->GetRemote());

    observers_.emplace_back(std::move(fake_observer));
  }

  // Wait until all observers receive all samples
  base::RunLoop().RunUntilIdle();

  for (const auto& observer : observers_)
    EXPECT_TRUE(observer->NoRemainingFailures());

  // Remove clients
  for (auto& client_data : clients_data_)
    handler_->RemoveClient(&client_data);
}

class SamplesHandlerFusionTestWithParam
    : public ::testing::TestWithParam<std::vector<std::pair<double, double>>>,
      public SamplesHandlerFusionTestBase {
 protected:
  void SetUp() override { SetUpBase(); }

  void TearDown() override { TearDownBase(); }

  void SetUpAccel() {
    accel_ = std::make_unique<libmems::fakes::FakeIioDevice>(
        nullptr, fakes::kAccelDeviceName, fakes::kAccelDeviceId);

    for (const auto& channel : libmems::fakes::kFakeAccelChns) {
      accel_->AddChannel(
          std::make_unique<libmems::fakes::FakeIioChannel>(channel, true));
    }

    EXPECT_TRUE(accel_->WriteDoubleAttribute(libmems::kSamplingFrequencyAttr,
                                             kFooFrequency));
    accel_->CreateBuffer();
  }

  void OnSampleAvailable(const base::flat_map<int32_t, int64_t>& sample) {
    if (handler_)
      handler_->OnSampleAvailableOnThread(sample);
  }

  void ReadSamples(int num) {
    for (int i = 0; i < num; ++i) {
      auto sample_opt = accel_->ReadSample();
      if (!sample_opt.has_value()) {
        --i;
        // Pass an invalid sample to trigger a READ_FAILED.
        OnSampleAvailable(base::flat_map<int32_t, int64_t>());
        continue;
      }

      OnSampleAvailable(sample_opt.value());
    }
  }

  std::unique_ptr<libmems::fakes::FakeIioDevice> accel_;
};

// Add clients with the first frequencies set, update clients with the second
// frequencies, and remove clients. Clients' frequencies and the sample
// handler's |sampling_frequency_| are checked after each modification.
TEST_P(SamplesHandlerFusionTestWithParam, UpdateFrequency) {
  clients_data_.reserve(GetParam().size());

  std::multiset<double> frequencies;

  // Add clients
  for (size_t i = 0; i < GetParam().size(); ++i) {
    clients_data_.emplace_back(ClientData(i));
    ClientData& client_data = clients_data_[i];

    // At least one channel enabled
    client_data.enabled_chn_indices.emplace(3);  // timestamp
    client_data.timeout = 0;
    client_data.frequency = GetParam()[i].first;

    handler_->AddClient(&client_data, GetRemote());

    frequencies.emplace(FixFrequency(client_data.frequency));
    EXPECT_EQ(frequency_, FixFrequencyWithMin(*frequencies.rbegin()));
  }

  // Update clients' frequencies
  for (size_t i = 0; i < GetParam().size(); ++i) {
    ClientData& client_data = clients_data_[i];

    double new_freq = GetParam()[i].second;
    handler_->UpdateFrequency(&client_data, new_freq);

    auto it = frequencies.find(FixFrequency(GetParam()[i].first));
    EXPECT_TRUE(it != frequencies.end());
    frequencies.erase(it);
    frequencies.emplace(FixFrequency(new_freq));

    EXPECT_EQ(frequency_, FixFrequencyWithMin(*frequencies.rbegin()));
  }

  // Remove clients
  for (size_t i = 0; i < GetParam().size(); ++i) {
    ClientData& client_data = clients_data_[i];

    handler_->RemoveClient(&client_data);
    auto it = frequencies.find(FixFrequency(GetParam()[i].second));
    EXPECT_TRUE(it != frequencies.end());
    frequencies.erase(it);

    EXPECT_EQ(frequency_, i == GetParam().size() - 1
                              ? 0.0
                              : FixFrequencyWithMin(*frequencies.rbegin()));
  }
}

// Add all clients into the sample handler, read the first |kPauseIndex|
// samples and pause reading, update clients' frequencies and enable accel_y
// channel, and read the rest samples. All samples are checked when received by
// observers.
TEST_P(SamplesHandlerFusionTestWithParam, ReadSamplesWithFrequency) {
  SetUpAccel();

  std::multiset<std::pair<int, cros::mojom::ObserverErrorType>> rf_failures;
  for (int i = 0; i < kNumFailures; ++i) {
    int k = base::RandInt(0, std::size(libmems::fakes::kFakeAccelSamples) - 1);

    accel_->AddFailedReadAtKthSample(k);
    rf_failures.insert(
        std::make_pair(k, cros::mojom::ObserverErrorType::READ_FAILED));
  }

  clients_data_.reserve(GetParam().size());

  double max_freq = -1, max_freq2 = -1;
  for (size_t i = 0; i < GetParam().size(); ++i) {
    max_freq = std::max(max_freq, GetParam()[i].first);
    max_freq2 = std::max(max_freq2, GetParam()[i].second);
  }

  max_freq = FixFrequencyWithMin(max_freq);
  max_freq2 = FixFrequencyWithMin(max_freq2);

  for (size_t i = 0; i < GetParam().size(); ++i) {
    clients_data_.emplace_back(ClientData(i));
    ClientData& client_data = clients_data_[i];

    client_data.enabled_chn_indices.emplace(0);  // gravity_x
    client_data.enabled_chn_indices.emplace(2);  // gravity_z
    client_data.enabled_chn_indices.emplace(3);  // timestamp
    client_data.frequency = GetParam()[i].first;

    auto failures = rf_failures;
    if (GetParam()[i].first == 0.0) {
      while (!failures.empty() && failures.begin()->first < fakes::kPauseIndex)
        failures.erase(failures.begin());

      failures.insert(
          std::make_pair(0, cros::mojom::ObserverErrorType::FREQUENCY_INVALID));
    }

    // The fake observer needs |max_freq| and |max_freq2| to calculate the
    // correct values of samples
    auto fake_observer = fakes::FakeSamplesObserver::Create(
        accel_.get(), std::move(failures), FixFrequency(GetParam()[i].first),
        FixFrequency(GetParam()[i].second), max_freq, max_freq2);

    handler_->AddClient(&client_data, fake_observer->GetRemote());

    observers_.emplace_back(std::move(fake_observer));
  }

  EXPECT_EQ(frequency_, max_freq);

  // Read |fakes::kPauseIndex| samples.
  ReadSamples(fakes::kPauseIndex);

  for (int i = 0; i < clients_data_.size(); ++i) {
    ClientData& client_data = clients_data_[i];

    // Update to the second frequency
    handler_->UpdateFrequency(&client_data, GetParam()[i].second);

    client_data.enabled_chn_indices.emplace(1);  // gravity_y
  }

  // Read the rest samples.
  ReadSamples(std::size(libmems::fakes::kFakeAccelSamples) -
              fakes::kPauseIndex);

  EXPECT_EQ(frequency_, max_freq2);

  // Wait until all observers receive all samples
  base::RunLoop().RunUntilIdle();

  for (const auto& observer : observers_)
    EXPECT_TRUE(observer->FinishedObserving());

  // Remove clients
  for (auto& client_data : clients_data_)
    handler_->RemoveClient(&client_data);
}

INSTANTIATE_TEST_SUITE_P(
    SamplesHandlerFusionTestWithParamRun,
    SamplesHandlerFusionTestWithParam,
    ::testing::Values(std::vector<std::pair<double, double>>(3, {10.0, 10.0}),
                      std::vector<std::pair<double, double>>{
                          {20.0, 50.0}, {10.0, 10.0}, {2.0, 3.0}},
                      std::vector<std::pair<double, double>>{
                          {10.0, 20.0}, {20.0, 30.0}, {0.0, 0.0}},
                      std::vector<std::pair<double, double>>{
                          {80.0, 50.0}, {10.0, 10.0}, {2.0, 3.0}},
                      std::vector<std::pair<double, double>>{
                          {10.0, 40.0}, {0.0, 20.0}, {2.0, 3.0}, {40.0, 10.0}},
                      std::vector<std::pair<double, double>>{
                          {2.0, 10.0}, {10.0, 30.0}, {80.0, 0.0}},
                      std::vector<std::pair<double, double>>{
                          {0.0, 10.0}, {10.0, 30.0}, {80.0, 60.0}},
                      std::vector<std::pair<double, double>>{
                          {2.0, 10.0}, {50.0, 30.0}, {80.0, 60.0}},
                      std::vector<std::pair<double, double>>{{20.0, 30.0},
                                                             {10.0, 10.0}}));

}  // namespace iioservice
