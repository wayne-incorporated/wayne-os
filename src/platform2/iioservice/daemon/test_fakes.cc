// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "iioservice/daemon/test_fakes.h"

#include <algorithm>
#include <iterator>
#include <vector>

#include <gtest/gtest.h>
#include <libmems/common_types.h>
#include <libmems/test_fakes.h>

#include <base/check.h>
#include <base/check_op.h>

namespace iioservice {

namespace fakes {

namespace {

int64_t CalcMovingAverage(const std::vector<int64_t>& values) {
  int64_t size = values.size();
  int64_t value_total = 0, sum = 0;
  for (int64_t i = size - 1; i >= 0; --i) {
    sum += values[i];
    value_total += sum;
  }

  return value_total / ((size + 1) * size / 2);
}

}  // namespace

// static
FakeSamplesHandler::ScopedFakeSamplesHandler FakeSamplesHandler::Create(
    scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    DeviceData* const device_data,
    libmems::fakes::FakeIioDevice* fake_iio_device) {
  ScopedFakeSamplesHandler handler(nullptr, SamplesHandlerDeleter);
  double min_freq, max_freq;
  if (!fake_iio_device->GetMinMaxFrequency(&min_freq, &max_freq))
    return handler;

  handler.reset(new FakeSamplesHandler(std::move(ipc_task_runner),
                                       std::move(task_runner), device_data,
                                       fake_iio_device, min_freq, max_freq));
  return handler;
}

void FakeSamplesHandler::ResumeReading() {
  sample_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&FakeSamplesHandler::ResumeReadingOnThread,
                                weak_factory_.GetWeakPtr()));
}

void FakeSamplesHandler::CheckRequestedFrequency(double max_freq) {
  sample_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&FakeSamplesHandler::CheckRequestedFrequencyOnThread,
                     weak_factory_.GetWeakPtr(), max_freq));
}

FakeSamplesHandler::FakeSamplesHandler(
    scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    DeviceData* const device_data,
    libmems::fakes::FakeIioDevice* fake_iio_device,
    double min_freq,
    double max_freq)
    : SamplesHandler(std::move(ipc_task_runner),
                     std::move(task_runner),
                     device_data,
                     min_freq,
                     max_freq),
      fake_iio_device_(fake_iio_device) {}

void FakeSamplesHandler::ResumeReadingOnThread() {
  CHECK(sample_task_runner_->BelongsToCurrentThread());

  fake_iio_device_->ResumeReadingSamples();
}

void FakeSamplesHandler::CheckRequestedFrequencyOnThread(double max_freq) {
  CHECK(sample_task_runner_->BelongsToCurrentThread());

  CHECK_EQ(max_freq, requested_frequency_);
}

// static
std::unique_ptr<FakeSamplesObserver> FakeSamplesObserver::Create(
    libmems::IioDevice* device,
    std::multiset<std::pair<int, cros::mojom::ObserverErrorType>> failures,
    double frequency,
    double frequency2,
    double dev_frequency,
    double dev_frequency2,
    int pause_index) {
  std::unique_ptr<FakeSamplesObserver> handler(new FakeSamplesObserver(
      device, std::move(failures), frequency, frequency2, dev_frequency,
      dev_frequency2, pause_index));

  return handler;
}

FakeSamplesObserver::~FakeSamplesObserver() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
}

void FakeSamplesObserver::OnSampleUpdated(
    const libmems::IioDevice::IioSample& sample) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(failures_.empty() || failures_.begin()->first > sample_index_);

  sample_ = sample;

  int step = GetStep();
  CHECK_GE(step, 1);

  CHECK_GT(std::size(libmems::fakes::kFakeAccelSamples),
           sample_index_ + step - 1);

  if (device_->GetId() == kAccelDeviceId) {
    for (int chnIndex = 0; chnIndex < std::size(libmems::fakes::kFakeAccelChns);
         ++chnIndex) {
      auto it = sample.find(chnIndex);

      // channel: accel_y isn't enabled before |pause_index_|
      if (sample_index_ + step - 1 < pause_index_ && chnIndex == 1) {
        CHECK(it == sample.end());
        continue;
      }

      CHECK(it != sample.end());

      // Check timestamp channel
      if (strncmp(libmems::fakes::kFakeAccelChns[chnIndex],
                  libmems::kTimestampAttr,
                  strlen(libmems::kTimestampAttr)) == 0) {
        CHECK_EQ(it->second,
                 GetFakeAccelSamples(sample_index_ + step - 1, chnIndex));
        continue;
      }

      // Check other channels
      std::vector<int64_t> values;
      for (int index = 0; index < step; ++index) {
        if (chnIndex == 1 && sample_index_ + index < pause_index_) {
          values.push_back(GetFakeAccelSamples(pause_index_, chnIndex));
        } else {
          values.push_back(
              GetFakeAccelSamples(sample_index_ + index, chnIndex));
        }
      }

      CHECK_EQ(it->second, CalcMovingAverage(values));
    }
  } else {
    auto channels = device_->GetAllChannels();
    for (size_t i = 0; i < channels.size(); ++i) {
      auto raw_value = channels[i]->ReadNumberAttribute(libmems::kRawAttr);
      if (!raw_value.has_value())
        continue;

      auto it = sample.find(i);
      CHECK(it != sample.end());
      CHECK_EQ(raw_value.value(), it->second);
    }
  }

  sample_index_ += step;
}

void FakeSamplesObserver::OnErrorOccurred(cros::mojom::ObserverErrorType type) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(!failures_.empty());
  CHECK_EQ(failures_.begin()->second, type);

  if (type != cros::mojom::ObserverErrorType::FREQUENCY_INVALID)
    CHECK_LE(failures_.begin()->first, sample_index_ + GetStep());
  else
    CHECK_EQ(frequency_, 0.0);

  failures_.erase(failures_.begin());
}

mojo::PendingRemote<cros::mojom::SensorDeviceSamplesObserver>
FakeSamplesObserver::GetRemote() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(!receiver_.is_bound());

  auto remote = receiver_.BindNewPipeAndPassRemote();
  receiver_.set_disconnect_handler(base::BindOnce(
      &FakeSamplesObserver::OnObserverDisconnect, weak_factory_.GetWeakPtr()));
  return remote;
}

bool FakeSamplesObserver::is_bound() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  return receiver_.is_bound();
}

bool FakeSamplesObserver::FinishedObserving() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  int step = GetStep();

  return (frequency2_ == 0.0 && sample_index_ + step - 1 >= pause_index_) ||
         sample_index_ + step - 1 >=
             std::size(libmems::fakes::kFakeAccelSamples);
}

bool FakeSamplesObserver::NoRemainingFailures() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  return failures_.empty();
}

int FakeSamplesObserver::GetSampleIndex() const {
  return sample_index_;
}

const libmems::IioDevice::IioSample& FakeSamplesObserver::GetLatestSample()
    const {
  return sample_;
}

FakeSamplesObserver::FakeSamplesObserver(
    libmems::IioDevice* device,
    std::multiset<std::pair<int, cros::mojom::ObserverErrorType>> failures,
    double frequency,
    double frequency2,
    double dev_frequency,
    double dev_frequency2,
    int pause_index)
    : device_(device),
      failures_(std::move(failures)),
      frequency_(frequency),
      frequency2_(frequency2),
      dev_frequency_(dev_frequency),
      dev_frequency2_(dev_frequency2),
      pause_index_(pause_index) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK_GE(frequency_, 0.0);
  CHECK_GE(frequency2_, 0.0);
  CHECK_GE(dev_frequency_, libmems::kFrequencyEpsilon);
  CHECK_GE(dev_frequency2_, libmems::kFrequencyEpsilon);

  if (frequency_ == 0.0) {
    if (frequency2_ == 0.0)
      sample_index_ = std::size(libmems::fakes::kFakeAccelSamples);
    else
      sample_index_ = pause_index_;
  }

  if (device_) {
    with_accel_matrix_ =
        device_->ReadStringAttribute(kAccelMatrixAttribute).has_value();
  }
}

void FakeSamplesObserver::OnObserverDisconnect() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  receiver_.reset();
}

int FakeSamplesObserver::GetStep() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK_GE(dev_frequency_, libmems::kFrequencyEpsilon);

  int step = std::size(libmems::fakes::kFakeAccelSamples);
  if (frequency_ >= libmems::kFrequencyEpsilon)
    step = dev_frequency_ / frequency_;

  if (sample_index_ + step - 1 < pause_index_)
    return step;

  if (frequency2_ < libmems::kFrequencyEpsilon)
    return std::size(libmems::fakes::kFakeAccelSamples);

  int step2 = dev_frequency2_ / frequency2_;

  return std::max(pause_index_ - sample_index_ + 1, step2);
}

int64_t FakeSamplesObserver::GetFakeAccelSamples(int sample_index,
                                                 int chnIndex) {
  int64_t value = libmems::fakes::kFakeAccelSamples[sample_index][chnIndex];
  if (with_accel_matrix_) {
    if (chnIndex == 0 || chnIndex == 1)
      value *= -1;
  }

  return value;
}

FakeEventsObserver::FakeEventsObserver(
    libmems::fakes::FakeIioDevice* device,
    std::multiset<std::pair<int, cros::mojom::ObserverErrorType>> failures,
    std::set<int32_t> event_indices)
    : device_(device),
      failures_(std::move(failures)),
      event_indices_(std::move(event_indices)) {
  event_index_ = -1;
  NextEventIndex();
}

FakeEventsObserver::~FakeEventsObserver() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
}

void FakeEventsObserver::OnEventUpdated(cros::mojom::IioEventPtr event) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  EXPECT_EQ(event->timestamp / 1000000000LL, event_index_);

  auto size = device_->GetAllEvents().size();
  libmems::IioEvent* iio_event = device_->GetEvent(event_index_ % size);

  EXPECT_EQ(ConvertChanType(iio_event->GetChannelType()), event->chan_type);
  EXPECT_EQ(ConvertEventType(iio_event->GetEventType()), event->event_type);
  if (iio_event->GetDirection() == iio_event_direction::IIO_EV_DIR_EITHER) {
    if ((event_index_ / size) % 2 == 0) {
      EXPECT_EQ(event->direction,
                cros::mojom::IioEventDirection::IIO_EV_DIR_RISING);
    } else {
      EXPECT_EQ(event->direction,
                cros::mojom::IioEventDirection::IIO_EV_DIR_FALLING);
    }
  } else {
    EXPECT_EQ(ConvertDirection(iio_event->GetDirection()), event->direction);
  }
  EXPECT_EQ(iio_event->GetChannelNumber(), event->channel);

  NextEventIndex();
}

void FakeEventsObserver::OnErrorOccurred(cros::mojom::ObserverErrorType type) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(!failures_.empty());
  CHECK_EQ(failures_.begin()->second, type);

  failures_.erase(failures_.begin());
}

mojo::PendingRemote<cros::mojom::SensorDeviceEventsObserver>
FakeEventsObserver::GetRemote() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  auto remote = receiver_.BindNewPipeAndPassRemote();
  receiver_.set_disconnect_handler(base::BindOnce(
      &FakeEventsObserver::OnObserverDisconnect, weak_factory_.GetWeakPtr()));
  return remote;
}

bool FakeEventsObserver::is_bound() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  return receiver_.is_bound();
}

bool FakeEventsObserver::FinishedObserving() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  return event_index_ >= libmems::fakes::kEventNumber;
}

bool FakeEventsObserver::NoRemainingFailures() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  return failures_.empty();
}

int FakeEventsObserver::GetEventIndex() const {
  return event_index_;
}

void FakeEventsObserver::NextEventIndex() {
  if (event_index_ >= libmems::fakes::kEventNumber)
    return;

  auto size = device_->GetAllEvents().size();
  while (++event_index_ < libmems::fakes::kEventNumber) {
    if (base::Contains(event_indices_, event_index_ % size))
      break;
  }
}

void FakeEventsObserver::OnObserverDisconnect() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  receiver_.reset();
}

}  // namespace fakes

}  // namespace iioservice
