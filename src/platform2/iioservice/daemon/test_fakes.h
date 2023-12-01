// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IIOSERVICE_DAEMON_TEST_FAKES_H_
#define IIOSERVICE_DAEMON_TEST_FAKES_H_

#include <memory>
#include <optional>
#include <set>
#include <utility>

#include <base/functional/callback.h>
#include <base/run_loop.h>
#include <base/sequence_checker.h>
#include <base/task/single_thread_task_runner.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include <libmems/iio_device.h>
#include <libmems/test_fakes.h>

#include "iioservice/daemon/samples_handler.h"
#include "iioservice/mojo/sensor.mojom.h"

namespace iioservice {

namespace fakes {

constexpr char kAccelDeviceName[] = "FakeAccelDevice";
constexpr int kAccelDeviceId = 1;

constexpr char kFakeSamplingFrequencyAvailable[] =
    "0.000000 5.000000 40.000000";

constexpr int kPauseIndex = 50;

class FakeSamplesHandler : public SamplesHandler {
 public:
  using ScopedFakeSamplesHandler =
      std::unique_ptr<FakeSamplesHandler, decltype(&SamplesHandlerDeleter)>;

  static ScopedFakeSamplesHandler Create(
      scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner,
      DeviceData* const device_data,
      libmems::fakes::FakeIioDevice* fake_iio_device);

  void ResumeReading();
  void CheckRequestedFrequency(double max_freq);

 private:
  FakeSamplesHandler(
      scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner,
      DeviceData* const device_data,
      libmems::fakes::FakeIioDevice* fake_iio_device,
      double min_freq,
      double max_freq);

  void ResumeReadingOnThread();
  void CheckRequestedFrequencyOnThread(double max_freq);

  libmems::fakes::FakeIioDevice* fake_iio_device_;

  base::WeakPtrFactory<FakeSamplesHandler> weak_factory_{this};
};

class FakeObserver : cros::mojom::SensorDeviceSamplesObserver {
 public:
  explicit FakeObserver(base::RepeatingClosure quit_closure)
      : quit_closure_(std::move(quit_closure)) {}

  mojo::PendingRemote<cros::mojom::SensorDeviceSamplesObserver> GetRemote() {
    CHECK(!receiver_.is_bound());
    auto pending_remote = receiver_.BindNewPipeAndPassRemote();
    receiver_.set_disconnect_handler(base::BindOnce(
        &FakeObserver::OnObserverDisconnect, base::Unretained(this)));
    return pending_remote;
  }

  std::optional<cros::mojom::ObserverErrorType>& GetError() { return type_; }
  void WaitForError(cros::mojom::ObserverErrorType type) {
    expected_type_ = type;

    base::RunLoop run_loop;
    quit_closure_ = run_loop.QuitClosure();
    run_loop.Run();
  }

  // cros::mojom::SensorDeviceSamplesObserver overrides:
  void OnSampleUpdated(const libmems::IioDevice::IioSample& sample) override {}
  void OnErrorOccurred(cros::mojom::ObserverErrorType type) override {
    type_ = type;
    if (type == expected_type_)
      quit_closure_.Run();
  }

 private:
  void OnObserverDisconnect() {
    receiver_.reset();
    if (quit_closure_)
      quit_closure_.Run();
  }

  base::RepeatingClosure quit_closure_;

  cros::mojom::ObserverErrorType expected_type_;
  base::RepeatingClosure error_quit_closure_;
  mojo::Receiver<cros::mojom::SensorDeviceSamplesObserver> receiver_{this};
  std::optional<cros::mojom::ObserverErrorType> type_;
};

class FakeSamplesObserver : public cros::mojom::SensorDeviceSamplesObserver {
 public:
  static std::unique_ptr<FakeSamplesObserver> Create(
      libmems::IioDevice* device,
      std::multiset<std::pair<int, cros::mojom::ObserverErrorType>> failures,
      double frequency,
      double frequency2,
      double dev_frequency,
      double dev_frequency2,
      int pause_index = kPauseIndex);

  ~FakeSamplesObserver() override;

  // cros::mojom::SensorDeviceSamplesObserver overrides:
  void OnSampleUpdated(const libmems::IioDevice::IioSample& sample) override;
  void OnErrorOccurred(cros::mojom::ObserverErrorType type) override;

  mojo::PendingRemote<cros::mojom::SensorDeviceSamplesObserver> GetRemote();
  bool is_bound() const;

  bool FinishedObserving() const;
  bool NoRemainingFailures() const;

  int GetSampleIndex() const;
  const libmems::IioDevice::IioSample& GetLatestSample() const;

 private:
  FakeSamplesObserver(
      libmems::IioDevice* device,
      std::multiset<std::pair<int, cros::mojom::ObserverErrorType>> failures,
      double frequency,
      double frequency2,
      double dev_frequency,
      double dev_frequency2,
      int pause_index = kPauseIndex);

  void OnObserverDisconnect();

  int GetStep() const;
  int64_t GetFakeAccelSamples(int sample_index, int chnIndex);

  libmems::IioDevice* device_;

  std::multiset<std::pair<int, cros::mojom::ObserverErrorType>> failures_;

  double frequency_;
  double frequency2_;
  double dev_frequency_;
  double dev_frequency2_;
  int pause_index_;

  bool with_accel_matrix_ = false;

  int sample_index_ = 0;
  // Latest sample.
  libmems::IioDevice::IioSample sample_;

  mojo::Receiver<cros::mojom::SensorDeviceSamplesObserver> receiver_{this};

  SEQUENCE_CHECKER(sequence_checker_);

  base::WeakPtrFactory<FakeSamplesObserver> weak_factory_{this};
};

class FakeEventsObserver : public cros::mojom::SensorDeviceEventsObserver {
 public:
  FakeEventsObserver(
      libmems::fakes::FakeIioDevice* device,
      std::multiset<std::pair<int, cros::mojom::ObserverErrorType>> failures,
      std::set<int32_t> event_indices);

  ~FakeEventsObserver() override;

  // cros::mojom::SensorDeviceEventsObserver overrides:
  void OnEventUpdated(cros::mojom::IioEventPtr event) override;
  void OnErrorOccurred(cros::mojom::ObserverErrorType type) override;

  mojo::PendingRemote<cros::mojom::SensorDeviceEventsObserver> GetRemote();
  bool is_bound() const;

  bool FinishedObserving() const;
  bool NoRemainingFailures() const;

  int GetEventIndex() const;

  void NextEventIndex();

 private:
  void OnObserverDisconnect();

  libmems::fakes::FakeIioDevice* device_;
  std::multiset<std::pair<int, cros::mojom::ObserverErrorType>> failures_;
  std::set<int32_t> event_indices_;

  int event_index_;

  mojo::Receiver<cros::mojom::SensorDeviceEventsObserver> receiver_{this};

  SEQUENCE_CHECKER(sequence_checker_);

  base::WeakPtrFactory<FakeEventsObserver> weak_factory_{this};
};

}  // namespace fakes

}  // namespace iioservice

#endif  // IIOSERVICE_DAEMON_TEST_FAKES_H_
