// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include <memory>
#include <utility>
#include <vector>

#include <base/notreached.h>
#include <base/rand_util.h>
#include <base/test/task_environment.h>
#include <libmems/test_fakes.h>
#include <mojo/public/cpp/bindings/receiver_set.h>

#include "iioservice/daemon/events_handler.h"
#include "iioservice/daemon/test_fakes.h"

namespace iioservice {

namespace {

constexpr int kNumFailures = 10;

// An observer that does nothing to events or errors. Instead, it simply waits
// for the mojo disconnection and calls |quit_closure|.
class FakeObserver : cros::mojom::SensorDeviceEventsObserver {
 public:
  explicit FakeObserver(base::RepeatingClosure quit_closure)
      : quit_closure_(std::move(quit_closure)) {}

  mojo::PendingRemote<cros::mojom::SensorDeviceEventsObserver> GetRemote() {
    CHECK(!receiver_.is_bound());
    auto pending_remote = receiver_.BindNewPipeAndPassRemote();
    receiver_.set_disconnect_handler(base::BindOnce(
        &FakeObserver::OnObserverDisconnect, base::Unretained(this)));
    return pending_remote;
  }

  // cros::mojom::SensorDeviceEventsObserver overrides:
  void OnEventUpdated(cros::mojom::IioEventPtr event) override {}
  void OnErrorOccurred(cros::mojom::ObserverErrorType type) override {}

 private:
  void OnObserverDisconnect() {
    receiver_.reset();
    quit_closure_.Run();
  }

  base::RepeatingClosure quit_closure_;
  mojo::Receiver<cros::mojom::SensorDeviceEventsObserver> receiver_{this};
};

class EventsHandlerTest : public ::testing::Test,
                          public cros::mojom::SensorDeviceEventsObserver {
 public:
  mojo::PendingRemote<cros::mojom::SensorDeviceEventsObserver> GetRemote() {
    mojo::PendingRemote<cros::mojom::SensorDeviceEventsObserver> remote;
    receiver_set_.Add(this, remote.InitWithNewPipeAndPassReceiver());
    return remote;
  }

  // cros::mojom::SensorDeviceEventsObserver overrides:
  void OnEventUpdated(cros::mojom::IioEventPtr event) override { NOTREACHED(); }
  void OnErrorOccurred(cros::mojom::ObserverErrorType type) override {
    NOTREACHED();
  }

 protected:
  void SetUp() override {
    device_ =
        std::make_unique<libmems::fakes::FakeIioDevice>(nullptr, "sx9310", 0);

    for (int i = 0; i < 4; ++i) {
      device_->AddEvent(std::make_unique<libmems::fakes::FakeIioEvent>(
          iio_chan_type::IIO_PROXIMITY, iio_event_type::IIO_EV_TYPE_THRESH,
          iio_event_direction::IIO_EV_DIR_EITHER, i));
    }

    handler_ = EventsHandler::Create(
        task_environment_.GetMainThreadTaskRunner(),
        task_environment_.GetMainThreadTaskRunner(), device_.get());
    EXPECT_TRUE(handler_);
  }

  void TearDown() override {
    handler_.reset();
    observers_.clear();

    base::RunLoop().RunUntilIdle();
  }

  base::test::SingleThreadTaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME,
      base::test::TaskEnvironment::MainThreadType::IO};

  std::unique_ptr<libmems::fakes::FakeIioDevice> device_;

  EventsHandler::ScopedEventsHandler handler_ = {
      nullptr, EventsHandler::EventsHandlerDeleter};
  std::vector<std::unique_ptr<fakes::FakeEventsObserver>> observers_;
  mojo::ReceiverSet<cros::mojom::SensorDeviceEventsObserver> receiver_set_;
};

TEST_F(EventsHandlerTest, AddClient) {
  // No events in this test
  device_->SetPauseCallbackAtKthEvents(0, base::BindOnce([]() {}));

  handler_->AddClient({3}, GetRemote());  // timestamp
  handler_->AddClient({3}, GetRemote());  // Can be called multiple times.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(receiver_set_.size(), 2);
}

// Add all clients into the event handler, and read all events. All events are
// checked when received by observers.
TEST_F(EventsHandlerTest, ReadEventsWithEnabledFakeIioEvents) {
  // Set the pause in the beginning to prevent reading events before all
  // clients added.
  device_->SetPauseCallbackAtKthEvents(0, base::BindOnce([]() {}));

  std::multiset<std::pair<int, cros::mojom::ObserverErrorType>> failures;
  for (int i = 0; i < kNumFailures; ++i) {
    int k = base::RandInt(0, libmems::fakes::kEventNumber - 1);

    device_->AddFailedReadAtKthEvent(k);
    failures.insert(
        std::make_pair(k, cros::mojom::ObserverErrorType::READ_FAILED));
  }

  std::vector<std::set<int32_t>> clients = {
      {0, 1},
      {0},
  };

  for (size_t i = 0; i < clients.size(); ++i) {
    // The fake observer needs |max_freq| and |max_freq2| to calculate the
    // correct values of events
    auto fake_observer = std::make_unique<fakes::FakeEventsObserver>(
        device_.get(), failures, clients[i]);

    handler_->AddClient(
        std::vector<int32_t>(clients[i].begin(), clients[i].end()),
        fake_observer->GetRemote());

    observers_.emplace_back(std::move(fake_observer));
  }

  // TODO(chenghaoyang): pause and enable other FakeIioEvents.

  device_->ResumeReadingEvents();

  // Wait until all observers receive all events.
  base::RunLoop().RunUntilIdle();

  for (const auto& observer : observers_)
    EXPECT_TRUE(observer->FinishedObserving());
}

}  // namespace

}  // namespace iioservice
