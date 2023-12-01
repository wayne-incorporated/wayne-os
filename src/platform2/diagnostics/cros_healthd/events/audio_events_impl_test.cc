// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/functional/callback.h>
#include <base/run_loop.h>
#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include "cras/dbus-proxy-mocks.h"
#include "diagnostics/cros_healthd/events/audio_events_impl.h"
#include "diagnostics/cros_healthd/events/mock_event_observer.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/mojom/public/cros_healthd_events.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

using ::testing::_;
using ::testing::Invoke;
using ::testing::SaveArg;
using ::testing::StrictMock;

class MockAudioObserver : public mojom::CrosHealthdAudioObserver {
 public:
  explicit MockAudioObserver(
      mojo::PendingReceiver<mojom::CrosHealthdAudioObserver> receiver)
      : receiver_{this /* impl */, std::move(receiver)} {
    DCHECK(receiver_.is_bound());
  }
  MockAudioObserver(const MockAudioObserver&) = delete;
  MockAudioObserver& operator=(const MockAudioObserver&) = delete;

  MOCK_METHOD(void, OnUnderrun, (), (override));
  MOCK_METHOD(void, OnSevereUnderrun, (), (override));

 private:
  mojo::Receiver<mojom::CrosHealthdAudioObserver> receiver_;
};

// Tests for the AudioEventsImpl class.
class AudioEventsImplTest : public testing::Test {
 protected:
  AudioEventsImplTest() = default;
  AudioEventsImplTest(const AudioEventsImplTest&) = delete;
  AudioEventsImplTest& operator=(const AudioEventsImplTest&) = delete;

  void SetUp() override {
    EXPECT_CALL(*mock_context_.mock_cras_proxy(),
                DoRegisterUnderrunSignalHandler(_, _))
        .WillOnce(SaveArg<0>(&underrun_callback_));
    EXPECT_CALL(*mock_context_.mock_cras_proxy(),
                DoRegisterSevereUnderrunSignalHandler(_, _))
        .WillOnce(SaveArg<0>(&severe_underrun_callback_));

    audio_events_impl_ = std::make_unique<AudioEventsImpl>(&mock_context_);

    mojo::PendingRemote<mojom::EventObserver> observer;
    mojo::PendingReceiver<mojom::EventObserver> observer_receiver(
        observer.InitWithNewPipeAndPassReceiver());
    observer_ = std::make_unique<StrictMock<MockEventObserver>>(
        std::move(observer_receiver));
    audio_events_impl_->AddObserver(std::move(observer));

    mojo::PendingRemote<mojom::CrosHealthdAudioObserver> deprecated_observer;
    deprecated_observer_ = std::make_unique<StrictMock<MockAudioObserver>>(
        deprecated_observer.InitWithNewPipeAndPassReceiver());
    audio_events_impl_->AddObserver(std::move(deprecated_observer));
  }

  // Simulate signal is fired and then callback is run.
  void InvokeUnderrunEvent() { std::move(underrun_callback_).Run(); }
  void InvokeSevereUnderrunEvent() {
    std::move(severe_underrun_callback_).Run();
  }

  void SetExpectedEvent(mojom::AudioEventInfo::State state) {
    EXPECT_CALL(*mock_observer(), OnEvent(_))
        .WillOnce(Invoke([=](mojom::EventInfoPtr info) {
          EXPECT_TRUE(info->is_audio_event_info());
          const auto& audio_event_info = info->get_audio_event_info();
          EXPECT_EQ(audio_event_info->state, state);
        }));
  }

  MockEventObserver* mock_observer() { return observer_.get(); }
  MockAudioObserver* mock_deprecated_observer() {
    return deprecated_observer_.get();
  }

 private:
  base::test::TaskEnvironment task_environment_;
  MockContext mock_context_;
  std::unique_ptr<AudioEventsImpl> audio_events_impl_;
  std::unique_ptr<StrictMock<MockEventObserver>> observer_;
  std::unique_ptr<StrictMock<MockAudioObserver>> deprecated_observer_;
  base::OnceCallback<void()> underrun_callback_;
  base::OnceCallback<void()> severe_underrun_callback_;
};

TEST_F(AudioEventsImplTest, UnderrunEvent) {
  base::RunLoop run_loop;
  SetExpectedEvent(mojom::AudioEventInfo::State::kUnderrun);
  EXPECT_CALL(*mock_deprecated_observer(), OnUnderrun()).WillOnce(Invoke([&]() {
    run_loop.Quit();
  }));

  InvokeUnderrunEvent();

  run_loop.Run();
}

TEST_F(AudioEventsImplTest, SevereUnderrunEvent) {
  base::RunLoop run_loop;
  SetExpectedEvent(mojom::AudioEventInfo::State::kSevereUnderrun);
  EXPECT_CALL(*mock_deprecated_observer(), OnSevereUnderrun())
      .WillOnce(Invoke([&]() { run_loop.Quit(); }));

  InvokeSevereUnderrunEvent();

  run_loop.Run();
}

}  // namespace
}  // namespace diagnostics
