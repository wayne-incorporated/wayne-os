// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <mojo/public/cpp/bindings/pending_remote.h>

#include "diagnostics/cros_healthd/events/event_observer_test_future.h"
#include "diagnostics/cros_healthd/events/touchscreen_events_impl.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/mojom/public/cros_healthd_events.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

using ::testing::_;
using ::testing::WithArg;

// Tests for the TouchscreenEventsImpl class.
class TouchscreenEventsImplTest : public testing::Test {
 protected:
  TouchscreenEventsImplTest() = default;
  TouchscreenEventsImplTest(const TouchscreenEventsImplTest&) = delete;
  TouchscreenEventsImplTest& operator=(const TouchscreenEventsImplTest&) =
      delete;

  void SetUp() override {
    EXPECT_CALL(*mock_executor(), MonitorTouchscreen(_, _))
        .WillOnce(WithArg<0>([=](auto touchscreen_observer) {
          touchscreen_observer_.Bind(std::move(touchscreen_observer));
        }));
  }

  void AddEventObserver(mojo::PendingRemote<mojom::EventObserver> observer) {
    events_impl_.AddObserver(std::move(observer));
  }

  void EmitTouchscreenConnectedEvent(
      const mojom::TouchscreenConnectedEventPtr& event) {
    touchscreen_observer_->OnConnected(event.Clone());
  }

  void EmitTouchscreenTouchEvent(const mojom::TouchscreenTouchEventPtr& event) {
    touchscreen_observer_->OnTouch(event.Clone());
  }

 private:
  MockExecutor* mock_executor() { return mock_context_.mock_executor(); }

  base::test::TaskEnvironment task_environment_;
  MockContext mock_context_;
  TouchscreenEventsImpl events_impl_{&mock_context_};
  mojo::Remote<mojom::TouchscreenObserver> touchscreen_observer_;
};

// Test that we can receive touchscreen touch events.
TEST_F(TouchscreenEventsImplTest, TouchscreenTouchEvent) {
  mojom::TouchscreenTouchEvent fake_touch_event;
  fake_touch_event.touch_points.push_back(mojom::TouchPointInfo::New());

  EventObserverTestFuture event_observer;
  AddEventObserver(event_observer.BindNewPendingRemote());

  EmitTouchscreenTouchEvent(fake_touch_event.Clone());

  auto event = event_observer.WaitForEvent();
  ASSERT_TRUE(event->is_touchscreen_event_info());
  const auto& touchscreen_event_info = event->get_touchscreen_event_info();
  ASSERT_TRUE(touchscreen_event_info->is_touch_event());
  EXPECT_EQ(fake_touch_event, *touchscreen_event_info->get_touch_event());
}

// Test that we can receive touchscreen connected events.
TEST_F(TouchscreenEventsImplTest, TouchscreenConnectedEvent) {
  mojom::TouchscreenConnectedEvent fake_connected_event;
  fake_connected_event.max_x = 1;
  fake_connected_event.max_y = 2;

  EventObserverTestFuture event_observer;
  AddEventObserver(event_observer.BindNewPendingRemote());

  EmitTouchscreenConnectedEvent(fake_connected_event.Clone());

  auto event = event_observer.WaitForEvent();
  ASSERT_TRUE(event->is_touchscreen_event_info());
  const auto& touchscreen_event_info = event->get_touchscreen_event_info();
  ASSERT_TRUE(touchscreen_event_info->is_connected_event());
  EXPECT_EQ(fake_connected_event,
            *touchscreen_event_info->get_connected_event());
}

// Test that we can receive touchscreen connected events by multiple observers.
TEST_F(TouchscreenEventsImplTest,
       TouchscreenConnectedEventWithMultipleObservers) {
  mojom::TouchscreenConnectedEvent fake_connected_event;
  fake_connected_event.max_x = 1;
  fake_connected_event.max_y = 2;

  EventObserverTestFuture event_observer, event_observer2;
  AddEventObserver(event_observer.BindNewPendingRemote());
  AddEventObserver(event_observer2.BindNewPendingRemote());

  EmitTouchscreenConnectedEvent(fake_connected_event.Clone());

  auto check_result = [&fake_connected_event](mojom::EventInfoPtr event) {
    ASSERT_TRUE(event->is_touchscreen_event_info());
    const auto& touchscreen_event_info = event->get_touchscreen_event_info();
    ASSERT_TRUE(touchscreen_event_info->is_connected_event());
    EXPECT_EQ(fake_connected_event,
              *touchscreen_event_info->get_connected_event());
  };

  check_result(event_observer.WaitForEvent());
  check_result(event_observer2.WaitForEvent());
}

}  // namespace
}  // namespace diagnostics
