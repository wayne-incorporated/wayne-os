// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/test/task_environment.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/events/bluetooth_events_impl.h"
#include "diagnostics/cros_healthd/events/event_observer_test_future.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/mojom/public/cros_healthd_events.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

// Tests for the BluetoothEventsImpl class.
class BluetoothEventsImplTest : public testing::Test {
 protected:
  BluetoothEventsImplTest() = default;
  BluetoothEventsImplTest(const BluetoothEventsImplTest&) = delete;
  BluetoothEventsImplTest& operator=(const BluetoothEventsImplTest&) = delete;

  void SetUp() override {
    bluetooth_events_impl_.AddObserver(observer_.BindNewPendingRemote());
  }

  FakeBluetoothEventHub* fake_bluetooth_event_hub() const {
    return mock_context_.fake_bluetooth_event_hub();
  }

  void WaitAndCheckEvent(mojom::BluetoothEventInfo::State state) {
    auto info = observer_.WaitForEvent();
    ASSERT_TRUE(info->is_bluetooth_event_info());
    const auto& bluetooth_event_info = info->get_bluetooth_event_info();
    EXPECT_EQ(bluetooth_event_info->state, state);
  }

 private:
  base::test::TaskEnvironment task_environment_;
  MockContext mock_context_;
  BluetoothEventsImpl bluetooth_events_impl_{&mock_context_};
  EventObserverTestFuture observer_;
};

}  // namespace

// Test that we can receive an adapter added event.
TEST_F(BluetoothEventsImplTest, ReceiveAdapterAddedEvent) {
  fake_bluetooth_event_hub()->SendAdapterAdded();
  WaitAndCheckEvent(mojom::BluetoothEventInfo::State::kAdapterAdded);
}

// Test that we can receive an adapter removed event.
TEST_F(BluetoothEventsImplTest, ReceiveAdapterRemovedEvent) {
  fake_bluetooth_event_hub()->SendAdapterRemoved();
  WaitAndCheckEvent(mojom::BluetoothEventInfo::State::kAdapterRemoved);
}

// Test that we can receive an adapter property changed event.
TEST_F(BluetoothEventsImplTest, ReceiveAdapterPropertyChangedEvent) {
  fake_bluetooth_event_hub()->SendAdapterPropertyChanged();
  WaitAndCheckEvent(mojom::BluetoothEventInfo::State::kAdapterPropertyChanged);
}

// Test that we can receive a device added event.
TEST_F(BluetoothEventsImplTest, ReceiveDeviceAddedEvent) {
  fake_bluetooth_event_hub()->SendDeviceAdded();
  WaitAndCheckEvent(mojom::BluetoothEventInfo::State::kDeviceAdded);
}

// Test that we can receive a device removed event.
TEST_F(BluetoothEventsImplTest, ReceiveDeviceRemovedEvent) {
  fake_bluetooth_event_hub()->SendDeviceRemoved();
  WaitAndCheckEvent(mojom::BluetoothEventInfo::State::kDeviceRemoved);
}

// Test that we can receive a device property changed event.
TEST_F(BluetoothEventsImplTest, ReceiveDevicePropertyChangedEvent) {
  fake_bluetooth_event_hub()->SendDevicePropertyChanged();
  WaitAndCheckEvent(mojom::BluetoothEventInfo::State::kDevicePropertyChanged);
}

}  // namespace diagnostics
