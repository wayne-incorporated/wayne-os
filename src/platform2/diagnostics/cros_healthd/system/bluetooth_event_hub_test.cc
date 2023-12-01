// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include <base/run_loop.h>
#include <base/test/task_environment.h>
#include <dbus/object_path.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/system/bluetooth_event_hub.h"
#include "diagnostics/cros_healthd/system/fake_bluetooth_event_hub.h"
#include "diagnostics/dbus_bindings/bluetooth/dbus-proxy-mocks.h"

namespace diagnostics {
namespace {

using ::testing::_;
using ::testing::Invoke;
using ::testing::StrictMock;

// Tests for the BluetoothEventHub class.
class BluetoothEventHubTest : public testing::Test {
 protected:
  BluetoothEventHubTest() = default;
  BluetoothEventHubTest(const BluetoothEventHubTest&) = delete;
  BluetoothEventHubTest& operator=(const BluetoothEventHubTest&) = delete;

  FakeBluetoothEventHub* fake_bluetooth_event_hub() const {
    return fake_bluetooth_event_hub_.get();
  }

  // Getter of mock proxy.
  org::bluez::Adapter1ProxyMock* mock_adapter_proxy() const {
    return static_cast<StrictMock<org::bluez::Adapter1ProxyMock>*>(
        adapter_proxy_.get());
  }
  org::bluez::Device1ProxyMock* mock_device_proxy() const {
    return static_cast<StrictMock<org::bluez::Device1ProxyMock>*>(
        device_proxy_.get());
  }

 private:
  base::test::TaskEnvironment task_environment_;
  std::unique_ptr<FakeBluetoothEventHub> fake_bluetooth_event_hub_ =
      std::make_unique<FakeBluetoothEventHub>();
  // Mock proxy.
  std::unique_ptr<org::bluez::Adapter1ProxyMock> adapter_proxy_ =
      std::make_unique<StrictMock<org::bluez::Adapter1ProxyMock>>();
  std::unique_ptr<org::bluez::Device1ProxyMock> device_proxy_ =
      std::make_unique<StrictMock<org::bluez::Device1ProxyMock>>();
};

}  // namespace

// Test that we will observe adapter property changed events when an adapter is
// added.
TEST_F(BluetoothEventHubTest, ObserveAdapterPropertyChanged) {
  base::RunLoop run_loop;
  EXPECT_CALL(*mock_adapter_proxy(), SetPropertyChangedCallback(_))
      .WillOnce(Invoke([&](auto _) { run_loop.Quit(); }));

  fake_bluetooth_event_hub()->SendAdapterAdded(mock_adapter_proxy());
  run_loop.Run();
}

// Test that we will observe device property changed events when an device is
// added.
TEST_F(BluetoothEventHubTest, ObserveDevicePropertyChanged) {
  base::RunLoop run_loop;
  EXPECT_CALL(*mock_device_proxy(), SetPropertyChangedCallback(_))
      .WillOnce(Invoke([&](auto _) { run_loop.Quit(); }));

  fake_bluetooth_event_hub()->SendDeviceAdded(mock_device_proxy());
  run_loop.Run();
}

}  // namespace diagnostics
