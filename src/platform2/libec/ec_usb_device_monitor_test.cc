// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <dbus/object_path.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <power_manager/proto_bindings/suspend.pb.h>

#include "libec/ec_usb_device_monitor.h"

namespace ec {

constexpr static int32_t kSuspendId = 1000;

class EcUsbDeviceMonitorTest : public testing::Test,
                               public EcUsbDeviceMonitor::Observer {
 public:
  EcUsbDeviceMonitorTest() {
    dbus::Bus::Options options;
    options.bus_type = dbus::Bus::SYSTEM;
    mock_bus_ = base::MakeRefCounted<dbus::MockBus>(options);

    power_manager_proxy_ = base::MakeRefCounted<dbus::MockObjectProxy>(
        mock_bus_.get(), power_manager::kPowerManagerServiceName,
        dbus::ObjectPath(power_manager::kPowerManagerServicePath));

    EXPECT_CALL(*mock_bus_.get(),
                GetObjectProxy(
                    power_manager::kPowerManagerServiceName,
                    dbus::ObjectPath(power_manager::kPowerManagerServicePath)))
        .WillOnce(testing::Return(power_manager_proxy_.get()));

    // Proxy expects a suspend done signal to be registered then stores callback
    // to call in future.
    EXPECT_CALL(*power_manager_proxy_,
                DoConnectToSignal(power_manager::kPowerManagerInterface,
                                  power_manager::kSuspendDoneSignal, testing::_,
                                  testing::_))
        .WillOnce(testing::SaveArg<2>(&suspend_done_callback_));
  }

  void SetUp() override { on_device_reconnected_called_ = false; }

  // EcUsbDeviceMonitor::Observer test implementation
  void OnDeviceReconnected() override { on_device_reconnected_called_ = true; }

 protected:
  void SendSuspendDone(int32_t suspend_id = kSuspendId) {
    dbus::Signal suspend_done_signal(power_manager::kPowerManagerInterface,
                                     power_manager::kSuspendDoneSignal);
    power_manager::SuspendDone message;
    message.set_suspend_id(suspend_id);
    ASSERT_TRUE(dbus::MessageWriter(&suspend_done_signal)
                    .AppendProtoAsArrayOfBytes(message));
    suspend_done_callback_.Run(&suspend_done_signal);
  }

  scoped_refptr<dbus::MockBus> mock_bus_;
  scoped_refptr<dbus::MockObjectProxy> power_manager_proxy_;
  dbus::ObjectProxy::SignalCallback suspend_done_callback_;
  bool on_device_reconnected_called_ = false;
};

// Ensure that PowerEventObservers are notified on power button down event.
TEST_F(EcUsbDeviceMonitorTest, SuspendDoneTest) {
  auto client = std::make_unique<EcUsbDeviceMonitor>(mock_bus_);

  client->AddObserver(this);
  SendSuspendDone();
  EXPECT_TRUE(on_device_reconnected_called_);
}

TEST_F(EcUsbDeviceMonitorTest, AddObserverRemoveObserverTest) {
  auto client = std::make_unique<EcUsbDeviceMonitor>(mock_bus_);

  // First verify observer is added and functions correctly
  client->AddObserver(this);
  SendSuspendDone();
  EXPECT_TRUE(on_device_reconnected_called_);

  // Then verify observer is removed and is no longer called
  on_device_reconnected_called_ = false;
  client->RemoveObserver(this);
  SendSuspendDone();
  EXPECT_FALSE(on_device_reconnected_called_);
}
}  // namespace ec
