// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "biod/power_manager_client.h"

#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <dbus/object_path.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <power_manager/proto_bindings/input_event.pb.h>

#include "biod/power_event_observer.h"

namespace biod {

class PowerManagerClientTest : public testing::Test, public PowerEventObserver {
 public:
  PowerManagerClientTest() {
    dbus::Bus::Options options;
    options.bus_type = dbus::Bus::SYSTEM;
    mock_bus_ = base::MakeRefCounted<dbus::MockBus>(options);

    power_manager_proxy_ = base::MakeRefCounted<dbus::MockObjectProxy>(
        mock_bus_.get(), power_manager::kPowerManagerServiceName,
        dbus::ObjectPath(power_manager::kPowerManagerServicePath));

    // Set an expectation so that the MockBus will return our mock power manager
    // proxy.
    EXPECT_CALL(*mock_bus_.get(),
                GetObjectProxy(
                    power_manager::kPowerManagerServiceName,
                    dbus::ObjectPath(power_manager::kPowerManagerServicePath)))
        .WillOnce(testing::Return(power_manager_proxy_.get()));

    EXPECT_CALL(*power_manager_proxy_,
                DoConnectToSignal(power_manager::kPowerManagerInterface,
                                  power_manager::kInputEventSignal, testing::_,
                                  testing::_))
        .WillOnce(testing::SaveArg<2>(&input_event_callback_));
  }

  // PowerEventObserver implementation
  void PowerButtonEventReceived(bool down,
                                const base::TimeTicks& timestamp) override {
    if (down)
      last_power_button_down_event_ = timestamp;
    else
      last_power_button_up_event_ = timestamp;
  }

 protected:
  void SendInputEventSignal(power_manager::InputEvent_Type type,
                            base::TimeTicks event_time) {
    dbus::Signal input_event_signal(power_manager::kPowerManagerInterface,
                                    power_manager::kInputEventSignal);
    power_manager::InputEvent message;
    message.set_type(type);
    message.set_timestamp(event_time.ToInternalValue());
    ASSERT_TRUE(dbus::MessageWriter(&input_event_signal)
                    .AppendProtoAsArrayOfBytes(message));
    input_event_callback_.Run(&input_event_signal);
  }

  scoped_refptr<dbus::MockBus> mock_bus_;
  scoped_refptr<dbus::MockObjectProxy> power_manager_proxy_;
  dbus::ObjectProxy::SignalCallback input_event_callback_;
  // last TimeTicks at which the power button down event was received.
  base::TimeTicks last_power_button_down_event_;
  // last TimeTicks at which the power button up event was received.
  base::TimeTicks last_power_button_up_event_;
};

// Ensure that PowerEventObservers are notified on power button down event.
TEST_F(PowerManagerClientTest, PowerButtonDownEvent) {
  std::unique_ptr<PowerManagerClientInterface> client =
      PowerManagerClient::Create(mock_bus_);

  client->AddObserver(this);
  base::TimeTicks event_time = base::TimeTicks::Now();
  // |last_power_button_down_event_| should have default value before power
  // button down event.
  ASSERT_EQ(last_power_button_down_event_, base::TimeTicks());
  SendInputEventSignal(
      power_manager::InputEvent_Type::InputEvent_Type_POWER_BUTTON_DOWN,
      event_time);
  // |last_power_button_down_event_| should now have the timestamp
  // communicated as part of event.
  ASSERT_EQ(last_power_button_down_event_, event_time);
}

// Ensure that PowerEventObservers are notified on power button up event.
TEST_F(PowerManagerClientTest, PowerButtonUpEvent) {
  std::unique_ptr<PowerManagerClientInterface> client =
      PowerManagerClient::Create(mock_bus_);

  client->AddObserver(this);
  base::TimeTicks event_time = base::TimeTicks::Now();
  // |last_power_button_up_event_| should have default value before power
  // button up event.
  ASSERT_EQ(last_power_button_up_event_, base::TimeTicks());
  SendInputEventSignal(
      power_manager::InputEvent_Type::InputEvent_Type_POWER_BUTTON_UP,
      event_time);
  // |last_power_button_up_event_| should now have the timestamp
  // communicated as part of event.
  ASSERT_EQ(last_power_button_up_event_, event_time);
}

}  // namespace biod
