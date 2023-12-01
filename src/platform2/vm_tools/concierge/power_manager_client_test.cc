// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/power_manager_client.h"

#include <stdint.h>

#include <memory>

#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/memory/ref_counted.h>
#include <base/task/sequenced_task_runner.h>
#include <base/test/task_environment.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <dbus/object_path.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <power_manager/proto_bindings/suspend.pb.h>

using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;

namespace vm_tools {
namespace concierge {
namespace {

void SetTrue(bool* flag) {
  *flag = true;
}

void Increment(int32_t* counter) {
  *counter += 1;
}

class PowerManagerClientTest : public ::testing::Test {
 public:
  PowerManagerClientTest() = default;

  void SetUp() override {
    dbus::Bus::Options options;
    options.bus_type = dbus::Bus::SYSTEM;
    mock_bus_ = new dbus::MockBus(options);

    power_manager_proxy_ = new dbus::MockObjectProxy(
        mock_bus_.get(), power_manager::kPowerManagerServiceName,
        dbus::ObjectPath(power_manager::kPowerManagerServicePath));

    // Sets an expectation that the mock proxy's CallMethodAndBlock() will use
    // CreateMockProxyResponse() to return responses.
    EXPECT_CALL(*power_manager_proxy_.get(), CallMethodAndBlock(_, _))
        .WillRepeatedly(
            Invoke(this, &PowerManagerClientTest::CreateMockProxyResponse));

    // Set an expectation so that the MockBus will return our mock power manager
    // proxy.
    EXPECT_CALL(*mock_bus_.get(),
                GetObjectProxy(
                    power_manager::kPowerManagerServiceName,
                    dbus::ObjectPath(power_manager::kPowerManagerServicePath)))
        .WillOnce(Return(power_manager_proxy_.get()));

    EXPECT_CALL(*mock_bus_, GetDBusTaskRunner())
        .WillRepeatedly(
            Return(base::SequencedTaskRunner::GetCurrentDefault().get()));
  }

 protected:
  std::unique_ptr<dbus::Response> CreateMockProxyResponse(
      dbus::MethodCall* method_call, int timeout_ms) {
    if (method_call->GetInterface() != power_manager::kPowerManagerInterface) {
      LOG(ERROR) << "Unexpected method call: " << method_call->ToString();
      return std::unique_ptr<dbus::Response>();
    }

    std::unique_ptr<dbus::Response> response = dbus::Response::CreateEmpty();
    if (method_call->GetMember() ==
        power_manager::kRegisterSuspendDelayMethod) {
      power_manager::RegisterSuspendDelayReply reply;
      reply.set_delay_id(delay_id_);

      if (!dbus::MessageWriter(response.get())
               .AppendProtoAsArrayOfBytes(reply)) {
        LOG(ERROR) << "Failed to encode RegisterSuspendDelayReply";
      }
    } else if (method_call->GetMember() ==
               power_manager::kHandleSuspendReadinessMethod) {
      power_manager::SuspendReadinessInfo info;
      if (!dbus::MessageReader(method_call).PopArrayOfBytesAsProto(&info)) {
        LOG(ERROR) << "Failed to decode SuspendReadinessInfo";
        return std::unique_ptr<dbus::Response>();
      }

      reported_delay_id_ = info.delay_id();
      reported_suspend_id_ = info.suspend_id();
    } else if (method_call->GetMember() ==
               power_manager::kUnregisterSuspendDelayMethod) {
      unregistered_ = true;
    }

    return response;
  }

  base::test::TaskEnvironment task_environment_;

  scoped_refptr<dbus::MockBus> mock_bus_;
  scoped_refptr<dbus::MockObjectProxy> power_manager_proxy_;

  // Tests may change these values but the defaults should also be valid.
  int32_t delay_id_{7};
  int32_t current_suspend_id_{11};

  // Set in CreateMockProxyResponse().
  int32_t reported_delay_id_{-1};
  int32_t reported_suspend_id_{-1};
  bool unregistered_{false};
};

}  // namespace

// Tests that PowerManagerClient notifies powerd that it is ready to suspend
// once the registered callback returns.
TEST_F(PowerManagerClientTest, SuspendReadiness) {
  std::unique_ptr<PowerManagerClient> client =
      std::make_unique<PowerManagerClient>(mock_bus_);

  delay_id_ = 19;
  current_suspend_id_ = 13;

  client->RegisterSuspendDelay(base::DoNothing(), base::DoNothing());

  dbus::Signal suspend_imminent(power_manager::kPowerManagerInterface,
                                power_manager::kSuspendImminentSignal);

  power_manager::SuspendImminent message;
  message.set_suspend_id(current_suspend_id_);
  ASSERT_TRUE(dbus::MessageWriter(&suspend_imminent)
                  .AppendProtoAsArrayOfBytes(message));

  client->HandleSuspendImminent(&suspend_imminent);

  EXPECT_EQ(delay_id_, reported_delay_id_);
  EXPECT_EQ(current_suspend_id_, reported_suspend_id_);
}

// Tests that the PowerManagerClient unregisters its suspend delay when it is
// destroyed.
TEST_F(PowerManagerClientTest, Unregister) {
  std::unique_ptr<PowerManagerClient> client =
      std::make_unique<PowerManagerClient>(mock_bus_);

  client->RegisterSuspendDelay(base::DoNothing(), base::DoNothing());
  client.reset();

  EXPECT_TRUE(unregistered_);
}

// Tests that the PowerManagerClient runs the provided callbacks when it
// receives a SuspendImminent signal.
TEST_F(PowerManagerClientTest, SuspendImminent) {
  std::unique_ptr<PowerManagerClient> client =
      std::make_unique<PowerManagerClient>(mock_bus_);

  current_suspend_id_ = 1297;

  bool called = false;
  client->RegisterSuspendDelay(base::BindRepeating(&SetTrue, &called),
                               base::DoNothing());

  dbus::Signal suspend_imminent(power_manager::kPowerManagerInterface,
                                power_manager::kSuspendImminentSignal);

  power_manager::SuspendImminent message;
  message.set_suspend_id(current_suspend_id_);
  ASSERT_TRUE(dbus::MessageWriter(&suspend_imminent)
                  .AppendProtoAsArrayOfBytes(message));

  client->HandleSuspendImminent(&suspend_imminent);

  EXPECT_TRUE(called);
}

// Tests that the PowerManagerClient runs the provided callbacks when it
// receives a SuspendDone signal.
TEST_F(PowerManagerClientTest, SuspendDone) {
  std::unique_ptr<PowerManagerClient> client =
      std::make_unique<PowerManagerClient>(mock_bus_);

  current_suspend_id_ = 509;

  bool called = false;
  client->RegisterSuspendDelay(base::DoNothing(),
                               base::BindRepeating(&SetTrue, &called));

  dbus::Signal suspend_imminent(power_manager::kPowerManagerInterface,
                                power_manager::kSuspendImminentSignal);

  power_manager::SuspendImminent imminent;
  imminent.set_suspend_id(current_suspend_id_);
  ASSERT_TRUE(dbus::MessageWriter(&suspend_imminent)
                  .AppendProtoAsArrayOfBytes(imminent));

  client->HandleSuspendImminent(&suspend_imminent);

  EXPECT_FALSE(called);

  dbus::Signal suspend_done(power_manager::kPowerManagerInterface,
                            power_manager::kSuspendDoneSignal);

  power_manager::SuspendDone done;
  done.set_suspend_id(current_suspend_id_);
  ASSERT_TRUE(
      dbus::MessageWriter(&suspend_done).AppendProtoAsArrayOfBytes(done));

  client->HandleSuspendDone(&suspend_done);

  EXPECT_TRUE(called);
}

// Tests that the PowerManagerClient ignores SuspendDone signals whose ids
// don't match the current suspend id.
TEST_F(PowerManagerClientTest, WrongSuspendId) {
  std::unique_ptr<PowerManagerClient> client =
      std::make_unique<PowerManagerClient>(mock_bus_);

  current_suspend_id_ = 92;

  bool called = false;
  client->RegisterSuspendDelay(base::DoNothing(),
                               base::BindRepeating(&SetTrue, &called));

  dbus::Signal suspend_imminent(power_manager::kPowerManagerInterface,
                                power_manager::kSuspendImminentSignal);

  power_manager::SuspendImminent imminent;
  imminent.set_suspend_id(current_suspend_id_);
  ASSERT_TRUE(dbus::MessageWriter(&suspend_imminent)
                  .AppendProtoAsArrayOfBytes(imminent));

  client->HandleSuspendImminent(&suspend_imminent);

  EXPECT_FALSE(called);

  dbus::Signal suspend_done(power_manager::kPowerManagerInterface,
                            power_manager::kSuspendDoneSignal);

  power_manager::SuspendDone done;
  done.set_suspend_id(current_suspend_id_ - 1);
  ASSERT_TRUE(
      dbus::MessageWriter(&suspend_done).AppendProtoAsArrayOfBytes(done));

  client->HandleSuspendDone(&suspend_done);

  EXPECT_FALSE(called);
}

// Tests that the PowerManagerClient runs the provided callbacks even if it
// receives multiple SuspendImminent signals before receiving a SuspendDone.
TEST_F(PowerManagerClientTest, MultipleSuspendImminents) {
  std::unique_ptr<PowerManagerClient> client =
      std::make_unique<PowerManagerClient>(mock_bus_);

  current_suspend_id_ = 7261;

  int32_t counter = 0;
  client->RegisterSuspendDelay(base::BindRepeating(&Increment, &counter),
                               base::DoNothing());

  for (int i = 0; i < 3; ++i) {
    ++current_suspend_id_;

    dbus::Signal suspend_imminent(power_manager::kPowerManagerInterface,
                                  power_manager::kSuspendImminentSignal);

    power_manager::SuspendImminent imminent;
    imminent.set_suspend_id(current_suspend_id_);
    ASSERT_TRUE(dbus::MessageWriter(&suspend_imminent)
                    .AppendProtoAsArrayOfBytes(imminent));

    client->HandleSuspendImminent(&suspend_imminent);

    EXPECT_EQ(i + 1, counter);
  }
}

// Tests that PowerManagerClient re-registers its suspend delay and uses the
// new delay id if powerd restarts.
TEST_F(PowerManagerClientTest, NameOwnerChanged) {
  std::unique_ptr<PowerManagerClient> client =
      std::make_unique<PowerManagerClient>(mock_bus_);

  // Register the suspend delay and do one suspend.
  delay_id_ = 189;
  client->RegisterSuspendDelay(base::DoNothing(), base::DoNothing());

  dbus::Signal suspend_imminent(power_manager::kPowerManagerInterface,
                                power_manager::kSuspendImminentSignal);

  power_manager::SuspendImminent message;
  message.set_suspend_id(current_suspend_id_);
  ASSERT_TRUE(dbus::MessageWriter(&suspend_imminent)
                  .AppendProtoAsArrayOfBytes(message));

  client->HandleSuspendImminent(&suspend_imminent);

  EXPECT_EQ(delay_id_, reported_delay_id_);

  // Now pretend like powerd restarted and do another suspend.
  delay_id_ = 2678;
  client->HandleNameOwnerChanged("", "new_powerd");

  dbus::Signal suspend_imminent2(power_manager::kPowerManagerInterface,
                                 power_manager::kSuspendImminentSignal);

  power_manager::SuspendImminent message2;
  message2.set_suspend_id(current_suspend_id_);
  ASSERT_TRUE(dbus::MessageWriter(&suspend_imminent2)
                  .AppendProtoAsArrayOfBytes(message2));

  client->HandleSuspendImminent(&suspend_imminent2);

  EXPECT_EQ(delay_id_, reported_delay_id_);
}

}  // namespace concierge
}  // namespace vm_tools
