// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/power_manager.h"

#include <string>
#include <utility>

#include <base/check.h>
#include <base/threading/thread.h>
#include <dbus/mock_object_proxy.h>
#include <gmock/gmock.h>
#include <google/protobuf/message_lite.h>
#include <gtest/gtest.h>
#include <power_manager/dbus-proxy-mocks.h>
#include <power_manager/proto_bindings/suspend.pb.h>

#include "trunks/dbus_interface.h"
#include "trunks/mock_command_transceiver.h"
#include "trunks/mock_resource_manager.h"
#include "trunks/trunks_factory_for_test.h"

using testing::_;
using testing::DoAll;
using testing::Invoke;
using testing::Return;
using testing::StrictMock;

using MessageRepeatingCallback =
    base::RepeatingCallback<void(const std::vector<uint8_t>&)>;
using MessageOnceCallback =
    base::OnceCallback<void(const std::vector<uint8_t>&)>;
using ConnectedCallback = dbus::ObjectProxy::OnConnectedCallback;
using ErrorCallback = base::OnceCallback<void(brillo::Error*)>;
using SuccessCallback = base::OnceCallback<void()>;
using NameOwnerChangedCallback =
    base::RepeatingCallback<void(const std::string&, const std::string&)>;
using ServiceAvailableCallback =
    dbus::ObjectProxy::WaitForServiceToBeAvailableCallback;

namespace {

const char kPowerManagerInterface[] = "org.chromium.PowerManager";
const char kSuspendImminentSignal[] = "SuspendImminent";
const char kDarkSuspendImminentSignal[] = "DarkSuspendImminent";
const char kSuspendDoneSignal[] = "SuspendDone";

const int32_t kSomeDelayId = 1001;
const int32_t kSomeSuspendId = 17;

void SerializeProto(const google::protobuf::MessageLite& proto,
                    std::vector<uint8_t>* raw_buf) {
  std::string serialized_proto;
  CHECK(proto.SerializeToString(&serialized_proto));
  raw_buf->assign(serialized_proto.begin(), serialized_proto.end());
}

bool DeserializeProto(const std::vector<uint8_t>& raw_buf,
                      google::protobuf::MessageLite* proto) {
  return proto->ParseFromArray(&raw_buf.front(), raw_buf.size());
}

void SendMessage(MessageOnceCallback callback,
                 const google::protobuf::MessageLite& proto) {
  std::vector<uint8_t> serialized_proto;
  SerializeProto(proto, &serialized_proto);
  std::move(callback).Run(serialized_proto);
}

}  // namespace

namespace trunks {

class PowerManagerTest : public testing::Test {
 public:
  struct Signal {
    std::string name;
    MessageRepeatingCallback on_signal;
    ConnectedCallback on_connected;
  };

  PowerManagerTest() {
    power_manager_.set_resource_manager(&resource_manager_);
    power_manager_.set_power_manager_proxy(&proxy_);
    background_thread_.Start();
    power_manager_.set_task_runner(background_thread_.task_runner());
  }

  void SetUp() override {
    ON_CALL(proxy_, DoRegisterSuspendDoneSignalHandler(_, _))
        .WillByDefault(Invoke([this](const MessageRepeatingCallback& signal,
                                     ConnectedCallback* connected) {
          suspend_done_.name = kSuspendDoneSignal;
          suspend_done_.on_signal = signal;
          suspend_done_.on_connected = std::move(*connected);
        }));
    ON_CALL(proxy_, DoRegisterSuspendImminentSignalHandler(_, _))
        .WillByDefault(Invoke([this](const MessageRepeatingCallback& signal,
                                     ConnectedCallback* connected) {
          suspend_imminent_.name = kSuspendImminentSignal;
          suspend_imminent_.on_signal = signal;
          suspend_imminent_.on_connected = std::move(*connected);
        }));
    ON_CALL(proxy_, DoRegisterDarkSuspendImminentSignalHandler(_, _))
        .WillByDefault(Invoke([this](const MessageRepeatingCallback& signal,
                                     ConnectedCallback* connected) {
          dark_suspend_imminent_.name = kDarkSuspendImminentSignal;
          dark_suspend_imminent_.on_signal = signal;
          dark_suspend_imminent_.on_connected = std::move(*connected);
        }));
    ON_CALL(*object_proxy_, DoWaitForServiceToBeAvailable(_))
        .WillByDefault(Invoke([this](ServiceAvailableCallback* cb) {
          service_available_ = std::move(*cb);
        }));
    ON_CALL(*object_proxy_, SetNameOwnerChangedCallback(_))
        .WillByDefault(Invoke([this](const NameOwnerChangedCallback& cb) {
          name_owner_changed_ = cb;
        }));
    ON_CALL(proxy_, UnregisterSuspendDelay(_, _, _))
        .WillByDefault(Return(true));
    ON_CALL(proxy_, GetObjectProxy())
        .WillByDefault(Return(object_proxy_.get()));
  }

  void SendSuspendDone(int32_t suspend_id = kSomeSuspendId) {
    power_manager::SuspendDone message;
    message.set_suspend_id(suspend_id);
    SendMessage(suspend_done_.on_signal, message);
  }
  void SendSuspendImminent(int32_t suspend_id = kSomeSuspendId,
                           bool dark = false) {
    power_manager::SuspendImminent message;
    message.set_suspend_id(suspend_id);
    Signal* signal = dark ? &dark_suspend_imminent_ : &suspend_imminent_;
    SendMessage(signal->on_signal, message);
  }
  void ConnectSignal(Signal* signal, bool success = true) {
    std::move(signal->on_connected)
        .Run(kPowerManagerInterface, signal->name, success);
  }
  void ConnectAllSignals() {
    ConnectSignal(&suspend_done_);
    ConnectSignal(&suspend_imminent_);
    ConnectSignal(&dark_suspend_imminent_);
  }
  void ServiceAvailable(bool available = true) {
    EXPECT_CALL(*object_proxy_, SetNameOwnerChangedCallback(_))
        .Times(available ? 1 : 0);
    std::move(service_available_).Run(available);
  }
  void ServiceLost() { name_owner_changed_.Run("some_owner", std::string()); }
  void ServiceRestored() {
    name_owner_changed_.Run(std::string(), "some_owner");
  }

  brillo::ErrorPtr TestError() {
    return brillo::Error::Create(FROM_HERE, "test_domain", "test_code",
                                 "test_message");
  }

  void SetSuspendDelay(int32_t delay_id = kSomeDelayId) {
    EXPECT_CALL(proxy_, RegisterSuspendDelayAsync(_, _, _, _))
        .WillOnce(Invoke([delay_id](const std::vector<uint8_t>& /* request */,
                                    MessageOnceCallback on_reply,
                                    ErrorCallback /* on_error */,
                                    int /* timeout_ms */) {
          power_manager::RegisterSuspendDelayReply reply;
          reply.set_delay_id(delay_id);
          SendMessage(std::move(on_reply), reply);
        }));
  }
  void DenySuspendDelay() {
    EXPECT_CALL(proxy_, RegisterSuspendDelayAsync(_, _, _, _))
        .WillOnce(Invoke([this](const std::vector<uint8_t>& /* request */,
                                MessageOnceCallback /* on_reply */,
                                ErrorCallback on_error, int /* timeout_ms */) {
          brillo::ErrorPtr error = TestError();
          std::move(on_error).Run(error.get());
        }));
  }

  void ExpectSuspendReadiness(bool reply_success = true) {
    last_readiness_info_.Clear();
    EXPECT_CALL(proxy_, HandleSuspendReadinessAsync(_, _, _, _))
        .WillOnce(Invoke([this, reply_success](
                             const std::vector<uint8_t>& serialized_proto,
                             SuccessCallback on_success, ErrorCallback on_error,
                             int /* timeout_ms */) {
          DeserializeProto(serialized_proto, &last_readiness_info_);
          if (reply_success) {
            std::move(on_success).Run();
          } else {
            brillo::ErrorPtr error = TestError();
            std::move(on_error).Run(error.get());
          }
        }))
        .RetiresOnSaturation();
  }
  void CheckSuspendReadiness(int32_t suspend_id = kSomeSuspendId,
                             int32_t delay_id = kSomeDelayId) {
    EXPECT_EQ(suspend_id, last_readiness_info_.suspend_id());
    EXPECT_EQ(delay_id, last_readiness_info_.delay_id());
  }

  void ExpectUnregisterSuspendDelay(bool reply_success = true) {
    last_unregister_suspend_delay_.Clear();
    EXPECT_CALL(proxy_, UnregisterSuspendDelay(_, _, _))
        .WillOnce(Invoke([this, reply_success](
                             const std::vector<uint8_t>& serialized_proto,
                             brillo::ErrorPtr* error,
                             int /* timeout_ms */) -> bool {
          DeserializeProto(serialized_proto, &last_unregister_suspend_delay_);
          if (!reply_success) {
            *error = TestError();
          }
          return reply_success;
        }))
        .RetiresOnSaturation();
  }
  void CheckUnregisterSuspendDelay(int32_t delay_id = kSomeDelayId) {
    EXPECT_EQ(delay_id, last_unregister_suspend_delay_.delay_id());
  }

  void Init() {
    EXPECT_CALL(proxy_, DoRegisterSuspendDoneSignalHandler(_, _)).Times(1);
    EXPECT_CALL(proxy_, DoRegisterSuspendImminentSignalHandler(_, _)).Times(1);
    EXPECT_CALL(proxy_, DoRegisterDarkSuspendImminentSignalHandler(_, _))
        .Times(1);
    EXPECT_CALL(*object_proxy_, DoWaitForServiceToBeAvailable(_)).Times(1);
    power_manager_.Init(ignored_bus_);
  }

  void NormalStart() {
    Init();
    ConnectAllSignals();
    SetSuspendDelay();
    ServiceAvailable();
  }

  void SuspendResume(bool do_suspend = true,
                     bool do_resume = true,
                     int32_t suspend_id = kSomeSuspendId,
                     int32_t delay_id = kSomeDelayId) {
    EXPECT_CALL(resource_manager_, Suspend()).Times(do_suspend);
    if (do_suspend) {
      ExpectSuspendReadiness();
      SendSuspendImminent(suspend_id);
      CheckSuspendReadiness(suspend_id, delay_id);
    }

    EXPECT_CALL(resource_manager_, Resume()).Times(do_resume);
    if (do_resume) {
      SendSuspendDone();
    }
    testing::Mock::VerifyAndClearExpectations(&proxy_);
    testing::Mock::VerifyAndClearExpectations(&resource_manager_);
  }

 protected:
  using MockDBusObjectProxyType = StrictMock<dbus::MockObjectProxy>;
  scoped_refptr<MockDBusObjectProxyType> object_proxy_ =
      new MockDBusObjectProxyType(
          nullptr, "", dbus::ObjectPath(trunks::kTrunksServicePath));
  org::chromium::PowerManagerProxyMock proxy_;
  TrunksFactoryForTest factory_;
  StrictMock<MockCommandTransceiver> transceiver_;
  StrictMock<MockResourceManager> resource_manager_{factory_, &transceiver_};
  PowerManager power_manager_;
  base::Thread background_thread_{"test_background_thread"};

  Signal suspend_done_;
  Signal suspend_imminent_;
  Signal dark_suspend_imminent_;
  NameOwnerChangedCallback name_owner_changed_;
  ServiceAvailableCallback service_available_;

  power_manager::SuspendReadinessInfo last_readiness_info_;
  power_manager::UnregisterSuspendDelayRequest last_unregister_suspend_delay_;

 private:
  scoped_refptr<dbus::Bus> ignored_bus_ = new dbus::Bus(dbus::Bus::Options());
};

TEST_F(PowerManagerTest, StartSuccess) {
  NormalStart();
}

TEST_F(PowerManagerTest, ServiceAvailableFailure) {
  // If ServiceAvailable(false) is received, don't proceed registering
  // SuspendDelay.
  Init();
  ConnectAllSignals();
  EXPECT_CALL(proxy_, RegisterSuspendDelayAsync(_, _, _, _)).Times(0);
  ServiceAvailable(false);
}

TEST_F(PowerManagerTest, SuspendWithoutResumeSignalConnected) {
  // Don't suspend resource manager if there is no signal to initiate resume.
  // SuspendReadinessInfo should still be reported.
  Init();
  SetSuspendDelay();
  ConnectSignal(&suspend_done_, false);
  ConnectSignal(&suspend_imminent_);
  ConnectSignal(&dark_suspend_imminent_);
  ServiceAvailable();
  ExpectSuspendReadiness();
  EXPECT_CALL(resource_manager_, Suspend()).Times(0);
  SendSuspendImminent();
  CheckSuspendReadiness();
}

TEST_F(PowerManagerTest, SuspendWithoutSuspendDelay) {
  // IF all signals are connected but SuspendDelay is not registered, still
  // suspend resource manager on SuspendImminent, just don't send
  // SuspendReadinessInfo.
  Init();
  DenySuspendDelay();
  ConnectAllSignals();
  ServiceAvailable();
  EXPECT_CALL(proxy_, HandleSuspendReadinessAsync(_, _, _, _)).Times(0);
  EXPECT_CALL(resource_manager_, Suspend()).Times(1);
  SendSuspendImminent();
}

TEST_F(PowerManagerTest, SuspendResume) {
  // Test that it works multiple times.
  // SuspendReadinessInfo should contain the right suspend_ids.
  NormalStart();
  SuspendResume(true, true, kSomeSuspendId);
  SuspendResume(true, true, kSomeSuspendId + 5);
  SuspendResume(true, true, kSomeSuspendId - 5);
}

TEST_F(PowerManagerTest, SuspendWithoutResume) {
  // If SuspendImminent is received twice, without resume in between, the
  // resource manager should still be suspended twice. The suspended state
  // is not tracked outside of resource manager.
  // SuspendReadinessInfo should contain the right suspend_ids.
  NormalStart();
  SuspendResume(true, false, kSomeSuspendId);
  SuspendResume(true, false, kSomeSuspendId + 3);
}

TEST_F(PowerManagerTest, ResumeWithoutSuspend) {
  // Resource manager should be resumed even if there was no previous suspend.
  // In case of SuspendDone signals without intermittent SuspendImminent,
  // resource manager should be resumed every time.
  NormalStart();
  SuspendResume(false, true);
  SuspendResume(false, true);
}

TEST_F(PowerManagerTest, SuspendReadinessIgnoresResult) {
  // The results of sending SuspendReadinessInfo shouldn't affect the behavior.
  // Errors are ignored.
  NormalStart();
  EXPECT_CALL(resource_manager_, Suspend()).Times(3);
  EXPECT_CALL(resource_manager_, Resume()).Times(3);
  ExpectSuspendReadiness(false);
  SendSuspendImminent(kSomeSuspendId);
  CheckSuspendReadiness(kSomeSuspendId);

  SendSuspendDone();

  ExpectSuspendReadiness(false);
  SendSuspendImminent(kSomeSuspendId + 1);
  CheckSuspendReadiness(kSomeSuspendId + 1);

  ExpectSuspendReadiness(false);
  SendSuspendImminent(kSomeSuspendId);
  CheckSuspendReadiness(kSomeSuspendId);

  SendSuspendDone();

  SendSuspendDone();
}

TEST_F(PowerManagerTest, TearDown) {
  // If SuspendDelay is registered, TearDown should unregister it.
  // It stops sending ReadinessInfo after TearDown, even if a signal is
  // received.
  NormalStart();
  ExpectUnregisterSuspendDelay();
  power_manager_.TearDown();
  CheckUnregisterSuspendDelay();
  EXPECT_CALL(proxy_, HandleSuspendReadinessAsync(_, _, _, _)).Times(0);
  EXPECT_CALL(resource_manager_, Suspend()).Times(1);
  SendSuspendImminent();
}

TEST_F(PowerManagerTest, TearDownAfterSuspendResume) {
  NormalStart();
  SuspendResume();
  SuspendResume();
  ExpectUnregisterSuspendDelay();
  power_manager_.TearDown();
  CheckUnregisterSuspendDelay();
}

TEST_F(PowerManagerTest, TearDownInSuspend) {
  NormalStart();
  SuspendResume(true, false);
  ExpectUnregisterSuspendDelay();
  power_manager_.TearDown();
  CheckUnregisterSuspendDelay();
}

TEST_F(PowerManagerTest, UnregisterSuspendDelayFailure) {
  // If UnregisterSuspendDelay failed during tear down, continue
  // using it, if a signal is received after that.
  NormalStart();
  ExpectUnregisterSuspendDelay(false);
  power_manager_.TearDown();
  CheckUnregisterSuspendDelay();
  SuspendResume();
}

TEST_F(PowerManagerTest, ServiceLost) {
  // If service is lost, resource manager should be resumed just in case.
  // SuspendDelay should not be attempted to be unregistered - service is
  // gone.
  NormalStart();
  EXPECT_CALL(proxy_, UnregisterSuspendDelay(_, _, _)).Times(0);
  EXPECT_CALL(resource_manager_, Resume()).Times(1);
  ServiceLost();
}

TEST_F(PowerManagerTest, ServiceRestored) {
  NormalStart();
  EXPECT_CALL(proxy_, UnregisterSuspendDelay(_, _, _)).Times(0);
  EXPECT_CALL(resource_manager_, Resume()).Times(1);
  ServiceLost();
  testing::Mock::VerifyAndClearExpectations(&resource_manager_);

  // While no service, don't send ReadinessInfo, but otherwise process
  // SuspendImminent and SuspendDone.
  EXPECT_CALL(proxy_, HandleSuspendReadinessAsync(_, _, _, _)).Times(0);
  EXPECT_CALL(resource_manager_, Suspend()).Times(1);
  SendSuspendImminent();
  EXPECT_CALL(resource_manager_, Resume()).Times(1);
  SendSuspendDone();
  testing::Mock::VerifyAndClearExpectations(&resource_manager_);

  // When service is restored, register SuspendDelay, and start using the
  // new delay_id.
  int32_t new_delay_id = kSomeDelayId + 1;
  SetSuspendDelay(new_delay_id);
  ServiceRestored();

  SuspendResume(true, true, kSomeSuspendId, new_delay_id);

  ExpectUnregisterSuspendDelay();
  power_manager_.TearDown();
  CheckUnregisterSuspendDelay(new_delay_id);
}

TEST_F(PowerManagerTest, UnexpectedServiceRestored) {
  // If "service restored" event received without prior "service lost",
  // assume we missed that prior event, and handle as if we received
  // both events. Don't attempt to unregister previous SuspendDelay.
  NormalStart();

  int32_t new_delay_id = kSomeDelayId + 1;
  SetSuspendDelay(new_delay_id);
  EXPECT_CALL(proxy_, UnregisterSuspendDelay(_, _, _)).Times(0);
  EXPECT_CALL(resource_manager_, Resume()).Times(1);
  ServiceRestored();

  SuspendResume(true, true, kSomeSuspendId, new_delay_id);
}

}  // namespace trunks
