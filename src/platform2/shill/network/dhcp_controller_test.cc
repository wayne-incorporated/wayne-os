// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/network/dhcp_controller.h"

#include <map>
#include <memory>
#include <string>
#include <sys/time.h>
#include <utility>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <chromeos/dbus/service_constants.h>

#include "shill/event_dispatcher.h"
#include "shill/logging.h"
#include "shill/mock_log.h"
#include "shill/mock_metrics.h"
#include "shill/net/mock_process_manager.h"
#include "shill/net/mock_time.h"
#include "shill/network/dhcpv4_config.h"
#include "shill/network/mock_dhcp_provider.h"
#include "shill/network/mock_dhcp_proxy.h"
#include "shill/store/property_store_test.h"
#include "shill/technology.h"
#include "shill/test_event_dispatcher.h"
#include "shill/testing.h"

using testing::_;
using testing::AnyNumber;
using testing::ByMove;
using testing::ContainsRegex;
using testing::DoAll;
using testing::EndsWith;
using testing::InvokeWithoutArgs;
using testing::Mock;
using testing::Return;
using testing::SaveArg;
using testing::SetArgPointee;
using testing::WithArg;

namespace shill {

namespace {
constexpr bool kArpGateway = true;
constexpr char kDeviceName[] = "eth0";
constexpr bool kEnableRFC8925 = false;
constexpr char kHostName[] = "hostname";
constexpr char kLeaseFileSuffix[] = "leasefilesuffix";
constexpr bool kHasHostname = true;
constexpr bool kHasLeaseSuffix = true;
constexpr uint32_t kTimeNow = 10;
constexpr uint32_t kLeaseDuration = 5;

MATCHER_P(IsWeakPtrTo, address, "") {
  return arg.get() == address;
}
}  // namespace

class DHCPControllerTest : public PropertyStoreTest {
 public:
  DHCPControllerTest()
      : proxy_(new MockDHCPProxy()),
        controller_(new DHCPController(control_interface(),
                                       dispatcher(),
                                       &provider_,
                                       kDeviceName,
                                       kLeaseFileSuffix,
                                       kArpGateway,
                                       kEnableRFC8925,
                                       kHostName,
                                       Technology::kUnknown,
                                       &metrics_)) {
    controller_->time_ = &time_;
  }

  void SetUp() override { controller_->process_manager_ = &process_manager_; }

  void SetDHCPVerboseLog() {
    ScopeLogger::GetInstance()->EnableScopesByName("dhcp");
    ScopeLogger::GetInstance()->set_verbose_level(3);
  }

  void ResetDHCPVerboseLog() {
    ScopeLogger::GetInstance()->EnableScopesByName("-dhcp");
    ScopeLogger::GetInstance()->set_verbose_level(0);
  }

  // Sets the current time returned by time_.GetTimeBoottime() to |second|.
  void SetCurrentTimeToSecond(uint32_t second) {
    struct timeval current = {static_cast<__time_t>(second), 0};
    EXPECT_CALL(time_, GetTimeBoottime(_))
        .WillOnce(DoAll(SetArgPointee<0>(current), Return(0)));
  }

  bool StartInstance() { return controller_->Start(); }

  void StopInstance() { controller_->Stop("In test"); }

  void InvokeOnIPConfigUpdated(const IPConfig::Properties& properties,
                               bool new_lease_acquired) {
    controller_->OnIPConfigUpdated(properties, new_lease_acquired);
  }

  bool ShouldFailOnAcquisitionTimeout() {
    return controller_->ShouldFailOnAcquisitionTimeout();
  }

  void SetShouldFailOnAcquisitionTimeout(bool value) {
    controller_->is_gateway_arp_active_ = !value;
  }

  bool ShouldKeepLeaseOnDisconnect() {
    return controller_->ShouldKeepLeaseOnDisconnect();
  }

  void SetShouldKeepLeaseOnDisconnect(bool value) {
    controller_->arp_gateway_ = value;
  }

  void CreateMockMinijailConfig(const std::string& hostname,
                                const std::string& lease_suffix,
                                bool arp_gateway);

 protected:
  static constexpr int kPID = 123456;

  std::unique_ptr<MockDHCPProxy> proxy_;
  MockProcessManager process_manager_;
  MockTime time_;
  std::unique_ptr<DHCPController> controller_;
  MockDHCPProvider provider_;
  MockMetrics metrics_;
};

// Resets |controller_| to an instance initiated with the given parameters,
// which can be used in the tests for verifying parameters to invoke minijail.
void DHCPControllerTest::CreateMockMinijailConfig(
    const std::string& hostname,
    const std::string& lease_suffix,
    bool arp_gateway) {
  controller_.reset(new DHCPController(
      control_interface(), dispatcher(), &provider_, kDeviceName, lease_suffix,
      arp_gateway, /*enable_rfc_8925=*/false, hostname, Technology::kUnknown,
      metrics()));
  controller_->process_manager_ = &process_manager_;
}

TEST_F(DHCPControllerTest, InitProxy) {
  static const char kService[] = ":1.200";
  EXPECT_NE(nullptr, proxy_);
  EXPECT_EQ(nullptr, controller_->proxy_);
  EXPECT_CALL(*control_interface(), CreateDHCPProxy(kService))
      .WillOnce(Return(ByMove(std::move(proxy_))));
  controller_->InitProxy(kService);
  EXPECT_EQ(nullptr, proxy_);
  EXPECT_NE(nullptr, controller_->proxy_);

  controller_->InitProxy(kService);
}

TEST_F(DHCPControllerTest, StartFail) {
  EXPECT_CALL(process_manager_, StartProcessInMinijail(_, _, _, _, _, _))
      .WillOnce(Return(-1));
  EXPECT_FALSE(controller_->Start());
  EXPECT_EQ(0, controller_->pid_);
}

MATCHER_P3(IsDHCPCDArgs, has_hostname, has_arp_gateway, has_lease_suffix, "") {
  if (arg[0] != "-B" || arg[1] != "-i" || arg[2] != "chromeos" ||
      arg[3] != "-q" || arg[4] != "-4") {
    return false;
  }

  int end_offset = 5;
  if (has_hostname) {
    if (arg[end_offset] != "-h" || arg[end_offset + 1] != kHostName) {
      return false;
    }
    end_offset += 2;
  }

  if (has_arp_gateway) {
    if (arg[end_offset] != "-R" || arg[end_offset + 1] != "--unicast") {
      return false;
    }
    end_offset += 2;
  }

  std::string device_arg = has_lease_suffix ? std::string(kDeviceName) + "=" +
                                                  std::string(kLeaseFileSuffix)
                                            : kDeviceName;
  return arg[end_offset] == device_arg;
}

TEST_F(DHCPControllerTest, StartWithoutLeaseSuffix) {
  CreateMockMinijailConfig(kHostName, kDeviceName, kArpGateway);
  EXPECT_CALL(
      process_manager_,
      StartProcessInMinijail(
          _, _, IsDHCPCDArgs(kHasHostname, kArpGateway, !kHasLeaseSuffix), _, _,
          _))
      .WillOnce(Return(-1));
  EXPECT_FALSE(StartInstance());
}

TEST_F(DHCPControllerTest, StartWithHostname) {
  CreateMockMinijailConfig(kHostName, kLeaseFileSuffix, kArpGateway);
  EXPECT_CALL(
      process_manager_,
      StartProcessInMinijail(
          _, _, IsDHCPCDArgs(kHasHostname, kArpGateway, kHasLeaseSuffix), _, _,
          _))
      .WillOnce(Return(-1));
  EXPECT_FALSE(StartInstance());
}

TEST_F(DHCPControllerTest, StartWithEmptyHostname) {
  CreateMockMinijailConfig("", kLeaseFileSuffix, kArpGateway);
  EXPECT_CALL(
      process_manager_,
      StartProcessInMinijail(
          _, _, IsDHCPCDArgs(!kHasHostname, kArpGateway, kHasLeaseSuffix), _, _,
          _))
      .WillOnce(Return(-1));
  EXPECT_FALSE(StartInstance());
}

TEST_F(DHCPControllerTest, StartWithoutArpGateway) {
  CreateMockMinijailConfig(kHostName, kLeaseFileSuffix, !kArpGateway);
  EXPECT_CALL(
      process_manager_,
      StartProcessInMinijail(
          _, _, IsDHCPCDArgs(kHasHostname, !kArpGateway, kHasLeaseSuffix), _, _,
          _))
      .WillOnce(Return(-1));
  EXPECT_FALSE(StartInstance());
}

TEST_F(DHCPControllerTest, TimeToLeaseExpiry_Success) {
  IPConfig::Properties properties;
  properties.lease_duration_seconds = kLeaseDuration;
  SetCurrentTimeToSecond(kTimeNow);
  InvokeOnIPConfigUpdated(properties, true);

  for (uint32_t i = 0; i < kLeaseDuration; i++) {
    SetCurrentTimeToSecond(kTimeNow + i);
    EXPECT_EQ(base::Seconds(kLeaseDuration - i),
              controller_->TimeToLeaseExpiry());
  }
}

TEST_F(DHCPControllerTest, TimeToLeaseExpiry_NoDHCPLease) {
  SetDHCPVerboseLog();
  ScopedMockLog log;
  // |current_lease_expiration_time_| has not been set, so expect an error.
  EXPECT_CALL(log, Log(_, _, EndsWith("No current DHCP lease")));
  EXPECT_FALSE(controller_->TimeToLeaseExpiry().has_value());
  ResetDHCPVerboseLog();
}

TEST_F(DHCPControllerTest, TimeToLeaseExpiry_CurrentLeaseExpired) {
  SetDHCPVerboseLog();
  IPConfig::Properties properties;
  properties.lease_duration_seconds = kLeaseDuration;
  SetCurrentTimeToSecond(kTimeNow);
  InvokeOnIPConfigUpdated(properties, true);

  // Lease should expire at kTimeNow + kLeaseDuration.
  ScopedMockLog log;
  SetCurrentTimeToSecond(kTimeNow + kLeaseDuration + 1);
  EXPECT_CALL(log,
              Log(_, _, EndsWith("Current DHCP lease has already expired")));
  EXPECT_FALSE(controller_->TimeToLeaseExpiry().has_value());
  ResetDHCPVerboseLog();
}

TEST_F(DHCPControllerTest, ExpiryMetrics) {
  // Get a lease with duration of 1 second, the expiry callback should be
  // triggered right after 1 second.
  IPConfig::Properties properties;
  properties.lease_duration_seconds = 1;
  InvokeOnIPConfigUpdated(properties, true);

  dispatcher()->task_environment().FastForwardBy(base::Milliseconds(500));

  EXPECT_CALL(metrics_, SendToUMA(Metrics::kMetricExpiredLeaseLengthSeconds,
                                  Technology(Technology::kUnknown), 1));
  dispatcher()->task_environment().FastForwardBy(base::Milliseconds(500));
}

namespace {

class DHCPControllerCallbackTest : public DHCPControllerTest {
 public:
  void SetUp() override {
    DHCPControllerTest::SetUp();
    controller_->RegisterCallbacks(
        base::BindRepeating(&DHCPControllerCallbackTest::UpdateCallback,
                            base::Unretained(this)),
        base::BindRepeating(&DHCPControllerCallbackTest::DropCallback,
                            base::Unretained(this)));
  }

  MOCK_METHOD(void, UpdateCallback, (const IPConfig::Properties&, bool));
  MOCK_METHOD(void, DropCallback, (bool is_voluntary));

  void ExpectUpdateCallback(bool new_lease_acquired) {
    EXPECT_CALL(*this, UpdateCallback(_, new_lease_acquired))
        .WillOnce(SaveArg<0>(&update_properties_));
    EXPECT_CALL(*this, DropCallback(_)).Times(0);
    dispatcher()->task_environment().RunUntilIdle();
  }

  void ExpectFailureCallback() {
    EXPECT_CALL(*this, UpdateCallback(_, _)).Times(0);
    EXPECT_CALL(*this, DropCallback(/*is_voluntary=*/false));
    dispatcher()->task_environment().RunUntilIdle();
  }

 protected:
  IPConfig::Properties update_properties_;
};

}  // namespace

TEST_F(DHCPControllerCallbackTest, ProcessEventSignalSuccess) {
  std::map<std::string, DHCPController::ClientEventReason> cases = {
      {"Bound", DHCPController::ClientEventReason::kBound},
      {"Rebind", DHCPController::ClientEventReason::kRebind},
      {"Reboot", DHCPController::ClientEventReason::kReboot},
      {"Renew", DHCPController::ClientEventReason::kRenew}};
  for (const auto& [name, reason] : cases) {
    int address_octet = 0;
    for (const auto lease_time_given : {false, true}) {
      KeyValueStore conf;
      conf.Set<uint32_t>(DHCPv4Config::kConfigurationKeyIPAddress,
                         ++address_octet);
      if (lease_time_given) {
        const uint32_t kLeaseTime = 1;
        conf.Set<uint32_t>(DHCPv4Config::kConfigurationKeyLeaseTime,
                           kLeaseTime);
      }
      controller_->ProcessEventSignal(reason, conf);
      ExpectUpdateCallback(true);
      std::string failure_message = name + " failed with lease time " +
                                    (lease_time_given ? "given" : "not given");
      EXPECT_TRUE(Mock::VerifyAndClearExpectations(this)) << failure_message;
      EXPECT_EQ(base::StringPrintf("%d.0.0.0", address_octet),
                update_properties_.address)
          << failure_message;
    }
  }
}

TEST_F(DHCPControllerCallbackTest, ProcessEventSignalFail) {
  KeyValueStore conf;
  conf.Set<uint32_t>(DHCPv4Config::kConfigurationKeyIPAddress, 0x01020304);
  controller_->lease_acquisition_timeout_callback_.Reset(base::DoNothing());
  controller_->lease_expiration_callback_.Reset(base::DoNothing());
  controller_->ProcessEventSignal(DHCPController::ClientEventReason::kFail,
                                  conf);
  ExpectFailureCallback();
  Mock::VerifyAndClearExpectations(this);
  EXPECT_TRUE(update_properties_.address.empty());
  EXPECT_TRUE(controller_->lease_acquisition_timeout_callback_.IsCancelled());
  EXPECT_TRUE(controller_->lease_expiration_callback_.IsCancelled());
}

TEST_F(DHCPControllerCallbackTest, ProcessEventSignalUnknown) {
  KeyValueStore conf;
  conf.Set<uint32_t>(DHCPv4Config::kConfigurationKeyIPAddress, 0x01020304);
  EXPECT_CALL(*this, UpdateCallback(_, _)).Times(0);
  EXPECT_CALL(*this, DropCallback(_)).Times(0);
  controller_->ProcessEventSignal(DHCPController::ClientEventReason::kUnknown,
                                  conf);
  Mock::VerifyAndClearExpectations(this);
}

TEST_F(DHCPControllerCallbackTest, ProcessEventSignalGatewayArp) {
  KeyValueStore conf;
  conf.Set<uint32_t>(DHCPv4Config::kConfigurationKeyIPAddress, 0x01020304);
  EXPECT_CALL(process_manager_, StartProcessInMinijail(_, _, _, _, _, _))
      .WillOnce(Return(0));
  StartInstance();
  controller_->ProcessEventSignal(
      DHCPController::ClientEventReason::kGatewayArp, conf);
  ExpectUpdateCallback(false);
  Mock::VerifyAndClearExpectations(this);
  EXPECT_EQ("4.3.2.1", update_properties_.address);
  // Will not fail on acquisition timeout since Gateway ARP is active.
  EXPECT_FALSE(ShouldFailOnAcquisitionTimeout());

  // An official reply from a DHCP server should reset our GatewayArp state.
  controller_->ProcessEventSignal(DHCPController::ClientEventReason::kRenew,
                                  conf);
  ExpectUpdateCallback(true);
  Mock::VerifyAndClearExpectations(this);
  // Will fail on acquisition timeout since Gateway ARP is not active.
  EXPECT_TRUE(ShouldFailOnAcquisitionTimeout());
}

TEST_F(DHCPControllerCallbackTest, ProcessEventSignalGatewayArpNak) {
  KeyValueStore conf;
  conf.Set<uint32_t>(DHCPv4Config::kConfigurationKeyIPAddress, 0x01020304);
  EXPECT_CALL(process_manager_, StartProcessInMinijail(_, _, _, _, _, _))
      .WillOnce(Return(0));
  StartInstance();
  controller_->ProcessEventSignal(
      DHCPController::ClientEventReason::kGatewayArp, conf);
  EXPECT_FALSE(ShouldFailOnAcquisitionTimeout());

  // Sending a NAK should clear is_gateway_arp_active_.
  controller_->ProcessEventSignal(DHCPController::ClientEventReason::kNak,
                                  conf);
  // Will fail on acquisition timeout since Gateway ARP is not active.
  EXPECT_TRUE(ShouldFailOnAcquisitionTimeout());
  Mock::VerifyAndClearExpectations(this);
}

TEST_F(DHCPControllerCallbackTest, ProcessStatusChangedSignalUnknown) {
  EXPECT_CALL(*this, UpdateCallback(_, _)).Times(0);
  EXPECT_CALL(*this, DropCallback(_)).Times(0);
  controller_->ProcessStatusChangedSignal(
      DHCPController::ClientStatus::kUnknown);
  dispatcher()->task_environment().RunUntilIdle();
}

TEST_F(DHCPControllerCallbackTest,
       ProcessStatusChangedSignalIPv6OnlyPreferred) {
  EXPECT_CALL(*this, UpdateCallback(_, _)).Times(0);
  EXPECT_CALL(*this, DropCallback(/*is_voluntary=*/true));
  controller_->ProcessStatusChangedSignal(
      DHCPController::ClientStatus::kIPv6Preferred);
  dispatcher()->task_environment().RunUntilIdle();
}

TEST_F(DHCPControllerCallbackTest, StoppedDuringFailureCallback) {
  KeyValueStore conf;
  conf.Set<uint32_t>(DHCPv4Config::kConfigurationKeyIPAddress, 0x01020304);
  // Stop the DHCP config while it is calling the failure callback.  We
  // need to ensure that no callbacks are left running inadvertently as
  // a result.
  controller_->ProcessEventSignal(DHCPController::ClientEventReason::kFail,
                                  conf);
  EXPECT_CALL(*this, DropCallback(/*is_voluntary=*/false))
      .WillOnce(InvokeWithoutArgs(this, &DHCPControllerTest::StopInstance));
  dispatcher()->task_environment().RunUntilIdle();
  EXPECT_TRUE(Mock::VerifyAndClearExpectations(this));
  EXPECT_TRUE(controller_->lease_acquisition_timeout_callback_.IsCancelled());
  EXPECT_TRUE(controller_->lease_expiration_callback_.IsCancelled());
}

TEST_F(DHCPControllerCallbackTest, StoppedDuringSuccessCallback) {
  KeyValueStore conf;
  conf.Set<uint32_t>(DHCPv4Config::kConfigurationKeyIPAddress, 0x01020304);
  conf.Set<uint32_t>(DHCPv4Config::kConfigurationKeyLeaseTime, kLeaseDuration);

  // Stop the DHCP config while it is calling the success callback.  This
  // can happen if the device has a static IP configuration and releases
  // the lease after accepting other network parameters from the DHCP
  // IPConfig properties.  We need to ensure that no callbacks are left
  // running inadvertently as a result.
  controller_->ProcessEventSignal(DHCPController::ClientEventReason::kBound,
                                  conf);
  EXPECT_CALL(*this, UpdateCallback(_, true))
      .WillOnce(InvokeWithoutArgs(this, &DHCPControllerTest::StopInstance));
  dispatcher()->task_environment().RunUntilIdle();
  EXPECT_TRUE(Mock::VerifyAndClearExpectations(this));
  EXPECT_TRUE(controller_->lease_acquisition_timeout_callback_.IsCancelled());
  EXPECT_TRUE(controller_->lease_expiration_callback_.IsCancelled());
}

TEST_F(DHCPControllerCallbackTest, ProcessAcquisitionTimeout) {
  // Do not fail on acquisition timeout (i.e. ARP gateway is active).
  SetShouldFailOnAcquisitionTimeout(false);
  EXPECT_CALL(*this, DropCallback(_)).Times(0);
  controller_->ProcessAcquisitionTimeout();
  dispatcher()->task_environment().RunUntilIdle();
  Mock::VerifyAndClearExpectations(this);
  Mock::VerifyAndClearExpectations(controller_.get());

  // Fail on acquisition timeout.
  SetShouldFailOnAcquisitionTimeout(true);
  controller_->ProcessAcquisitionTimeout();
  ExpectFailureCallback();
  Mock::VerifyAndClearExpectations(this);
  Mock::VerifyAndClearExpectations(controller_.get());
}

TEST_F(DHCPControllerTest, ReleaseIP) {
  controller_->pid_ = 1 << 18;  // Ensure unknown positive PID.
  EXPECT_CALL(*proxy_, Release(kDeviceName)).Times(1);
  SetShouldKeepLeaseOnDisconnect(false);
  controller_->proxy_ = std::move(proxy_);
  EXPECT_TRUE(controller_->ReleaseIP(DHCPController::kReleaseReasonDisconnect));
  controller_->pid_ = 0;
}

TEST_F(DHCPControllerTest, KeepLeaseOnDisconnect) {
  controller_->pid_ = 1 << 18;  // Ensure unknown positive PID.

  // Keep lease on disconnect (i.e. ARP gateway is enabled).
  SetShouldKeepLeaseOnDisconnect(true);
  EXPECT_CALL(*proxy_, Release(kDeviceName)).Times(0);
  controller_->proxy_ = std::move(proxy_);
  EXPECT_TRUE(controller_->ReleaseIP(DHCPController::kReleaseReasonDisconnect));
  controller_->pid_ = 0;
}

TEST_F(DHCPControllerTest, ReleaseLeaseOnDisconnect) {
  controller_->pid_ = 1 << 18;  // Ensure unknown positive PID.

  // Release lease on disconnect.
  SetShouldKeepLeaseOnDisconnect(false);
  EXPECT_CALL(*proxy_, Release(kDeviceName)).Times(1);
  controller_->proxy_ = std::move(proxy_);
  EXPECT_TRUE(controller_->ReleaseIP(DHCPController::kReleaseReasonDisconnect));
  controller_->pid_ = 0;
}

TEST_F(DHCPControllerTest, ReleaseIPStaticIPWithLease) {
  controller_->pid_ = 1 << 18;  // Ensure unknown positive PID.
  controller_->is_lease_active_ = true;
  EXPECT_CALL(*proxy_, Release(kDeviceName));
  controller_->proxy_ = std::move(proxy_);
  EXPECT_TRUE(controller_->ReleaseIP(DHCPController::kReleaseReasonStaticIP));
  EXPECT_EQ(nullptr, controller_->proxy_);
  controller_->pid_ = 0;
}

TEST_F(DHCPControllerTest, ReleaseIPStaticIPWithoutLease) {
  controller_->pid_ = 1 << 18;  // Ensure unknown positive PID.
  controller_->is_lease_active_ = false;
  EXPECT_CALL(*proxy_, Release(kDeviceName)).Times(0);
  MockDHCPProxy* proxy_pointer = proxy_.get();
  controller_->proxy_ = std::move(proxy_);
  EXPECT_TRUE(controller_->ReleaseIP(DHCPController::kReleaseReasonStaticIP));
  // Expect that proxy has not been released.
  EXPECT_EQ(proxy_pointer, controller_->proxy_.get());
  controller_->pid_ = 0;
}

TEST_F(DHCPControllerTest, RenewIP) {
  EXPECT_CALL(process_manager_, StartProcessInMinijail(_, _, _, _, _, _))
      .WillOnce(Return(-1));
  controller_->pid_ = 0;
  EXPECT_FALSE(
      controller_->RenewIP());  // Expect a call to Start() if pid_ is 0.
  Mock::VerifyAndClearExpectations(&process_manager_);
  EXPECT_CALL(process_manager_, StartProcessInMinijail(_, _, _, _, _, _))
      .Times(0);
  EXPECT_TRUE(controller_->lease_acquisition_timeout_callback_.IsCancelled());
  controller_->lease_expiration_callback_.Reset(base::DoNothing());
  controller_->pid_ = 456;
  EXPECT_FALSE(controller_->RenewIP());  // Expect no crash with NULL proxy.
  EXPECT_CALL(*proxy_, Rebind(kDeviceName)).Times(1);
  controller_->proxy_ = std::move(proxy_);
  EXPECT_TRUE(controller_->RenewIP());
  EXPECT_FALSE(controller_->lease_acquisition_timeout_callback_.IsCancelled());
  EXPECT_TRUE(controller_->lease_expiration_callback_.IsCancelled());
  controller_->pid_ = 0;
}

TEST_F(DHCPControllerTest, RequestIP) {
  EXPECT_TRUE(controller_->lease_acquisition_timeout_callback_.IsCancelled());
  controller_->pid_ = 567;
  EXPECT_CALL(*proxy_, Rebind(kDeviceName)).Times(1);
  controller_->proxy_ = std::move(proxy_);
  EXPECT_TRUE(controller_->RenewIP());
  EXPECT_FALSE(controller_->lease_acquisition_timeout_callback_.IsCancelled());
  controller_->pid_ = 0;
}

TEST_F(DHCPControllerCallbackTest, RequestIPTimeout) {
  SetShouldFailOnAcquisitionTimeout(true);
  ExpectFailureCallback();
  controller_->lease_acquisition_timeout_ = base::TimeDelta();
  controller_->pid_ = 567;
  EXPECT_CALL(*proxy_, Rebind(kDeviceName)).Times(1);
  controller_->proxy_ = std::move(proxy_);
  controller_->RenewIP();
  controller_->dispatcher_->DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(this);
  Mock::VerifyAndClearExpectations(controller_.get());
  controller_->pid_ = 0;
}

TEST_F(DHCPControllerTest, Restart) {
  const int kPID1 = 1 << 17;  // Ensure unknown positive PID.
  const int kPID2 = 987;
  controller_->pid_ = kPID1;
  EXPECT_CALL(provider_, UnbindPID(kPID1));
  EXPECT_CALL(process_manager_, StopProcessAndBlock(kPID1))
      .WillOnce(Return(true));
  EXPECT_CALL(process_manager_, StartProcessInMinijail(_, _, _, _, _, _))
      .WillOnce(Return(kPID2));
  EXPECT_CALL(provider_, BindPID(kPID2, IsWeakPtrTo(controller_.get())));
  EXPECT_TRUE(controller_->Restart());
  EXPECT_EQ(kPID2, controller_->pid_);
  controller_->pid_ = 0;
}

TEST_F(DHCPControllerTest, RestartNoClient) {
  const int kPID = 777;
  EXPECT_CALL(process_manager_, StopProcessAndBlock(_)).Times(0);
  EXPECT_CALL(process_manager_, StartProcessInMinijail(_, _, _, _, _, _))
      .WillOnce(Return(kPID));
  EXPECT_CALL(provider_, BindPID(kPID, IsWeakPtrTo(controller_.get())));
  EXPECT_TRUE(controller_->Restart());
  EXPECT_EQ(kPID, controller_->pid_);
  controller_->pid_ = 0;
}

TEST_F(DHCPControllerCallbackTest, StartTimeout) {
  SetShouldFailOnAcquisitionTimeout(true);
  ExpectFailureCallback();
  controller_->lease_acquisition_timeout_ = base::TimeDelta();
  controller_->proxy_ = std::move(proxy_);
  EXPECT_CALL(process_manager_, StartProcessInMinijail(_, _, _, _, _, _))
      .WillOnce(Return(0));
  controller_->Start();
  controller_->dispatcher_->DispatchPendingEvents();
  Mock::VerifyAndClearExpectations(this);
  Mock::VerifyAndClearExpectations(controller_.get());
}

TEST_F(DHCPControllerTest, Stop) {
  const int kPID = 1 << 17;  // Ensure unknown positive PID.
  ScopedMockLog log;
  EXPECT_CALL(log, Log(_, _, _)).Times(AnyNumber());
  EXPECT_CALL(
      log,
      Log(_, _, ContainsRegex(base::StringPrintf("Stopping.+%s", __func__))));
  controller_->pid_ = kPID;
  controller_->lease_acquisition_timeout_callback_.Reset(base::DoNothing());
  controller_->lease_expiration_callback_.Reset(base::DoNothing());
  EXPECT_CALL(provider_, UnbindPID(kPID));
  controller_->Stop(__func__);
  EXPECT_TRUE(controller_->lease_acquisition_timeout_callback_.IsCancelled());
  EXPECT_TRUE(controller_->lease_expiration_callback_.IsCancelled());
  EXPECT_FALSE(controller_->pid_);
}

TEST_F(DHCPControllerTest, StopDuringRequestIP) {
  controller_->pid_ = 567;
  EXPECT_CALL(*proxy_, Rebind(kDeviceName)).Times(1);
  controller_->proxy_ = std::move(proxy_);
  EXPECT_TRUE(controller_->RenewIP());
  EXPECT_FALSE(controller_->lease_acquisition_timeout_callback_.IsCancelled());
  controller_->pid_ = 0;  // Keep Stop from killing a real process.
  controller_->Stop(__func__);
  EXPECT_TRUE(controller_->lease_acquisition_timeout_callback_.IsCancelled());
}

namespace {
// Verifies the existence of pid file and lease file after dhcpcd exited.
class DHCPControllerDHCPCDStoppedTest : public DHCPControllerTest {
 protected:
  void StartAndSaveExitCallback() {
    EXPECT_CALL(process_manager_, StartProcessInMinijail(_, _, _, _, _, _))
        .WillOnce(WithArg<5>([this](ProcessManager::ExitCallback cb) {
          exit_callback_ = std::move(cb);
          return kPID;
        }));
    EXPECT_CALL(provider_, BindPID(kPID, IsWeakPtrTo(controller_.get())));
    StartInstance();
  }

  // Creates pid and lease files in a ScopedTempDir which should be generated by
  // dhcpcd normally.
  void PrepareFiles() {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    controller_->set_root_for_testing(temp_dir_.GetPath());
    base::FilePath varrun = temp_dir_.GetPath().Append("var/run/dhcpcd");
    ASSERT_TRUE(base::CreateDirectory(varrun));
    pid_file_ =
        varrun.Append(base::StringPrintf("dhcpcd-%s-4.pid", kDeviceName));
    base::FilePath varlib = temp_dir_.GetPath().Append("var/lib/dhcpcd");
    ASSERT_TRUE(base::CreateDirectory(varlib));
    lease_file_ = varlib.Append(base::StringPrintf("%s.lease", kDeviceName));
    ASSERT_EQ(0, base::WriteFile(pid_file_, "", 0));
    ASSERT_EQ(0, base::WriteFile(lease_file_, "", 0));
    ASSERT_TRUE(base::PathExists(pid_file_));
    ASSERT_TRUE(base::PathExists(lease_file_));
  }

  void StopAndExpect(bool lease_file_exists) {
    ScopedMockLog log;
    // We use a non-zero exit status so that we get the log message.
    EXPECT_CALL(log, Log(_, _, ::testing::EndsWith("status 10")));
    EXPECT_CALL(provider_, UnbindPID(kPID));
    std::move(exit_callback_).Run(10);

    EXPECT_FALSE(base::PathExists(pid_file_));
    EXPECT_EQ(lease_file_exists, base::PathExists(lease_file_));
  }

  base::FilePath lease_file_;
  base::FilePath pid_file_;
  base::ScopedTempDir temp_dir_;
  ProcessManager::ExitCallback exit_callback_;
};

TEST_F(DHCPControllerDHCPCDStoppedTest, StopEphemral) {
  CreateMockMinijailConfig(kHostName, kDeviceName, kArpGateway);
  StartAndSaveExitCallback();
  PrepareFiles();
  StopAndExpect(false);
}

TEST_F(DHCPControllerDHCPCDStoppedTest, StopPersistent) {
  CreateMockMinijailConfig(kHostName, kLeaseFileSuffix, kArpGateway);
  StartAndSaveExitCallback();
  PrepareFiles();
  StopAndExpect(true);
}
}  // namespace

}  // namespace shill
