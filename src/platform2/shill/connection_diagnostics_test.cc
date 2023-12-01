// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/connection_diagnostics.h"

#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/time/time.h>
#include <gtest/gtest.h>

#include "shill/icmp_session.h"
#include "shill/manager.h"
#include "shill/mock_control.h"
#include "shill/mock_dns_client.h"
#include "shill/mock_event_dispatcher.h"
#include "shill/mock_icmp_session.h"
#include "shill/mock_metrics.h"

using testing::_;
using testing::ByMove;
using testing::DoAll;
using testing::NiceMock;
using testing::Return;
using testing::ReturnRef;
using testing::ReturnRefOfCopy;
using testing::SetArgPointee;
using testing::Test;

namespace shill {

namespace {
constexpr const char kInterfaceName[] = "int0";
constexpr const int kInterfaceIndex = 4;
constexpr const char kDNSServer0[] = "8.8.8.8";
constexpr const char kDNSServer1[] = "8.8.4.4";
const std::vector<std::string> kIPv4DnsList{kDNSServer0, kDNSServer1};
const std::vector<std::string> kIPv6DnsList{
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
};
constexpr const char kHttpUrl[] = "http://www.gstatic.com/generate_204";
const auto kIPv4DeviceAddress = *IPAddress::CreateFromString("100.200.43.22");
const auto kIPv6DeviceAddress =
    *IPAddress::CreateFromString("2001:db8::3333:4444:5555");
const auto kIPv4ServerAddress = *IPAddress::CreateFromString("8.8.8.8");
const auto kIPv6ServerAddress =
    *IPAddress::CreateFromString("fe80::1aa9:5ff:7ebf:14c5");
const auto kIPv4GatewayAddress = *IPAddress::CreateFromString("192.168.1.1");
const auto kIPv6GatewayAddress =
    *IPAddress::CreateFromString("fee2::11b2:53f:13be:125e");
const auto kIPv4ZeroAddress = *IPAddress::CreateFromString("0.0.0.0");
const std::vector<base::TimeDelta> kEmptyResult;
const std::vector<base::TimeDelta> kNonEmptyResult{base::Milliseconds(10)};
}  // namespace

MATCHER_P(IsEventList, expected_events, "") {
  // Match on type, phase, and result, but not message.
  if (arg.size() != expected_events.size()) {
    return false;
  }
  for (size_t i = 0; i < expected_events.size(); ++i) {
    if (expected_events[i].type != arg[i].type ||
        expected_events[i].phase != arg[i].phase ||
        expected_events[i].result != arg[i].result) {
      *result_listener << "\n=== Mismatch found on expected event index " << i
                       << " ===";
      *result_listener << "\nExpected: "
                       << ConnectionDiagnostics::EventToString(
                              expected_events[i]);
      *result_listener << "\n  Actual: "
                       << ConnectionDiagnostics::EventToString(arg[i]);
      *result_listener << "\nExpected connection diagnostics events:";
      for (const auto& expected_event : expected_events) {
        *result_listener << "\n"
                         << ConnectionDiagnostics::EventToString(
                                expected_event);
      }
      *result_listener << "\nActual connection diagnostics events:";
      for (const auto& actual_event : expected_events) {
        *result_listener << "\n"
                         << ConnectionDiagnostics::EventToString(actual_event);
      }
      return false;
    }
  }
  return true;
}

MATCHER_P4(IsArpRequest, local_ip, remote_ip, local_mac, remote_mac, "") {
  if (local_ip.Equals(arg.local_ip_address()) &&
      remote_ip.Equals(arg.remote_ip_address()) &&
      local_mac.Equals(arg.local_mac_address()) &&
      remote_mac.Equals(arg.remote_mac_address())) {
    return true;
  }

  if (!local_ip.Equals(arg.local_ip_address())) {
    *result_listener << "Device IP '" << arg.local_ip_address().ToString()
                     << "' (expected '" << local_ip.ToString() << "').";
  }

  if (!remote_ip.Equals(arg.remote_ip_address())) {
    *result_listener << "Remote IP '" << arg.remote_ip_address().ToString()
                     << "' (expected '" << remote_ip.ToString() << "').";
  }

  if (!local_mac.Equals(arg.local_mac_address())) {
    *result_listener << "Device MAC '" << arg.local_mac_address().HexEncode()
                     << "' (expected " << local_mac.HexEncode() << ")'.";
  }

  if (!remote_mac.Equals(arg.remote_mac_address())) {
    *result_listener << "Remote MAC '" << arg.remote_mac_address().HexEncode()
                     << "' (expected " << remote_mac.HexEncode() << ")'.";
  }

  return false;
}

class ConnectionDiagnosticsTest : public Test {
 public:
  ConnectionDiagnosticsTest()
      : ip_address_(kIPv4DeviceAddress),
        gateway_(kIPv4GatewayAddress),
        dns_list_(kIPv4DnsList),
        connection_diagnostics_(kInterfaceName,
                                kInterfaceIndex,
                                kIPv4DeviceAddress,
                                kIPv4GatewayAddress,
                                kIPv4DnsList,
                                &dispatcher_,
                                &metrics_,
                                callback_target_.result_callback()) {}

  ~ConnectionDiagnosticsTest() override = default;

  void SetUp() override {
    ASSERT_EQ(IPAddress::kFamilyIPv4, kIPv4DeviceAddress.family());
    ASSERT_EQ(IPAddress::kFamilyIPv4, kIPv4ServerAddress.family());
    ASSERT_EQ(IPAddress::kFamilyIPv4, kIPv4GatewayAddress.family());
    ASSERT_EQ(IPAddress::kFamilyIPv6, kIPv6ServerAddress.family());
    ASSERT_EQ(IPAddress::kFamilyIPv6, kIPv6GatewayAddress.family());

    dns_client_ = new NiceMock<MockDnsClient>();
    icmp_session_ = new NiceMock<MockIcmpSession>(&dispatcher_);
    connection_diagnostics_.dns_client_.reset(dns_client_);  // Passes ownership
    connection_diagnostics_.icmp_session_.reset(
        icmp_session_);  // Passes ownership
  }

  void TearDown() override {}

 protected:
  class CallbackTarget {
   public:
    CallbackTarget() {}

    MOCK_METHOD(void,
                ResultCallback,
                (const std::string&,
                 const std::vector<ConnectionDiagnostics::Event>&));

    base::OnceCallback<void(const std::string&,
                            const std::vector<ConnectionDiagnostics::Event>&)>
    result_callback() {
      return base::BindOnce(&CallbackTarget::ResultCallback,
                            base::Unretained(this));
    }
  };

  CallbackTarget& callback_target() { return callback_target_; }
  const IPAddress& gateway() { return gateway_; }

  void UseIPv6() {
    ip_address_ = kIPv6DeviceAddress;
    gateway_ = kIPv6GatewayAddress;
    dns_list_ = kIPv6DnsList;
    connection_diagnostics_.ip_address_ = kIPv6DeviceAddress;
    connection_diagnostics_.gateway_ = kIPv6GatewayAddress;
    connection_diagnostics_.dns_list_ = kIPv6DnsList;
  }

  void AddExpectedEvent(ConnectionDiagnostics::Type type,
                        ConnectionDiagnostics::Phase phase,
                        ConnectionDiagnostics::Result result) {
    expected_events_.push_back(
        ConnectionDiagnostics::Event(type, phase, result, ""));
  }

  void AddActualEvent(ConnectionDiagnostics::Type type,
                      ConnectionDiagnostics::Phase phase,
                      ConnectionDiagnostics::Result result) {
    connection_diagnostics_.diagnostic_events_.push_back(
        ConnectionDiagnostics::Event(type, phase, result, ""));
  }

  bool DoesPreviousEventMatch(ConnectionDiagnostics::Type type,
                              ConnectionDiagnostics::Phase phase,
                              ConnectionDiagnostics::Result result,
                              size_t num_events_ago) {
    return connection_diagnostics_.DoesPreviousEventMatch(type, phase, result,
                                                          num_events_ago);
  }

  bool Start(const std::string& url) {
    return connection_diagnostics_.Start(url);
  }

  void VerifyStopped() {
    EXPECT_FALSE(connection_diagnostics_.running());
    EXPECT_EQ(0, connection_diagnostics_.num_dns_attempts_);
    EXPECT_TRUE(connection_diagnostics_.diagnostic_events_.empty());
    EXPECT_EQ(nullptr, connection_diagnostics_.dns_client_);
    EXPECT_FALSE(connection_diagnostics_.icmp_session_->IsStarted());
    EXPECT_TRUE(
        connection_diagnostics_.id_to_pending_dns_server_icmp_session_.empty());
    EXPECT_EQ(nullptr, connection_diagnostics_.target_url_);
  }

  void ExpectIcmpSessionStop() { EXPECT_CALL(*icmp_session_, Stop()); }

  void ExpectSuccessfulStart() {
    EXPECT_FALSE(connection_diagnostics_.running());
    EXPECT_TRUE(connection_diagnostics_.diagnostic_events_.empty());
    EXPECT_TRUE(Start(kHttpUrl));
    EXPECT_TRUE(connection_diagnostics_.running());
  }

  void ExpectPingDNSServersStartSuccess() {
    ExpectPingDNSSeversStart(true, "");
  }

  void ExpectPingDNSSeversStartFailureAllAddressesInvalid() {
    ExpectPingDNSSeversStart(false,
                             ConnectionDiagnostics::kIssueDNSServersInvalid);
  }

  void ExpectPingDNSSeversStartFailureAllIcmpSessionsFailed() {
    ExpectPingDNSSeversStart(false, ConnectionDiagnostics::kIssueInternalError);
  }

  void ExpectPingDNSServersEndSuccessRetriesLeft() {
    ExpectPingDNSServersEndSuccess(true);
  }

  void ExpectPingDNSServersEndSuccessNoRetriesLeft() {
    ExpectPingDNSServersEndSuccess(false);
  }

  void ExpectPingDNSServersEndFailure() {
    AddExpectedEvent(ConnectionDiagnostics::kTypePingDNSServers,
                     ConnectionDiagnostics::kPhaseEnd,
                     ConnectionDiagnostics::kResultFailure);
    // Post task to find DNS server route only after all (i.e. 2) pings are
    // done.
    connection_diagnostics_.OnPingDNSServerComplete(0, kEmptyResult);
    EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, base::TimeDelta()));
    connection_diagnostics_.OnPingDNSServerComplete(1, kEmptyResult);
  }

  void ExpectResolveTargetServerIPAddressStartSuccess(
      IPAddress::Family family) {
    AddExpectedEvent(ConnectionDiagnostics::kTypeResolveTargetServerIP,
                     ConnectionDiagnostics::kPhaseStart,
                     ConnectionDiagnostics::kResultSuccess);
    ASSERT_FALSE(family == IPAddress::kFamilyUnknown);
    EXPECT_CALL(
        *dns_client_,
        Start(dns_list_, connection_diagnostics_.target_url_->host(), _))
        .WillOnce(Return(true));
    connection_diagnostics_.ResolveTargetServerIPAddress(dns_list_);
  }

  void ExpectResolveTargetServerIPAddressEndSuccess(
      const IPAddress& resolved_address) {
    ExpectResolveTargetServerIPAddressEnd(ConnectionDiagnostics::kResultSuccess,
                                          resolved_address);
  }

  void ExpectResolveTargetServerIPAddressEndTimeout() {
    ExpectResolveTargetServerIPAddressEnd(
        ConnectionDiagnostics::kResultTimeout,
        IPAddress::CreateFromFamily(IPAddress::kFamilyIPv4));
  }

  void ExpectResolveTargetServerIPAddressEndFailure() {
    ExpectResolveTargetServerIPAddressEnd(
        ConnectionDiagnostics::kResultFailure,
        IPAddress::CreateFromFamily(IPAddress::kFamilyIPv4));
  }

  void ExpectPingHostStartSuccess(ConnectionDiagnostics::Type ping_event_type,
                                  const IPAddress& address) {
    AddExpectedEvent(ping_event_type, ConnectionDiagnostics::kPhaseStart,
                     ConnectionDiagnostics::kResultSuccess);
    EXPECT_CALL(*icmp_session_, Start(address, _, _)).WillOnce(Return(true));
    connection_diagnostics_.PingHost(address);
  }

  void ExpectPingHostStartFailure(ConnectionDiagnostics::Type ping_event_type,
                                  const IPAddress& address) {
    AddExpectedEvent(ping_event_type, ConnectionDiagnostics::kPhaseStart,
                     ConnectionDiagnostics::kResultFailure);
    EXPECT_CALL(*icmp_session_, Start(address, _, _)).WillOnce(Return(false));
    EXPECT_CALL(metrics_, NotifyConnectionDiagnosticsIssue(
                              ConnectionDiagnostics::kIssueInternalError));
    EXPECT_CALL(callback_target(),
                ResultCallback(ConnectionDiagnostics::kIssueInternalError,
                               IsEventList(expected_events_)));
    connection_diagnostics_.PingHost(address);
  }

  void ExpectPingHostEndSuccess(ConnectionDiagnostics::Type ping_event_type,
                                const IPAddress& address) {
    AddExpectedEvent(ping_event_type, ConnectionDiagnostics::kPhaseEnd,
                     ConnectionDiagnostics::kResultSuccess);
    const auto& issue =
        ping_event_type == ConnectionDiagnostics::kTypePingGateway
            ? ConnectionDiagnostics::kIssueGatewayUpstream
            : ConnectionDiagnostics::kIssueHTTP;
    EXPECT_CALL(metrics_, NotifyConnectionDiagnosticsIssue(issue));
    EXPECT_CALL(callback_target(),
                ResultCallback(issue, IsEventList(expected_events_)));
    connection_diagnostics_.OnPingHostComplete(ping_event_type, address,
                                               kNonEmptyResult);
  }

  void ExpectPingHostEndFailure(ConnectionDiagnostics::Type ping_event_type,
                                const IPAddress& address) {
    AddExpectedEvent(ping_event_type, ConnectionDiagnostics::kPhaseEnd,
                     ConnectionDiagnostics::kResultFailure);
    // If the ping destination was not the gateway, the next action is to try
    // to ping the gateway.
    if (ping_event_type == ConnectionDiagnostics::kTypePingTargetServer) {
      EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, base::TimeDelta()));
    }
    connection_diagnostics_.OnPingHostComplete(ping_event_type, address,
                                               kEmptyResult);
  }

 private:
  // |expected_issue| only used if |is_success| is false.
  void ExpectPingDNSSeversStart(bool is_success,
                                const std::string& expected_issue) {
    AddExpectedEvent(ConnectionDiagnostics::kTypePingDNSServers,
                     ConnectionDiagnostics::kPhaseStart,
                     is_success ? ConnectionDiagnostics::kResultSuccess
                                : ConnectionDiagnostics::kResultFailure);
    if (!is_success &&
        // If the DNS server addresses are invalid, we will not even attempt to
        // start any ICMP sessions.
        expected_issue == ConnectionDiagnostics::kIssueDNSServersInvalid) {
      connection_diagnostics_.dns_list_ = {"110.2.3", "1.5"};
    } else {
      // We are either instrumenting the success case (started pinging all
      // DNS servers successfully) or the failure case where we fail to start
      // any pings.
      ASSERT_TRUE(is_success ||
                  expected_issue == ConnectionDiagnostics::kIssueInternalError);

      auto dns_server_icmp_session_0 =
          std::make_unique<NiceMock<MockIcmpSession>>(&dispatcher_);
      auto dns_server_icmp_session_1 =
          std::make_unique<NiceMock<MockIcmpSession>>(&dispatcher_);

      EXPECT_CALL(*dns_server_icmp_session_0,
                  Start(*IPAddress::CreateFromString(kDNSServer0), _, _))
          .WillOnce(Return(is_success));
      EXPECT_CALL(*dns_server_icmp_session_1,
                  Start(*IPAddress::CreateFromString(kDNSServer1), _, _))
          .WillOnce(Return(is_success));

      connection_diagnostics_.id_to_pending_dns_server_icmp_session_.clear();
      connection_diagnostics_.id_to_pending_dns_server_icmp_session_[0] =
          std::move(dns_server_icmp_session_0);
      connection_diagnostics_.id_to_pending_dns_server_icmp_session_[1] =
          std::move(dns_server_icmp_session_1);
    }

    if (is_success) {
      EXPECT_CALL(metrics_, NotifyConnectionDiagnosticsIssue(_)).Times(0);
      EXPECT_CALL(callback_target(), ResultCallback(_, _)).Times(0);
    } else {
      EXPECT_CALL(metrics_, NotifyConnectionDiagnosticsIssue(expected_issue));
      EXPECT_CALL(
          callback_target(),
          ResultCallback(expected_issue, IsEventList(expected_events_)));
    }
    connection_diagnostics_.PingDNSServers();
    if (is_success) {
      EXPECT_EQ(2, connection_diagnostics_
                       .id_to_pending_dns_server_icmp_session_.size());
    } else {
      EXPECT_TRUE(connection_diagnostics_.id_to_pending_dns_server_icmp_session_
                      .empty());
    }
  }

  void ExpectResolveTargetServerIPAddressEnd(
      ConnectionDiagnostics::Result result, const IPAddress& resolved_address) {
    AddExpectedEvent(ConnectionDiagnostics::kTypeResolveTargetServerIP,
                     ConnectionDiagnostics::kPhaseEnd, result);
    Error error;
    if (result == ConnectionDiagnostics::kResultSuccess) {
      error.Populate(Error::kSuccess);
      EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, base::TimeDelta()));
    } else if (result == ConnectionDiagnostics::kResultTimeout) {
      error.Populate(Error::kOperationTimeout);
      EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, base::TimeDelta()));
    } else {
      error.Populate(Error::kOperationFailed);
      EXPECT_CALL(metrics_,
                  NotifyConnectionDiagnosticsIssue(
                      ConnectionDiagnostics::kIssueDNSServerMisconfig));
      EXPECT_CALL(
          callback_target(),
          ResultCallback(ConnectionDiagnostics::kIssueDNSServerMisconfig,
                         IsEventList(expected_events_)));
    }
    connection_diagnostics_.OnDNSResolutionComplete(error, resolved_address);
  }

  void ExpectPingDNSServersEndSuccess(bool retries_left) {
    AddExpectedEvent(ConnectionDiagnostics::kTypePingDNSServers,
                     ConnectionDiagnostics::kPhaseEnd,
                     ConnectionDiagnostics::kResultSuccess);
    if (retries_left) {
      EXPECT_LT(connection_diagnostics_.num_dns_attempts_,
                ConnectionDiagnostics::kMaxDNSRetries);
    } else {
      EXPECT_GE(connection_diagnostics_.num_dns_attempts_,
                ConnectionDiagnostics::kMaxDNSRetries);
    }
    // Post retry task or report done only after all (i.e. 2) pings are done.
    connection_diagnostics_.OnPingDNSServerComplete(0, kNonEmptyResult);
    if (retries_left) {
      EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, base::TimeDelta()));
      EXPECT_CALL(metrics_, NotifyConnectionDiagnosticsIssue(_)).Times(0);
      EXPECT_CALL(callback_target(), ResultCallback(_, _)).Times(0);
    } else {
      EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, base::TimeDelta()))
          .Times(0);
      EXPECT_CALL(metrics_,
                  NotifyConnectionDiagnosticsIssue(
                      ConnectionDiagnostics::kIssueDNSServerNoResponse));
      EXPECT_CALL(
          callback_target(),
          ResultCallback(ConnectionDiagnostics::kIssueDNSServerNoResponse,
                         IsEventList(expected_events_)));
    }
    connection_diagnostics_.OnPingDNSServerComplete(1, kNonEmptyResult);
  }

  IPAddress ip_address_;
  IPAddress gateway_;
  std::vector<std::string> dns_list_;
  CallbackTarget callback_target_;
  NiceMock<MockMetrics> metrics_;
  ConnectionDiagnostics connection_diagnostics_;
  NiceMock<MockEventDispatcher> dispatcher_;

  // Used only for EXPECT_CALL(). Objects are owned by
  // |connection_diagnostics_|.
  NiceMock<MockDnsClient>* dns_client_;
  NiceMock<MockIcmpSession>* icmp_session_;

  // For each test, all events we expect to appear in the final result are
  // accumulated in this vector.
  std::vector<ConnectionDiagnostics::Event> expected_events_;
};

TEST_F(ConnectionDiagnosticsTest, DoesPreviousEventMatch) {
  // If |diagnostic_events| is empty, we should always fail to match an event.
  EXPECT_FALSE(
      DoesPreviousEventMatch(ConnectionDiagnostics::kTypePingDNSServers,
                             ConnectionDiagnostics::kPhaseStart,
                             ConnectionDiagnostics::kResultSuccess, 0));
  EXPECT_FALSE(
      DoesPreviousEventMatch(ConnectionDiagnostics::kTypePingDNSServers,
                             ConnectionDiagnostics::kPhaseStart,
                             ConnectionDiagnostics::kResultSuccess, 2));

  AddActualEvent(ConnectionDiagnostics::kTypeResolveTargetServerIP,
                 ConnectionDiagnostics::kPhaseStart,
                 ConnectionDiagnostics::kResultSuccess);
  AddActualEvent(ConnectionDiagnostics::kTypeResolveTargetServerIP,
                 ConnectionDiagnostics::kPhaseEnd,
                 ConnectionDiagnostics::kResultSuccess);

  // Matching out of bounds should fail. (2 events total, so 2 events before the
  // last event is out of bounds).
  EXPECT_FALSE(
      DoesPreviousEventMatch(ConnectionDiagnostics::kTypeResolveTargetServerIP,
                             ConnectionDiagnostics::kPhaseStart,
                             ConnectionDiagnostics::kResultSuccess, 2));

  // Valid matches.
  EXPECT_TRUE(
      DoesPreviousEventMatch(ConnectionDiagnostics::kTypeResolveTargetServerIP,
                             ConnectionDiagnostics::kPhaseStart,
                             ConnectionDiagnostics::kResultSuccess, 1));
  EXPECT_TRUE(
      DoesPreviousEventMatch(ConnectionDiagnostics::kTypeResolveTargetServerIP,
                             ConnectionDiagnostics::kPhaseEnd,
                             ConnectionDiagnostics::kResultSuccess, 0));
}

TEST_F(ConnectionDiagnosticsTest, StartWithBadURL) {
  const std::string kBadURL("http://www.foo.com:x");  // Colon but no port
  // IcmpSession::Stop will be called once when the bad URL is rejected.
  ExpectIcmpSessionStop();
  EXPECT_FALSE(Start(kBadURL));
  // IcmpSession::Stop will be called a second time when
  // |connection_diagnostics_| is destructed.
  ExpectIcmpSessionStop();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_InternalError) {
  // DNS resolution succeeds, and we attempt to ping the target web server but
  // fail because of an internal error.
  ExpectSuccessfulStart();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv4ServerAddress);
  ExpectPingHostStartFailure(ConnectionDiagnostics::kTypePingTargetServer,
                             kIPv4ServerAddress);
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_DNSFailure) {
  // DNS resolution fails (not timeout), so we end diagnostics.
  ExpectSuccessfulStart();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndFailure();
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_PingDNSServerStartFailure_1) {
  // we attempt to pinging DNS servers, but fail to start any IcmpSessions, so
  // end diagnostics.
  ExpectSuccessfulStart();
  ExpectPingDNSSeversStartFailureAllIcmpSessionsFailed();
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_PingDNSServerStartFailure_2) {
  // We attempt to pinging DNS servers, but all DNS servers configured for this
  // connection have invalid IP addresses, so we fail to start ping DNs servers,
  // and end diagnostics.
  ExpectSuccessfulStart();
  ExpectPingDNSSeversStartFailureAllAddressesInvalid();
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_PingDNSServerEndSuccess_NoRetries_1) {
  // Pinging DNS servers succeeds, DNS resolution times out, pinging DNS servers
  // succeeds again, and DNS resolution times out again. End diagnostics because
  // we have no more DNS retries left.
  ExpectSuccessfulStart();
  ExpectPingDNSServersStartSuccess();
  ExpectPingDNSServersEndSuccessRetriesLeft();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndTimeout();
  ExpectPingDNSServersStartSuccess();
  ExpectPingDNSServersEndSuccessRetriesLeft();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndTimeout();
  ExpectPingDNSServersStartSuccess();
  ExpectPingDNSServersEndSuccessNoRetriesLeft();
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_PingDNSServerEndSuccess_NoRetries_2) {
  // DNS resolution times out, pinging DNS servers succeeds, DNS resolution
  // times out again, pinging DNS servers succeeds. End diagnostics because we
  // have no more DNS retries left.
  ExpectSuccessfulStart();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndTimeout();
  ExpectPingDNSServersStartSuccess();
  ExpectPingDNSServersEndSuccessRetriesLeft();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndTimeout();
  ExpectPingDNSServersStartSuccess();
  ExpectPingDNSServersEndSuccessNoRetriesLeft();
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_PingTargetIPSuccess_1) {
  // DNS resolution succeeds, and pinging the resolved IP address succeeds, so
  // we end diagnostics.
  ExpectSuccessfulStart();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv4ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                             kIPv4ServerAddress);
  ExpectPingHostEndSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                           kIPv4ServerAddress);
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_PingTargetIPSuccess_2) {
  // pinging DNS servers succeeds, DNS resolution succeeds, and pinging the
  // resolved IP address succeeds, so we end diagnostics.
  ExpectSuccessfulStart();
  ExpectPingDNSServersStartSuccess();
  ExpectPingDNSServersEndSuccessRetriesLeft();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv4ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                             kIPv4ServerAddress);
  ExpectPingHostEndSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                           kIPv4ServerAddress);
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_PingTargetIPSuccess_3) {
  // DNS resolution times out, pinging DNS servers succeeds, DNS resolution
  // succeeds, and pinging the resolved IP address succeeds, so we end
  // diagnostics.
  ExpectSuccessfulStart();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndTimeout();
  ExpectPingDNSServersStartSuccess();
  ExpectPingDNSServersEndSuccessRetriesLeft();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv4ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                             kIPv4ServerAddress);
  ExpectPingHostEndSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                           kIPv4ServerAddress);
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_PingGatewaySuccess_1_IPv4) {
  // DNS resolution succeeds, pinging the resolved IP address fails, and we
  // successfully get route for the IP address. This address is remote, so ping
  // the local gateway and succeed, so we end diagnostics.
  ExpectSuccessfulStart();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv4ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                             kIPv4ServerAddress);
  ExpectPingHostEndFailure(ConnectionDiagnostics::kTypePingTargetServer,
                           kIPv4ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingGateway,
                             gateway());
  ExpectPingHostEndSuccess(ConnectionDiagnostics::kTypePingGateway, gateway());
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_PingGatewaySuccess_1_IPv6) {
  // Same as above, but this time the resolved IP address of the target URL is
  // IPv6.
  UseIPv6();

  ExpectSuccessfulStart();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv6);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv6ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                             kIPv6ServerAddress);
  ExpectPingHostEndFailure(ConnectionDiagnostics::kTypePingTargetServer,
                           kIPv6ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingGateway,
                             gateway());
  ExpectPingHostEndSuccess(ConnectionDiagnostics::kTypePingGateway, gateway());
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_PingGatewaySuccess_2) {
  // Pinging DNS servers succeeds, DNS resolution succeeds, pinging the resolved
  // IP address fails, and we successfully get route for the IP address. This
  // address is remote, so ping the local gateway and succeed, so we end
  // diagnostics.
  ExpectSuccessfulStart();
  ExpectPingDNSServersStartSuccess();
  ExpectPingDNSServersEndSuccessRetriesLeft();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv4ServerAddress);
  ExpectPingHostEndFailure(ConnectionDiagnostics::kTypePingTargetServer,
                           kIPv4ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingGateway,
                             gateway());
  ExpectPingHostEndSuccess(ConnectionDiagnostics::kTypePingGateway, gateway());
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_PingGatewaySuccess_3) {
  // DNS resolution times out, pinging DNS servers succeeds, DNS resolution
  // succeeds, pinging the resolved IP address fails, and we successfully get
  // route for the IP address. This address is remote, so ping the local
  // gateway. The ping succeeds, so we end diagnostics.
  ExpectSuccessfulStart();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndTimeout();
  ExpectPingDNSServersStartSuccess();
  ExpectPingDNSServersEndSuccessRetriesLeft();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv4ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                             kIPv4ServerAddress);
  ExpectPingHostEndFailure(ConnectionDiagnostics::kTypePingTargetServer,
                           kIPv4ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingGateway,
                             gateway());
  ExpectPingHostEndSuccess(ConnectionDiagnostics::kTypePingGateway, gateway());
  VerifyStopped();
}

TEST_F(ConnectionDiagnosticsTest, EndWith_PingGatewayFailure) {
  // DNS resolution succeeds, pinging the resolved IP address fails. Pinging
  // the gateway also fails, so we end diagnostics.
  ExpectSuccessfulStart();
  ExpectResolveTargetServerIPAddressStartSuccess(IPAddress::kFamilyIPv4);
  ExpectResolveTargetServerIPAddressEndSuccess(kIPv4ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingTargetServer,
                             kIPv4ServerAddress);
  ExpectPingHostEndFailure(ConnectionDiagnostics::kTypePingTargetServer,
                           kIPv4ServerAddress);
  ExpectPingHostStartSuccess(ConnectionDiagnostics::kTypePingGateway,
                             gateway());
  ExpectPingHostEndFailure(ConnectionDiagnostics::kTypePingGateway, gateway());
  VerifyStopped();
}

}  // namespace shill
