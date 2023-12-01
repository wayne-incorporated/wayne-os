// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/openvpn_management_server.h"

#include <netinet/in.h>

#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest.h>

#include "shill/manager.h"
#include "shill/mock_control.h"
#include "shill/mock_event_dispatcher.h"
#include "shill/mock_metrics.h"
#include "shill/net/mock_io_handler_factory.h"
#include "shill/net/mock_process_manager.h"
#include "shill/net/mock_sockets.h"
#include "shill/store/key_value_store.h"
#include "shill/vpn/mock_openvpn_driver.h"

using testing::_;
using testing::Assign;
using testing::Eq;
using testing::InSequence;
using testing::Return;
using testing::ReturnNew;

namespace shill {

namespace {
MATCHER_P(VoidStringEq, value, "") {
  return value == reinterpret_cast<const char*>(arg);
}
}  // namespace

class OpenVPNManagementServerTest : public testing::Test {
 public:
  OpenVPNManagementServerTest()
      : manager_(&control_, &dispatcher_, &metrics_, "", "", ""),
        driver_(&manager_, &process_manager_),
        server_(&driver_) {
    server_.io_handler_factory_ = &io_handler_factory_;
  }

  ~OpenVPNManagementServerTest() override = default;

 protected:
  static const int kConnectedSocket;

  void SetSockets() { server_.sockets_ = &sockets_; }
  void ExpectNotStarted() { EXPECT_FALSE(server_.IsStarted()); }

  void SetConnectedSocket() {
    server_.connected_socket_ = kConnectedSocket;
    SetSockets();
  }

  void ExpectSend(const std::string& value) {
    EXPECT_CALL(sockets_,
                Send(kConnectedSocket, VoidStringEq(value), value.size(), _))
        .WillOnce(Return(value.size()));
  }

  void ExpectOTPStaticChallengeResponse() {
    driver_.args()->Set<std::string>(kOpenVPNUserProperty, "jojo");
    driver_.args()->Set<std::string>(kOpenVPNPasswordProperty, "yoyo");
    driver_.args()->Set<std::string>(kOpenVPNOTPProperty, "123456");
    SetConnectedSocket();
    ExpectSend("username \"Auth\" \"jojo\"\n");
    ExpectSend("password \"Auth\" \"SCRV1:eW95bw==:MTIzNDU2\"\n");
  }

  void ExpectTokenStaticChallengeResponse() {
    driver_.args()->Set<std::string>(kOpenVPNUserProperty, "jojo");
    driver_.args()->Set<std::string>(kOpenVPNTokenProperty, "toto");
    SetConnectedSocket();
    ExpectSend("username \"Auth\" \"jojo\"\n");
    ExpectSend("password \"Auth\" \"toto\"\n");
  }

  void ExpectAuthenticationResponse() {
    driver_.args()->Set<std::string>(kOpenVPNUserProperty, "jojo");
    driver_.args()->Set<std::string>(kOpenVPNPasswordProperty, "yoyo");
    SetConnectedSocket();
    ExpectSend("username \"Auth\" \"jojo\"\n");
    ExpectSend("password \"Auth\" \"yoyo\"\n");
  }

  void ExpectPinResponse() {
    driver_.args()->Set<std::string>(kOpenVPNPinProperty, "987654");
    SetConnectedSocket();
    ExpectSend("password \"User-Specific TPM Token FOO\" \"987654\"\n");
  }

  void ExpectHoldRelease() {
    SetConnectedSocket();
    ExpectSend("hold release\n");
  }

  void ExpectRestart() {
    SetConnectedSocket();
    ExpectSend("signal SIGUSR1\n");
  }

  InputData CreateInputDataFromString(const std::string& str) {
    InputData data(
        reinterpret_cast<unsigned char*>(const_cast<char*>(str.data())),
        str.size());
    return data;
  }

  void SendSignal(const std::string& signal) { server_.SendSignal(signal); }

  void OnInput(InputData* data) { server_.OnInput(data); }

  void ProcessMessage(const std::string& message) {
    server_.ProcessMessage(message);
  }

  bool ProcessSuccessMessage(const std::string& message) {
    return server_.ProcessSuccessMessage(message);
  }

  bool ProcessStateMessage(const std::string& message) {
    return server_.ProcessStateMessage(message);
  }

  bool ProcessAuthTokenMessage(const std::string& message) {
    return server_.ProcessAuthTokenMessage(message);
  }

  bool GetHoldWaiting() { return server_.hold_waiting_; }

  static std::string ParseSubstring(const std::string& message,
                                    const std::string& start,
                                    const std::string& end) {
    return OpenVPNManagementServer::ParseSubstring(message, start, end);
  }

  static std::string ParsePasswordTag(const std::string& message) {
    return OpenVPNManagementServer::ParsePasswordTag(message);
  }

  static std::string ParsePasswordFailedReason(const std::string& message) {
    return OpenVPNManagementServer::ParsePasswordFailedReason(message);
  }

  void SetClientState(const std::string& state) { server_.state_ = state; }

  MockControl control_;
  MockEventDispatcher dispatcher_;
  MockMetrics metrics_;
  MockProcessManager process_manager_;
  Manager manager_;
  MockOpenVPNDriver driver_;
  MockSockets sockets_;
  MockIOHandlerFactory io_handler_factory_;
  OpenVPNManagementServer server_;  // Destroy before anything it references.
};

// static
const int OpenVPNManagementServerTest::kConnectedSocket = 555;

TEST_F(OpenVPNManagementServerTest, StartStarted) {
  SetSockets();
  EXPECT_TRUE(server_.Start(nullptr, nullptr));
}

TEST_F(OpenVPNManagementServerTest, StartSocketFail) {
  EXPECT_CALL(sockets_,
              Socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP))
      .WillOnce(Return(-1));
  EXPECT_FALSE(server_.Start(&sockets_, nullptr));
  ExpectNotStarted();
}

TEST_F(OpenVPNManagementServerTest, StartGetSockNameFail) {
  const int kSocket = 123;
  EXPECT_CALL(sockets_, Socket(AF_INET, _, IPPROTO_TCP))
      .WillOnce(Return(kSocket));
  EXPECT_CALL(sockets_, Bind(kSocket, _, _)).WillOnce(Return(0));
  EXPECT_CALL(sockets_, Listen(kSocket, 1)).WillOnce(Return(0));
  EXPECT_CALL(sockets_, GetSockName(kSocket, _, _)).WillOnce(Return(-1));
  EXPECT_CALL(sockets_, Close(kSocket)).WillOnce(Return(0));
  EXPECT_FALSE(server_.Start(&sockets_, nullptr));
  ExpectNotStarted();
}

TEST_F(OpenVPNManagementServerTest, Start) {
  const std::string kStaticChallenge = "static-challenge";
  driver_.args()->Set<std::string>(kOpenVPNStaticChallengeProperty,
                                   kStaticChallenge);
  const int kSocket = 123;
  EXPECT_CALL(sockets_, Socket(AF_INET, _, IPPROTO_TCP))
      .WillOnce(Return(kSocket));
  EXPECT_CALL(sockets_, Bind(kSocket, _, _)).WillOnce(Return(0));
  EXPECT_CALL(sockets_, Listen(kSocket, 1)).WillOnce(Return(0));
  EXPECT_CALL(sockets_, GetSockName(kSocket, _, _)).WillOnce(Return(0));
  EXPECT_CALL(io_handler_factory_,
              CreateIOReadyHandler(kSocket, IOHandler::kModeInput, _))
      .WillOnce(ReturnNew<IOHandler>());
  std::vector<std::vector<std::string>> options;
  EXPECT_TRUE(server_.Start(&sockets_, &options));
  EXPECT_EQ(&sockets_, server_.sockets_);
  EXPECT_EQ(kSocket, server_.socket_);
  EXPECT_NE(nullptr, server_.ready_handler_);
  std::vector<std::vector<std::string>> expected_options{
      {"management", "127.0.0.1", "0"},
      {"management-client"},
      {"management-hold"},
      {"management-query-passwords"},
      {"static-challenge", kStaticChallenge, "1"}};
  EXPECT_EQ(expected_options, options);
}

TEST_F(OpenVPNManagementServerTest, Stop) {
  EXPECT_TRUE(server_.state().empty());
  SetSockets();
  server_.input_handler_.reset(new IOHandler());
  const int kConnectedSocket = 234;
  server_.connected_socket_ = kConnectedSocket;
  EXPECT_CALL(sockets_, Close(kConnectedSocket)).WillOnce(Return(0));
  server_.ready_handler_.reset(new IOHandler());
  const int kSocket = 345;
  server_.socket_ = kSocket;
  SetClientState(OpenVPNManagementServer::kStateReconnecting);
  EXPECT_CALL(sockets_, Close(kSocket)).WillOnce(Return(0));
  server_.Stop();
  EXPECT_EQ(nullptr, server_.input_handler_);
  EXPECT_EQ(-1, server_.connected_socket_);
  EXPECT_EQ(nullptr, server_.ready_handler_);
  EXPECT_EQ(-1, server_.socket_);
  EXPECT_TRUE(server_.state().empty());
  ExpectNotStarted();
}

TEST_F(OpenVPNManagementServerTest, OnReadyAcceptFail) {
  const int kSocket = 333;
  SetSockets();
  EXPECT_CALL(sockets_, Accept(kSocket, nullptr, nullptr)).WillOnce(Return(-1));
  server_.OnReady(kSocket);
  EXPECT_EQ(-1, server_.connected_socket_);
}

TEST_F(OpenVPNManagementServerTest, OnReady) {
  const int kSocket = 111;
  SetConnectedSocket();
  EXPECT_CALL(sockets_, Accept(kSocket, nullptr, nullptr))
      .WillOnce(Return(kConnectedSocket));
  server_.ready_handler_.reset(new IOHandler());
  EXPECT_CALL(io_handler_factory_, CreateIOInputHandler(kConnectedSocket, _, _))
      .WillOnce(ReturnNew<IOHandler>());
  ExpectSend("state on\n");
  server_.OnReady(kSocket);
  EXPECT_EQ(kConnectedSocket, server_.connected_socket_);
  EXPECT_EQ(nullptr, server_.ready_handler_);
  EXPECT_NE(nullptr, server_.input_handler_);
}

TEST_F(OpenVPNManagementServerTest, OnInput) {
  {
    std::string s;
    InputData data = CreateInputDataFromString(s);
    OnInput(&data);
  }
  {
    std::string s =
        "foo\n"
        ">INFO:...\n"
        ">PASSWORD:Need 'Auth' SC:user/password/otp\n"
        ">PASSWORD:Need 'User-Specific TPM Token FOO' ...\n"
        ">PASSWORD:Verification Failed: .\n"
        ">PASSWORD:Auth-Token:ToKeN==\n"
        ">STATE:123,RECONNECTING,detail,...,...\n"
        ">HOLD:Waiting for hold release\n"
        "SUCCESS: Hold released.";
    InputData data = CreateInputDataFromString(s);
    ExpectOTPStaticChallengeResponse();
    ExpectPinResponse();
    EXPECT_CALL(driver_, FailService(Service::kFailureConnect,
                                     Service::kErrorDetailsNone));
    EXPECT_CALL(driver_, OnReconnecting(_));
    EXPECT_FALSE(GetHoldWaiting());
    OnInput(&data);
    EXPECT_TRUE(GetHoldWaiting());
  }
}

TEST_F(OpenVPNManagementServerTest, OnInputStop) {
  std::string s =
      ">PASSWORD:Verification Failed: .\n"
      ">STATE:123,RECONNECTING,detail,...,...";
  InputData data = CreateInputDataFromString(s);
  SetSockets();
  // Stops the server after the first message is processed.
  EXPECT_CALL(driver_,
              FailService(Service::kFailureConnect, Service::kErrorDetailsNone))
      .WillOnce(Assign(&server_.sockets_, nullptr));
  // The second message should not be processed.
  EXPECT_CALL(driver_, OnReconnecting(_)).Times(0);
  OnInput(&data);
}

TEST_F(OpenVPNManagementServerTest, OnInputStatus) {
  std::string s =
      "OpenVPN STATISTICS\n"
      "Updated,Wed Nov  3 14:11:13 2021\n"
      "TUN/TAP read bytes,0\n"
      "TUN/TAP write bytes,0\n"
      "TCP/UDP read bytes,3495\n"
      "TCP/UDP write bytes,3354\n"
      "Auth read bytes,0\n"
      "Data channel cipher,AES-256-GCM\n"
      "END";
  InputData data = CreateInputDataFromString(s);
  SetSockets();
  EXPECT_CALL(driver_, ReportCipherMetrics("AES-256-GCM"));
  OnInput(&data);
}

TEST_F(OpenVPNManagementServerTest, ProcessMessage) {
  ProcessMessage("foo");
  ProcessMessage(">INFO:");

  EXPECT_CALL(driver_, OnReconnecting(_));
  ProcessMessage(">STATE:123,RECONNECTING,detail,...,...");
}

TEST_F(OpenVPNManagementServerTest, ProcessSuccessMessage) {
  EXPECT_FALSE(ProcessSuccessMessage("foo"));
  EXPECT_TRUE(ProcessSuccessMessage("SUCCESS: foo"));
}

TEST_F(OpenVPNManagementServerTest, ProcessInfoMessage) {
  EXPECT_FALSE(server_.ProcessInfoMessage("foo"));
  EXPECT_TRUE(server_.ProcessInfoMessage(">INFO:foo"));
}

TEST_F(OpenVPNManagementServerTest, ProcessStateMessage) {
  EXPECT_TRUE(server_.state().empty());
  EXPECT_FALSE(ProcessStateMessage("foo"));
  EXPECT_TRUE(server_.state().empty());
  EXPECT_TRUE(ProcessStateMessage(">STATE:123,WAIT,detail,...,..."));
  EXPECT_EQ("WAIT", server_.state());
  {
    InSequence seq;
    EXPECT_CALL(driver_,
                OnReconnecting(OpenVPNDriver::kReconnectReasonUnknown));
    EXPECT_CALL(driver_,
                OnReconnecting(OpenVPNDriver::kReconnectReasonTLSError));
  }
  EXPECT_TRUE(ProcessStateMessage(">STATE:123,RECONNECTING,detail,...,..."));
  EXPECT_EQ(OpenVPNManagementServer::kStateReconnecting, server_.state());
  EXPECT_TRUE(ProcessStateMessage(">STATE:123,RECONNECTING,tls-error,...,..."));
}

TEST_F(OpenVPNManagementServerTest, ProcessStateMessageConnected) {
  EXPECT_TRUE(server_.state().empty());
  SetConnectedSocket();
  ExpectSend("status\n");
  EXPECT_TRUE(ProcessStateMessage(">STATE:123,CONNECTED,SUCCESS,...,..."));
}

TEST_F(OpenVPNManagementServerTest, ProcessNeedPasswordMessageAuthSC) {
  ExpectOTPStaticChallengeResponse();
  EXPECT_TRUE(server_.ProcessNeedPasswordMessage(
      ">PASSWORD:Need 'Auth' SC:user/password/otp"));
  EXPECT_FALSE(driver_.args()->Contains<std::string>(kOpenVPNOTPProperty));
}

TEST_F(OpenVPNManagementServerTest, ProcessNeedPasswordMessageAuth) {
  ExpectAuthenticationResponse();
  EXPECT_TRUE(server_.ProcessNeedPasswordMessage(
      ">PASSWORD:Need 'Auth' username/password"));
}

TEST_F(OpenVPNManagementServerTest, ProcessNeedPasswordMessageTPMToken) {
  ExpectPinResponse();
  EXPECT_TRUE(server_.ProcessNeedPasswordMessage(
      ">PASSWORD:Need 'User-Specific TPM Token FOO' ..."));
}

TEST_F(OpenVPNManagementServerTest, ProcessNeedPasswordMessageUnknown) {
  EXPECT_FALSE(server_.ProcessNeedPasswordMessage("foo"));
}

TEST_F(OpenVPNManagementServerTest, ParseSubstring) {
  EXPECT_EQ("", ParseSubstring("", "'", "'"));
  EXPECT_EQ("", ParseSubstring(" ", "'", "'"));
  EXPECT_EQ("", ParseSubstring("'", "'", "'"));
  EXPECT_EQ("", ParseSubstring("''", "'", "'"));
  EXPECT_EQ("", ParseSubstring("] [", "[", "]"));
  EXPECT_EQ("", ParseSubstring("[]", "[", "]"));
  EXPECT_EQ("bar", ParseSubstring("foo['bar']zoo", "['", "']"));
  EXPECT_EQ("bar", ParseSubstring("foo['bar']", "['", "']"));
  EXPECT_EQ("bar", ParseSubstring("['bar']zoo", "['", "']"));
  EXPECT_EQ("bar", ParseSubstring("['bar']['zoo']", "['", "']"));
}

TEST_F(OpenVPNManagementServerTest, ParsePasswordTag) {
  EXPECT_EQ("", ParsePasswordTag(""));
  EXPECT_EQ("Auth", ParsePasswordTag(
                        ">PASSWORD:Verification Failed: 'Auth' "
                        "['REVOKED: client certificate has been revoked']"));
}

TEST_F(OpenVPNManagementServerTest, ParsePasswordFailedReason) {
  EXPECT_EQ("", ParsePasswordFailedReason(""));
  EXPECT_EQ("REVOKED: client certificate has been revoked",
            ParsePasswordFailedReason(
                ">PASSWORD:Verification Failed: 'Auth' "
                "['REVOKED: client certificate has been revoked']"));
}

TEST_F(OpenVPNManagementServerTest, PerformStaticChallengeNoCreds) {
  EXPECT_CALL(driver_, FailService(Service::kFailureInternal,
                                   Service::kErrorDetailsNone))
      .Times(4);
  server_.PerformStaticChallenge("Auth");
  driver_.args()->Set<std::string>(kOpenVPNUserProperty, "jojo");
  server_.PerformStaticChallenge("Auth");
  driver_.args()->Set<std::string>(kOpenVPNPasswordProperty, "yoyo");
  server_.PerformStaticChallenge("Auth");
  driver_.args()->Clear();
  driver_.args()->Set<std::string>(kOpenVPNTokenProperty, "toto");
  server_.PerformStaticChallenge("Auth");
}

TEST_F(OpenVPNManagementServerTest, PerformStaticChallengeOTP) {
  ExpectOTPStaticChallengeResponse();
  server_.PerformStaticChallenge("Auth");
  EXPECT_FALSE(driver_.args()->Contains<std::string>(kOpenVPNOTPProperty));
}

TEST_F(OpenVPNManagementServerTest, PerformStaticChallengeToken) {
  ExpectTokenStaticChallengeResponse();
  server_.PerformStaticChallenge("Auth");
  EXPECT_FALSE(driver_.args()->Contains<std::string>(kOpenVPNTokenProperty));
}

TEST_F(OpenVPNManagementServerTest, PerformAuthenticationNoCreds) {
  EXPECT_CALL(driver_, FailService(Service::kFailureInternal,
                                   Service::kErrorDetailsNone))
      .Times(2);
  server_.PerformAuthentication("Auth");
  driver_.args()->Set<std::string>(kOpenVPNUserProperty, "jojo");
  server_.PerformAuthentication("Auth");
}

TEST_F(OpenVPNManagementServerTest, PerformAuthentication) {
  ExpectAuthenticationResponse();
  server_.PerformAuthentication("Auth");
}

TEST_F(OpenVPNManagementServerTest, ProcessHoldMessage) {
  EXPECT_FALSE(server_.hold_release_);
  EXPECT_FALSE(server_.hold_waiting_);

  EXPECT_FALSE(server_.ProcessHoldMessage("foo"));

  EXPECT_TRUE(server_.ProcessHoldMessage(">HOLD:Waiting for hold release"));
  EXPECT_FALSE(server_.hold_release_);
  EXPECT_TRUE(server_.hold_waiting_);

  ExpectHoldRelease();
  server_.hold_release_ = true;
  server_.hold_waiting_ = false;
  EXPECT_TRUE(server_.ProcessHoldMessage(">HOLD:Waiting for hold release"));
  EXPECT_TRUE(server_.hold_release_);
  EXPECT_FALSE(server_.hold_waiting_);
}

TEST_F(OpenVPNManagementServerTest, SupplyTPMTokenNoPin) {
  EXPECT_CALL(driver_, FailService(Service::kFailureInternal,
                                   Service::kErrorDetailsNone));
  server_.SupplyTPMToken("User-Specific TPM Token FOO");
}

TEST_F(OpenVPNManagementServerTest, SupplyTPMToken) {
  ExpectPinResponse();
  server_.SupplyTPMToken("User-Specific TPM Token FOO");
}

TEST_F(OpenVPNManagementServerTest, Send) {
  const char kMessage[] = "foo\n";
  SetConnectedSocket();
  ExpectSend(kMessage);
  server_.Send(kMessage);
}

TEST_F(OpenVPNManagementServerTest, SendState) {
  SetConnectedSocket();
  ExpectSend("state off\n");
  server_.SendState("off");
}

TEST_F(OpenVPNManagementServerTest, SendUsername) {
  SetConnectedSocket();
  ExpectSend("username \"Auth\" \"joesmith\"\n");
  server_.SendUsername("Auth", "joesmith");
}

TEST_F(OpenVPNManagementServerTest, SendUsernameWithSpecialCharacters) {
  SetConnectedSocket();
  // Verify that \ and " are escaped as \\ and \" in tag and username.
  ExpectSend("username \"\\\\ and \\\"\" \"joesmith with \\\" and \\\\\"\n");
  server_.SendUsername("\\ and \"", "joesmith with \" and \\");
}

TEST_F(OpenVPNManagementServerTest, SendPassword) {
  SetConnectedSocket();
  ExpectSend("password \"Auth\" \"foobar\"\n");
  server_.SendPassword("Auth", "foobar");
}

TEST_F(OpenVPNManagementServerTest, SendPasswordWithSpecialCharacters) {
  SetConnectedSocket();
  // Verify that \ and " are escaped as \\ and \" in tag and password.
  ExpectSend("password \"\\\\ and \\\"\" \"foobar with \\\" and \\\\\"\n");
  server_.SendPassword("\\ and \"", "foobar with \" and \\");
}

TEST_F(OpenVPNManagementServerTest, ProcessFailedPasswordMessage) {
  EXPECT_FALSE(server_.ProcessFailedPasswordMessage("foo"));
  EXPECT_CALL(driver_,
              FailService(Service::kFailureConnect, Service::kErrorDetailsNone))
      .Times(3);
  EXPECT_CALL(driver_, FailService(Service::kFailureConnect, Eq("Revoked.")));
  EXPECT_TRUE(
      server_.ProcessFailedPasswordMessage(">PASSWORD:Verification Failed: ."));
  EXPECT_TRUE(server_.ProcessFailedPasswordMessage(
      ">PASSWORD:Verification Failed: 'Private Key' ['Reason']"));
  EXPECT_TRUE(server_.ProcessFailedPasswordMessage(
      ">PASSWORD:Verification Failed: 'Auth'"));
  EXPECT_TRUE(server_.ProcessFailedPasswordMessage(
      ">PASSWORD:Verification Failed: 'Auth' ['Revoked.']"));
}

TEST_F(OpenVPNManagementServerTest, ProcessAuthTokenMessage) {
  EXPECT_FALSE(ProcessAuthTokenMessage("foo"));
  EXPECT_TRUE(ProcessAuthTokenMessage(">PASSWORD:Auth-Token:ToKeN=="));
}

TEST_F(OpenVPNManagementServerTest, SendSignal) {
  SetConnectedSocket();
  ExpectSend("signal SIGUSR2\n");
  SendSignal("SIGUSR2");
}

TEST_F(OpenVPNManagementServerTest, Restart) {
  ExpectRestart();
  server_.Restart();
}

TEST_F(OpenVPNManagementServerTest, SendHoldRelease) {
  ExpectHoldRelease();
  server_.SendHoldRelease();
}

TEST_F(OpenVPNManagementServerTest, Hold) {
  EXPECT_FALSE(server_.hold_release_);
  EXPECT_FALSE(server_.hold_waiting_);

  server_.ReleaseHold();
  EXPECT_TRUE(server_.hold_release_);
  EXPECT_FALSE(server_.hold_waiting_);

  server_.Hold();
  EXPECT_FALSE(server_.hold_release_);
  EXPECT_FALSE(server_.hold_waiting_);

  server_.hold_waiting_ = true;
  ExpectHoldRelease();
  server_.ReleaseHold();
  EXPECT_TRUE(server_.hold_release_);
  EXPECT_FALSE(server_.hold_waiting_);
}

TEST_F(OpenVPNManagementServerTest, EscapeToQuote) {
  EXPECT_EQ("", OpenVPNManagementServer::EscapeToQuote(""));
  EXPECT_EQ("foo './", OpenVPNManagementServer::EscapeToQuote("foo './"));
  EXPECT_EQ("\\\\", OpenVPNManagementServer::EscapeToQuote("\\"));
  EXPECT_EQ("\\\"", OpenVPNManagementServer::EscapeToQuote("\""));
  EXPECT_EQ("\\\\\\\"foo\\\\bar\\\"",
            OpenVPNManagementServer::EscapeToQuote("\\\"foo\\bar\""));
}

}  // namespace shill
