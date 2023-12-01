// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include <map>
#include <memory>
#include <optional>
#include <utility>

#include <base/test/task_environment.h>
#include <biod/mock_biod_metrics.h>
#include <biod/session_state_manager.h>
#include <dbus/login_manager/dbus-constants.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <dbus/object_path.h>
#include <dbus/scoped_dbus_error.h>

namespace biod {
namespace {

using testing::_;
using testing::ByMove;
using testing::DoAll;
using testing::Invoke;
using testing::Return;
using testing::SaveArg;

constexpr char kUsername[] = "user@user.com";
constexpr char kSanitizedUsername[] =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static_assert(sizeof(kSanitizedUsername) == 41);
constexpr char kExampleConnectionName[] = ":1.33";

MATCHER_P(IsMember, name, "") {
  if (arg->GetMember() != name) {
    *result_listener << "has member " << arg->GetMember();
    return false;
  }
  return true;
}

class MockSessionStateObserver : public SessionStateManagerInterface::Observer {
 public:
  MOCK_METHOD(void,
              OnUserLoggedIn,
              (const std::string& sanitized_username, bool is_new_login),
              (override));
  MOCK_METHOD(void, OnUserLoggedOut, (), (override));
};

class SessionStateManagerTest : public ::testing::Test {
 public:
  SessionStateManagerTest() {
    dbus::Bus::Options options;
    options.bus_type = dbus::Bus::SYSTEM;
    bus_ = new dbus::MockBus(options);

    proxy_ = new dbus::MockObjectProxy(
        bus_.get(), login_manager::kSessionManagerServiceName,
        dbus::ObjectPath(login_manager::kSessionManagerServicePath));

    EXPECT_CALL(*bus_,
                GetObjectProxy(login_manager::kSessionManagerServiceName, _))
        .WillRepeatedly(Return(proxy_.get()));

    EXPECT_CALL(*proxy_, DoConnectToSignal(
                             login_manager::kSessionManagerInterface, _, _, _))
        .WillRepeatedly(
            Invoke(this, &SessionStateManagerTest::ConnectToSignal));

    // Save NameOwnerChanged callback
    EXPECT_CALL(*proxy_, SetNameOwnerChangedCallback)
        .WillRepeatedly(SaveArg<0>(&on_name_owner_changed_));

    mock_metrics_ = std::make_unique<metrics::MockBiodMetrics>();

    manager_.emplace(bus_.get(), mock_metrics_.get());
  }

 protected:
  void EmitStateChangedSignal(const std::string& state);
  std::unique_ptr<dbus::Response> RetrievePrimarySessionResponse(
      const char* username, const char* sanitized_username);

  base::test::SingleThreadTaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  scoped_refptr<dbus::MockBus> bus_;
  scoped_refptr<dbus::MockObjectProxy> proxy_;
  dbus::MockObjectProxy::NameOwnerChangedCallback on_name_owner_changed_;
  MockSessionStateObserver observer_;
  std::unique_ptr<metrics::MockBiodMetrics> mock_metrics_;
  std::optional<SessionStateManager> manager_;

 private:
  void ConnectToSignal(
      const std::string& interface_name,
      const std::string& signal_name,
      dbus::ObjectProxy::SignalCallback signal_callback,
      dbus::ObjectProxy::OnConnectedCallback* on_connected_callback);

  std::map<std::string, dbus::ObjectProxy::SignalCallback> signal_callbacks_;
};

void SessionStateManagerTest::ConnectToSignal(
    const std::string& interface_name,
    const std::string& signal_name,
    dbus::ObjectProxy::SignalCallback signal_callback,
    dbus::ObjectProxy::OnConnectedCallback* on_connected_callback) {
  EXPECT_EQ(interface_name, login_manager::kSessionManagerInterface);
  signal_callbacks_[signal_name] = std::move(signal_callback);
  task_environment_.GetMainThreadTaskRunner()->PostTask(
      FROM_HERE,
      base::BindOnce(std::move(*on_connected_callback), interface_name,
                     signal_name, true /* success */));
}

void SessionStateManagerTest::EmitStateChangedSignal(const std::string& state) {
  const auto it =
      signal_callbacks_.find(login_manager::kSessionStateChangedSignal);
  ASSERT_TRUE(it != signal_callbacks_.end())
      << "Client didn't register for SessionStateChanged signal";

  dbus::Signal signal(login_manager::kSessionManagerInterface,
                      login_manager::kSessionStateChangedSignal);
  dbus::MessageWriter writer(&signal);
  writer.AppendString(state);

  it->second.Run(&signal);
}

std::unique_ptr<dbus::Response>
SessionStateManagerTest::RetrievePrimarySessionResponse(
    const char* username, const char* sanitized_username) {
  std::unique_ptr<dbus::Response> response(dbus::Response::CreateEmpty());
  dbus::MessageWriter writer(response.get());
  // Add username.
  writer.AppendString(username);
  // Add sanitized username.
  writer.AppendString(sanitized_username);

  return response;
}

// Tests that check biod behavior on SessionManager communication errors.
TEST_F(SessionStateManagerTest, TestPrimaryUserErrorNoReply) {
  EXPECT_CALL(
      *proxy_,
      CallMethodAndBlockWithErrorDetails(
          IsMember(login_manager::kSessionManagerRetrievePrimarySession), _, _))
      .WillOnce(
          [](dbus::MethodCall* method_call, int timeout_ms,
             dbus::ScopedDBusError* error) -> std::unique_ptr<dbus::Response> {
            dbus_set_error(error->get(), dbus_constants::kDBusErrorNoReply,
                           "Timeout");
            return nullptr;
          });

  EXPECT_CALL(*mock_metrics_,
              SendSessionRetrievePrimarySessionResult(
                  BiodMetrics::RetrievePrimarySessionResult::kErrorDBusNoReply))
      .Times(1);
  EXPECT_FALSE(manager_->RefreshPrimaryUser());
  EXPECT_TRUE(manager_->GetPrimaryUser().empty());
}

TEST_F(SessionStateManagerTest, TestPrimaryUserErrorServiceUnknown) {
  EXPECT_CALL(
      *proxy_,
      CallMethodAndBlockWithErrorDetails(
          IsMember(login_manager::kSessionManagerRetrievePrimarySession), _, _))
      .WillOnce(
          [](dbus::MethodCall* method_call, int timeout_ms,
             dbus::ScopedDBusError* error) -> std::unique_ptr<dbus::Response> {
            dbus_set_error(error->get(),
                           dbus_constants::kDBusErrorServiceUnknown,
                           "Service unknown");
            return nullptr;
          });

  EXPECT_CALL(
      *mock_metrics_,
      SendSessionRetrievePrimarySessionResult(
          BiodMetrics::RetrievePrimarySessionResult::kErrorDBusServiceUnknown))
      .Times(1);
  EXPECT_FALSE(manager_->RefreshPrimaryUser());
  EXPECT_TRUE(manager_->GetPrimaryUser().empty());
}

TEST_F(SessionStateManagerTest, TestPrimaryUserErrorOther) {
  EXPECT_CALL(
      *proxy_,
      CallMethodAndBlockWithErrorDetails(
          IsMember(login_manager::kSessionManagerRetrievePrimarySession), _, _))
      .WillOnce(
          [](dbus::MethodCall* method_call, int timeout_ms,
             dbus::ScopedDBusError* error) -> std::unique_ptr<dbus::Response> {
            dbus_set_error(error->get(), "TestError", "This is a test error");
            return nullptr;
          });

  EXPECT_CALL(*mock_metrics_,
              SendSessionRetrievePrimarySessionResult(
                  BiodMetrics::RetrievePrimarySessionResult::kErrorUnknown))
      .Times(1);
  EXPECT_FALSE(manager_->RefreshPrimaryUser());
  EXPECT_TRUE(manager_->GetPrimaryUser().empty());
}

// Tests that check invalid response from SessionManager.
TEST_F(SessionStateManagerTest, TestPrimaryUserNullResponse) {
  EXPECT_CALL(
      *proxy_,
      CallMethodAndBlockWithErrorDetails(
          IsMember(login_manager::kSessionManagerRetrievePrimarySession), _, _))
      .WillOnce(Return(ByMove(nullptr)));

  EXPECT_CALL(
      *mock_metrics_,
      SendSessionRetrievePrimarySessionResult(
          BiodMetrics::RetrievePrimarySessionResult::kErrorResponseMissing))
      .Times(1);
  EXPECT_FALSE(manager_->RefreshPrimaryUser());
  EXPECT_TRUE(manager_->GetPrimaryUser().empty());
}

TEST_F(SessionStateManagerTest, TestPrimaryUserNoDataInResponse) {
  // Prepare empty response.
  std::unique_ptr<dbus::Response> response(dbus::Response::CreateEmpty());

  EXPECT_CALL(
      *proxy_,
      CallMethodAndBlockWithErrorDetails(
          IsMember(login_manager::kSessionManagerRetrievePrimarySession), _, _))
      .WillOnce(Return(ByMove(std::move(response))));

  EXPECT_CALL(*mock_metrics_,
              SendSessionRetrievePrimarySessionResult(
                  BiodMetrics::RetrievePrimarySessionResult::kErrorParsing))
      .Times(1);
  EXPECT_FALSE(manager_->RefreshPrimaryUser());
  EXPECT_TRUE(manager_->GetPrimaryUser().empty());
}

TEST_F(SessionStateManagerTest, TestPrimaryUserNoSanitizedUsername) {
  // Prepare response with username only.
  std::unique_ptr<dbus::Response> response(dbus::Response::CreateEmpty());
  dbus::MessageWriter writer(response.get());
  // Add username.
  writer.AppendString("");

  EXPECT_CALL(
      *proxy_,
      CallMethodAndBlockWithErrorDetails(
          IsMember(login_manager::kSessionManagerRetrievePrimarySession), _, _))
      .WillOnce(Return(ByMove(std::move(response))));

  EXPECT_CALL(*mock_metrics_,
              SendSessionRetrievePrimarySessionResult(
                  BiodMetrics::RetrievePrimarySessionResult::kErrorParsing))
      .Times(1);
  EXPECT_FALSE(manager_->RefreshPrimaryUser());
  EXPECT_TRUE(manager_->GetPrimaryUser().empty());
}

TEST_F(SessionStateManagerTest, TestPrimaryUserUsernameNotString) {
  // Prepare response with an integer instead of username.
  std::unique_ptr<dbus::Response> response(dbus::Response::CreateEmpty());
  dbus::MessageWriter writer(response.get());
  // Add username, integer in this case.
  writer.AppendInt32(0);
  // Add sanitized username.
  writer.AppendString(kSanitizedUsername);

  EXPECT_CALL(
      *proxy_,
      CallMethodAndBlockWithErrorDetails(
          IsMember(login_manager::kSessionManagerRetrievePrimarySession), _, _))
      .WillOnce(Return(ByMove(std::move(response))));

  EXPECT_CALL(*mock_metrics_,
              SendSessionRetrievePrimarySessionResult(
                  BiodMetrics::RetrievePrimarySessionResult::kErrorParsing))
      .Times(1);
  EXPECT_FALSE(manager_->RefreshPrimaryUser());
  EXPECT_TRUE(manager_->GetPrimaryUser().empty());
}

TEST_F(SessionStateManagerTest, TestPrimaryUserSanitizedUsernameNotString) {
  // Prepare response with an integer instead of sanitized username..
  std::unique_ptr<dbus::Response> response(dbus::Response::CreateEmpty());
  dbus::MessageWriter writer(response.get());
  // Add username.
  writer.AppendString(kUsername);
  // Add sanitized username, integer in this case.
  writer.AppendInt32(0);

  EXPECT_CALL(
      *proxy_,
      CallMethodAndBlockWithErrorDetails(
          IsMember(login_manager::kSessionManagerRetrievePrimarySession), _, _))
      .WillOnce(Return(ByMove(std::move(response))));

  EXPECT_CALL(*mock_metrics_,
              SendSessionRetrievePrimarySessionResult(
                  BiodMetrics::RetrievePrimarySessionResult::kErrorParsing))
      .Times(1);
  EXPECT_FALSE(manager_->RefreshPrimaryUser());
  EXPECT_TRUE(manager_->GetPrimaryUser().empty());
}

TEST_F(SessionStateManagerTest, TestPrimaryUserNoSessionAvailable) {
  // Prepare response with no primary user.
  std::unique_ptr<dbus::Response> response =
      RetrievePrimarySessionResponse("", "");

  EXPECT_CALL(
      *proxy_,
      CallMethodAndBlockWithErrorDetails(
          IsMember(login_manager::kSessionManagerRetrievePrimarySession), _, _))
      .WillOnce(Return(ByMove(std::move(response))));

  EXPECT_CALL(*mock_metrics_,
              SendSessionRetrievePrimarySessionResult(
                  BiodMetrics::RetrievePrimarySessionResult::kSuccess))
      .Times(1);
  EXPECT_FALSE(manager_->RefreshPrimaryUser());
  EXPECT_TRUE(manager_->GetPrimaryUser().empty());
}

TEST_F(SessionStateManagerTest, TestPrimaryUserSuccess) {
  // Prepare response with information about primary user.
  std::unique_ptr<dbus::Response> response =
      RetrievePrimarySessionResponse(kUsername, kSanitizedUsername);

  // During first call to RefreshPrimaryUser() we expect to call
  // RetrievePrimarySession DBus method.
  EXPECT_CALL(
      *proxy_,
      CallMethodAndBlockWithErrorDetails(
          IsMember(login_manager::kSessionManagerRetrievePrimarySession), _, _))
      .WillOnce(Return(ByMove(std::move(response))));

  EXPECT_CALL(*mock_metrics_,
              SendSessionRetrievePrimarySessionResult(
                  BiodMetrics::RetrievePrimarySessionResult::kSuccess))
      .Times(1);
  EXPECT_TRUE(manager_->RefreshPrimaryUser());
  EXPECT_EQ(manager_->GetPrimaryUser(), kSanitizedUsername);
}

TEST_F(SessionStateManagerTest, TestRetrievePrimarySessionCallDuration) {
  ON_CALL(
      *proxy_,
      CallMethodAndBlockWithErrorDetails(
          IsMember(login_manager::kSessionManagerRetrievePrimarySession), _, _))
      .WillByDefault([this](dbus::MethodCall* method, int delay,
                            dbus::ScopedDBusError* error) {
        // Prepare response with information about primary user.
        std::unique_ptr<dbus::Response> response =
            RetrievePrimarySessionResponse(kUsername, kSanitizedUsername);

        task_environment_.FastForwardBy(base::Milliseconds(101));
        return response;
      });

  // Check that duration is greater or equal to 0.
  EXPECT_CALL(*mock_metrics_, SendSessionRetrievePrimarySessionDuration(101))
      .Times(1);
  EXPECT_TRUE(manager_->RefreshPrimaryUser());
}

TEST_F(SessionStateManagerTest, TestRefreshPrimarySessionNotifies) {
  manager_->AddObserver(&observer_);

  // Prepare response with information about primary user.
  std::unique_ptr<dbus::Response> response =
      RetrievePrimarySessionResponse(kUsername, kSanitizedUsername);

  // Prepare response with no primary user.
  std::unique_ptr<dbus::Response> response_no_user =
      RetrievePrimarySessionResponse("", "");

  // First call to RefreshPrimaryUser() will return information about logged
  // user, second call will return information that no one is logged in.
  EXPECT_CALL(
      *proxy_,
      CallMethodAndBlockWithErrorDetails(
          IsMember(login_manager::kSessionManagerRetrievePrimarySession), _, _))
      .WillOnce(Return(ByMove(std::move(response))))
      .WillOnce(Return(ByMove(std::move(response_no_user))));

  EXPECT_CALL(observer_, OnUserLoggedIn(kSanitizedUsername, false)).Times(1);
  EXPECT_TRUE(manager_->RefreshPrimaryUser());

  EXPECT_CALL(observer_, OnUserLoggedOut).Times(1);
  EXPECT_FALSE(manager_->RefreshPrimaryUser());
}

TEST_F(SessionStateManagerTest, TestRefreshPrimarySessionNoChangeLogin) {
  manager_->AddObserver(&observer_);

  // Prepare response with information about primary user.
  std::unique_ptr<dbus::Response> response1 =
      RetrievePrimarySessionResponse(kUsername, kSanitizedUsername);

  // Prepare response with information about primary user.
  std::unique_ptr<dbus::Response> response2 =
      RetrievePrimarySessionResponse(kUsername, kSanitizedUsername);

  // Both calls to RefreshPrimaryUser() will return information about logged
  // user.
  EXPECT_CALL(
      *proxy_,
      CallMethodAndBlockWithErrorDetails(
          IsMember(login_manager::kSessionManagerRetrievePrimarySession), _, _))
      .WillOnce(Return(ByMove(std::move(response1))))
      .WillOnce(Return(ByMove(std::move(response2))));

  EXPECT_CALL(observer_, OnUserLoggedIn(kSanitizedUsername, false)).Times(1);
  EXPECT_TRUE(manager_->RefreshPrimaryUser());

  // Expect we don't get notification.
  EXPECT_CALL(observer_, OnUserLoggedIn).Times(0);
  EXPECT_TRUE(manager_->RefreshPrimaryUser());
}

TEST_F(SessionStateManagerTest, TestRefreshPrimarySessionNoChangeLogout) {
  manager_->AddObserver(&observer_);

  // Prepare response with no primary user.
  std::unique_ptr<dbus::Response> response_no_user1 =
      RetrievePrimarySessionResponse("", "");

  // Prepare response with no primary user.
  std::unique_ptr<dbus::Response> response_no_user2 =
      RetrievePrimarySessionResponse("", "");

  // Both calls to RefreshPrimaryUser() will return information that no one
  // is logged in.
  EXPECT_CALL(
      *proxy_,
      CallMethodAndBlockWithErrorDetails(
          IsMember(login_manager::kSessionManagerRetrievePrimarySession), _, _))
      .WillOnce(Return(ByMove(std::move(response_no_user1))))
      .WillOnce(Return(ByMove(std::move(response_no_user2))));

  EXPECT_CALL(observer_, OnUserLoggedOut).Times(0);
  EXPECT_FALSE(manager_->RefreshPrimaryUser());
  EXPECT_FALSE(manager_->RefreshPrimaryUser());
}

TEST_F(SessionStateManagerTest, TestStateChangeStarted) {
  // Prepare response with information about primary user.
  std::unique_ptr<dbus::Response> response =
      RetrievePrimarySessionResponse(kUsername, kSanitizedUsername);

  // After first SessionStateChange signal we expect to call
  // RetrievePrimarySession DBus method.
  EXPECT_CALL(
      *proxy_,
      CallMethodAndBlockWithErrorDetails(
          IsMember(login_manager::kSessionManagerRetrievePrimarySession), _, _))
      .WillOnce(Return(ByMove(std::move(response))));

  manager_->AddObserver(&observer_);
  EXPECT_CALL(observer_, OnUserLoggedIn(kSanitizedUsername, true)).Times(1);

  EmitStateChangedSignal(dbus_constants::kSessionStateStarted);
  EXPECT_EQ(manager_->GetPrimaryUser(), kSanitizedUsername);

  // After second SessionStateChange signal we don't expect to call
  // RetrievePrimarySession DBus method.
  EXPECT_CALL(
      *proxy_,
      CallMethodAndBlockWithErrorDetails(
          IsMember(login_manager::kSessionManagerRetrievePrimarySession), _, _))
      .Times(0);
  EXPECT_CALL(observer_, OnUserLoggedIn).Times(0);

  EmitStateChangedSignal(dbus_constants::kSessionStateStarted);
  EXPECT_EQ(manager_->GetPrimaryUser(), kSanitizedUsername);
}

TEST_F(SessionStateManagerTest, TestStateChangeStopped) {
  manager_->AddObserver(&observer_);

  // Change state to stopped.`
  EXPECT_CALL(observer_, OnUserLoggedOut).Times(1);
  EmitStateChangedSignal(dbus_constants::kSessionStateStopped);
}

TEST_F(SessionStateManagerTest, TestStateChangeStartedStoppedStarted) {
  // Prepare response with information about primary user.
  std::unique_ptr<dbus::Response> response =
      RetrievePrimarySessionResponse(kUsername, kSanitizedUsername);

  manager_->AddObserver(&observer_);

  // After first SessionStateChange signal we expect to call
  // RetrievePrimarySession DBus method.
  EXPECT_CALL(
      *proxy_,
      CallMethodAndBlockWithErrorDetails(
          IsMember(login_manager::kSessionManagerRetrievePrimarySession), _, _))
      .WillOnce(Return(ByMove(std::move(response))));
  EXPECT_CALL(observer_, OnUserLoggedIn(kSanitizedUsername, true)).Times(1);

  EmitStateChangedSignal(dbus_constants::kSessionStateStarted);
  EXPECT_EQ(manager_->GetPrimaryUser(), kSanitizedUsername);

  // Change state to stopped.`
  EXPECT_CALL(observer_, OnUserLoggedOut).Times(1);
  EmitStateChangedSignal(dbus_constants::kSessionStateStopped);
  EXPECT_TRUE(manager_->GetPrimaryUser().empty());

  // Prepare response with information about primary user.
  std::unique_ptr<dbus::Response> response2 =
      RetrievePrimarySessionResponse(kUsername, kSanitizedUsername);

  // After third SessionStateChange signal we expect to call
  // RetrievePrimarySession DBus method.
  EXPECT_CALL(
      *proxy_,
      CallMethodAndBlockWithErrorDetails(
          IsMember(login_manager::kSessionManagerRetrievePrimarySession), _, _))
      .WillOnce(Return(ByMove(std::move(response2))));
  EXPECT_CALL(observer_, OnUserLoggedIn(kSanitizedUsername, true)).Times(1);

  EmitStateChangedSignal(dbus_constants::kSessionStateStarted);
  EXPECT_EQ(manager_->GetPrimaryUser(), kSanitizedUsername);
}

TEST_F(SessionStateManagerTest, TestStateChangeStartedNoUser) {
  // Prepare response with empty primary user.
  std::unique_ptr<dbus::Response> response =
      RetrievePrimarySessionResponse("", "");

  manager_->AddObserver(&observer_);

  // After first SessionStateChange signal we expect to call
  // RetrievePrimarySession DBus method, but OnUserLoggedIn method
  // shouldn't be called because there is no primary user.
  EXPECT_CALL(
      *proxy_,
      CallMethodAndBlockWithErrorDetails(
          IsMember(login_manager::kSessionManagerRetrievePrimarySession), _, _))
      .WillOnce(Return(ByMove(std::move(response))));
  EXPECT_CALL(observer_, OnUserLoggedIn).Times(0);

  EmitStateChangedSignal(dbus_constants::kSessionStateStarted);

  // Prepare response with information about primary user.
  std::unique_ptr<dbus::Response> response2 =
      RetrievePrimarySessionResponse(kUsername, kSanitizedUsername);

  // After second SessionStateChange signal we expect to call
  // RetrievePrimarySession DBus method.
  EXPECT_CALL(
      *proxy_,
      CallMethodAndBlockWithErrorDetails(
          IsMember(login_manager::kSessionManagerRetrievePrimarySession), _, _))
      .WillOnce(Return(ByMove(std::move(response2))));
  EXPECT_CALL(observer_, OnUserLoggedIn(kSanitizedUsername, true)).Times(1);

  EmitStateChangedSignal(dbus_constants::kSessionStateStarted);
}

TEST_F(SessionStateManagerTest, TestAddRemoveObserver) {
  manager_->AddObserver(&observer_);

  // Prepare response with information about primary user.
  std::unique_ptr<dbus::Response> response =
      RetrievePrimarySessionResponse(kUsername, kSanitizedUsername);
  std::unique_ptr<dbus::Response> response2 =
      RetrievePrimarySessionResponse(kUsername, kSanitizedUsername);

  // After SessionStateChange signal we expect OnUserLoggedIn to be called.
  EXPECT_CALL(
      *proxy_,
      CallMethodAndBlockWithErrorDetails(
          IsMember(login_manager::kSessionManagerRetrievePrimarySession), _, _))
      .WillOnce(Return(ByMove(std::move(response))))
      .WillOnce(Return(ByMove(std::move(response2))));
  EXPECT_CALL(observer_, OnUserLoggedIn).Times(1);
  manager_->RefreshPrimaryUser();

  // Remove observer.
  manager_->RemoveObserver(&observer_);
  // After SessionStateChange signal we expect that OnUserLoggedIn observer
  // method won't be called..
  EXPECT_CALL(observer_, OnUserLoggedIn).Times(0);
  manager_->RefreshPrimaryUser();
}

TEST_F(SessionStateManagerTest, TestOnNameOwnerChangedNewOwnerEmpty) {
  manager_->AddObserver(&observer_);

  // Prepare response with information about primary user.
  std::unique_ptr<dbus::Response> response =
      RetrievePrimarySessionResponse(kUsername, kSanitizedUsername);

  // Load primary user.
  EXPECT_CALL(
      *proxy_,
      CallMethodAndBlockWithErrorDetails(
          IsMember(login_manager::kSessionManagerRetrievePrimarySession), _, _))
      .WillOnce(Return(ByMove(std::move(response))));
  manager_->RefreshPrimaryUser();
  EXPECT_EQ(manager_->GetPrimaryUser(), kSanitizedUsername);

  // Expect that OnUserLoggedOut will be called when new name owner is empty.
  EXPECT_CALL(observer_, OnUserLoggedOut).Times(1);

  // Inform session manager that new owner is empty.
  const auto& old_owner = kExampleConnectionName;
  const auto& new_owner = "";
  on_name_owner_changed_.Run(old_owner, new_owner);
  EXPECT_TRUE(manager_->GetPrimaryUser().empty());
}

TEST_F(SessionStateManagerTest, TestOnNameOwnerChangedNewOwnerEmptyNoUser) {
  manager_->AddObserver(&observer_);

  // Expect that neither OnUserLoggedOut nor OnUserLoggedIn will be called when
  // new name owner is empty but user is not logged in.
  EXPECT_CALL(observer_, OnUserLoggedOut).Times(0);
  EXPECT_CALL(observer_, OnUserLoggedIn).Times(0);

  // Inform session manager that new owner is empty.
  const auto& old_owner = kExampleConnectionName;
  const auto& new_owner = "";
  on_name_owner_changed_.Run(old_owner, new_owner);
}

TEST_F(SessionStateManagerTest, TestOnNameOwnerChangedNewOwnerNotEmpty) {
  manager_->AddObserver(&observer_);

  // Expect that neither OnUserLoggedOut nor OnUserLoggedIn will be called when
  // new name owner is not empty.
  EXPECT_CALL(observer_, OnUserLoggedOut).Times(0);
  EXPECT_CALL(observer_, OnUserLoggedIn).Times(0);

  // Inform session manager that name has new owner.
  const auto& old_owner = "";
  const auto& new_owner = kExampleConnectionName;
  on_name_owner_changed_.Run(old_owner, new_owner);
}

}  // namespace
}  // namespace biod
