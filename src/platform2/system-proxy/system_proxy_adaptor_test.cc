// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "system-proxy/system_proxy_adaptor.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <list>
#include <map>
#include <utility>

#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/memory/weak_ptr.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_executor.h>
#include <brillo/dbus/async_event_sequencer.h>
#include <brillo/dbus/dbus_object.h>
#include <brillo/message_loops/base_message_loop.h>
#include <dbus/object_path.h>
#include <dbus/message.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_exported_object.h>
#include <dbus/mock_object_proxy.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/kerberos/dbus-constants.h>
#include <dbus/system_proxy/dbus-constants.h>

#include "bindings/worker_common.pb.h"
#include "system-proxy/kerberos_client.h"
#include "system_proxy/proto_bindings/system_proxy_service.pb.h"
#include "system-proxy/protobuf_util.h"
#include "system-proxy/sandboxed_worker.h"

using testing::_;
using testing::Return;

namespace system_proxy {
namespace {
const char kUser[] = "proxy_user";
const char kPassword[] = "proxy_password";
const char kPrincipalName[] = "user@TEST";
const char kLocalProxyHostPort[] = "local.proxy.url:3128";
const char kObjectPath[] = "/object/path";

// Stub completion callback for RegisterAsync().
void DoNothing(bool /* unused */) {}

}  // namespace

class FakeSandboxedWorker : public SandboxedWorker {
 public:
  explicit FakeSandboxedWorker(base::WeakPtr<SystemProxyAdaptor> adaptor)
      : SandboxedWorker(adaptor) {}
  FakeSandboxedWorker(const FakeSandboxedWorker&) = delete;
  FakeSandboxedWorker& operator=(const FakeSandboxedWorker&) = delete;
  ~FakeSandboxedWorker() override = default;

  bool Start() override { return is_running_ = true; }
  bool Stop() override {
    is_running_ = false;
    return true;
  }
  bool IsRunning() override { return is_running_; }

  std::string local_proxy_host_and_port() override {
    return kLocalProxyHostPort;
  }

 private:
  bool is_running_;
};

class FakeSystemProxyAdaptor : public SystemProxyAdaptor {
 public:
  FakeSystemProxyAdaptor(
      std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object)
      : SystemProxyAdaptor(std::move(dbus_object)), weak_ptr_factory_(this) {}
  FakeSystemProxyAdaptor(const FakeSystemProxyAdaptor&) = delete;
  FakeSystemProxyAdaptor& operator=(const FakeSystemProxyAdaptor&) = delete;
  ~FakeSystemProxyAdaptor() override = default;

 protected:
  std::unique_ptr<SandboxedWorker> CreateWorker() override {
    ++create_worker_count_;
    return std::make_unique<FakeSandboxedWorker>(
        weak_ptr_factory_.GetWeakPtr());
  }
  void ConnectNamespace(bool user_traffic) override {
    OnNamespaceConnected(GetWorker(user_traffic), user_traffic);
  }

 private:
  FRIEND_TEST(SystemProxyAdaptorTest, KerberosEnabled);
  FRIEND_TEST(SystemProxyAdaptorTest, ConnectNamespace);
  FRIEND_TEST(SystemProxyAdaptorTest, ProxyResolutionFilter);
  FRIEND_TEST(SystemProxyAdaptorTest, ProtectionSpaceAuthenticationRequired);
  FRIEND_TEST(SystemProxyAdaptorTest, ProtectionSpaceNoCredentials);
  FRIEND_TEST(SystemProxyAdaptorTest, ClearUserCredentials);
  FRIEND_TEST(SystemProxyAdaptorTest, ClearUserCredentialsRestartService);

  int create_worker_count_ = 0;
  base::WeakPtrFactory<FakeSystemProxyAdaptor> weak_ptr_factory_;
};

class SystemProxyAdaptorTest : public ::testing::Test {
 public:
  SystemProxyAdaptorTest() {
    const dbus::ObjectPath object_path(kObjectPath);

    // Mock out D-Bus initialization.
    mock_exported_object_ =
        base::MakeRefCounted<dbus::MockExportedObject>(bus_.get(), object_path);

    EXPECT_CALL(*bus_, GetExportedObject(_))
        .WillRepeatedly(Return(mock_exported_object_.get()));

    EXPECT_CALL(*mock_exported_object_, ExportMethod(_, _, _, _))
        .Times(testing::AnyNumber());

    mock_kerberos_proxy_ = base::MakeRefCounted<dbus::MockObjectProxy>(
        bus_.get(), kerberos::kKerberosServiceName,
        dbus::ObjectPath(kerberos::kKerberosServicePath));
    EXPECT_CALL(*bus_, GetObjectProxy(kerberos::kKerberosServiceName, _))
        .WillRepeatedly(Return(mock_kerberos_proxy_.get()));

    adaptor_.reset(new FakeSystemProxyAdaptor(
        std::make_unique<brillo::dbus_utils::DBusObject>(nullptr, bus_,
                                                         object_path)));
    adaptor_->RegisterAsync(base::BindRepeating(&DoNothing));
    mock_patchpanel_proxy_ = base::MakeRefCounted<dbus::MockObjectProxy>(
        bus_.get(), patchpanel::kPatchPanelServiceName,
        dbus::ObjectPath(patchpanel::kPatchPanelServicePath));
    brillo_loop_.SetAsCurrent();
  }
  SystemProxyAdaptorTest(const SystemProxyAdaptorTest&) = delete;
  SystemProxyAdaptorTest& operator=(const SystemProxyAdaptorTest&) = delete;
  ~SystemProxyAdaptorTest() override = default;

  void AddCredentialsToAuthCache(
      const worker::ProtectionSpace& protection_space,
      const std::string& username,
      const std::string& password) {
    Credentials credentials;
    credentials.set_username(username);
    credentials.set_password(password);
    mock_auth_cache_[protection_space.SerializeAsString()] = credentials;
  }

  void OnWorkerActive(dbus::Signal* signal) {
    EXPECT_EQ(signal->GetInterface(), "org.chromium.SystemProxy");
    EXPECT_EQ(signal->GetMember(), "WorkerActive");
    active_worker_signal_called_ = true;

    dbus::MessageReader signal_reader(signal);
    system_proxy::WorkerActiveSignalDetails details;
    EXPECT_TRUE(signal_reader.PopArrayOfBytesAsProto(&details));
    EXPECT_EQ(kLocalProxyHostPort, details.local_proxy_url());
  }

  void OnAuthenticationRequired(dbus::Signal* signal) {
    EXPECT_EQ(signal->GetInterface(), "org.chromium.SystemProxy");
    EXPECT_EQ(signal->GetMember(), "AuthenticationRequired");

    dbus::MessageReader signal_reader(signal);
    system_proxy::AuthenticationRequiredDetails details;
    EXPECT_TRUE(signal_reader.PopArrayOfBytesAsProto(&details));

    Credentials credentials;

    auto it = mock_auth_cache_.find(
        details.proxy_protection_space().SerializeAsString());

    if (it != mock_auth_cache_.end()) {
      credentials = it->second;
    } else {
      credentials.set_username("");
      credentials.set_password("");
    }

    SetAuthenticationDetailsRequest request;
    *request.mutable_credentials() = credentials;
    *request.mutable_protection_space() = details.proxy_protection_space();
    request.set_traffic_type(TrafficOrigin::SYSTEM);

    std::vector<uint8_t> proto_blob(request.ByteSizeLong());
    request.SerializeToArray(proto_blob.data(), proto_blob.size());

    adaptor_->SetAuthenticationDetails(proto_blob);
    ASSERT_TRUE(brillo_loop_.RunOnce(/*may_block=*/false));
  }

 protected:
  bool active_worker_signal_called_ = false;
  std::map<std::string, Credentials> mock_auth_cache_;
  scoped_refptr<dbus::MockBus> bus_ = new dbus::MockBus(dbus::Bus::Options());
  scoped_refptr<dbus::MockExportedObject> mock_exported_object_;
  // SystemProxyAdaptor instance that creates fake worker processes.
  std::unique_ptr<FakeSystemProxyAdaptor> adaptor_;

  scoped_refptr<dbus::MockObjectProxy> mock_patchpanel_proxy_;
  scoped_refptr<dbus::MockObjectProxy> mock_kerberos_proxy_;

  base::SingleThreadTaskExecutor task_executor_{base::MessagePumpType::IO};
  brillo::BaseMessageLoop brillo_loop_{task_executor_.task_runner()};
};

// Verifies if System-proxy starts the system and user traffic workers and sets
// the credentials for both workers.
TEST_F(SystemProxyAdaptorTest, SetAuthenticationDetails) {
  EXPECT_CALL(*bus_, GetObjectProxy(patchpanel::kPatchPanelServiceName, _))
      .Times(2)
      .WillRepeatedly(Return(mock_patchpanel_proxy_.get()));

  EXPECT_FALSE(adaptor_->system_services_worker_.get());
  SetAuthenticationDetailsRequest request;
  Credentials credentials;
  credentials.set_username(kUser);
  credentials.set_password(kPassword);
  credentials.add_policy_credentials_auth_schemes("basic");
  credentials.add_policy_credentials_auth_schemes("digest");

  *request.mutable_credentials() = credentials;
  request.set_traffic_type(TrafficOrigin::ALL);

  std::vector<uint8_t> proto_blob(request.ByteSizeLong());
  request.SerializeToArray(proto_blob.data(), proto_blob.size());

  // First create a worker object.
  adaptor_->SetAuthenticationDetails(proto_blob);
  ASSERT_TRUE(brillo_loop_.RunOnce(/*may_block=*/false));

  ASSERT_TRUE(adaptor_->system_services_worker_.get());
  EXPECT_TRUE(adaptor_->system_services_worker_->IsRunning());
  ASSERT_TRUE(adaptor_->arc_worker_.get());
  EXPECT_TRUE(adaptor_->arc_worker_->IsRunning());

  // Verify that credentials were set for user and system traffic.
  int fds_system[2], fds_user[2];
  EXPECT_TRUE(base::CreateLocalNonBlockingPipe(fds_system));
  base::ScopedFD read_scoped_fd_system(fds_system[0]);
  // Reset the worker stdin pipe to read the input from the other endpoint.
  adaptor_->system_services_worker_->stdin_pipe_.reset(fds_system[1]);
  EXPECT_TRUE(base::CreateLocalNonBlockingPipe(fds_user));
  base::ScopedFD read_scoped_fd_user(fds_user[0]);
  // Reset the worker stdin pipe to read the input from the other endpoint.
  adaptor_->arc_worker_->stdin_pipe_.reset(fds_user[1]);

  adaptor_->SetAuthenticationDetails(proto_blob);
  // Process the tasks which send credentials to both workers via communication
  // pipes.
  ASSERT_TRUE(brillo_loop_.RunOnce(/*may_block=*/false));
  ASSERT_TRUE(brillo_loop_.RunOnce(/*may_block=*/false));

  worker::WorkerConfigs config;
  ASSERT_TRUE(ReadProtobuf(read_scoped_fd_system.get(), &config));
  EXPECT_TRUE(config.has_credentials());
  EXPECT_EQ(config.credentials().username(), kUser);
  EXPECT_EQ(config.credentials().password(), kPassword);

  worker::WorkerConfigs config_user;
  ASSERT_TRUE(ReadProtobuf(read_scoped_fd_user.get(), &config_user));
  EXPECT_TRUE(config_user.has_credentials());
  EXPECT_EQ(config_user.credentials().username(), kUser);
  EXPECT_EQ(config_user.credentials().password(), kPassword);
  EXPECT_GT(credentials.policy_credentials_auth_schemes().size(), 0);
  EXPECT_EQ(credentials.policy_credentials_auth_schemes().Get(0), "basic");
  EXPECT_EQ(credentials.policy_credentials_auth_schemes().Get(1), "digest");
}

// Verifies if System-proxy only starts the worker which tunnels system traffic.
TEST_F(SystemProxyAdaptorTest, SetAuthenticationDetailsOnlySystemTraffic) {
  EXPECT_CALL(*bus_, GetObjectProxy(patchpanel::kPatchPanelServiceName, _))
      .WillOnce(Return(mock_patchpanel_proxy_.get()));

  EXPECT_FALSE(adaptor_->system_services_worker_.get());
  SetAuthenticationDetailsRequest request;
  Credentials credentials;
  credentials.set_username(kUser);
  credentials.set_password(kPassword);
  *request.mutable_credentials() = credentials;
  request.set_traffic_type(TrafficOrigin::SYSTEM);

  std::vector<uint8_t> proto_blob(request.ByteSizeLong());
  request.SerializeToArray(proto_blob.data(), proto_blob.size());

  adaptor_->SetAuthenticationDetails(proto_blob);
  ASSERT_TRUE(brillo_loop_.RunOnce(/*may_block=*/false));

  ASSERT_TRUE(adaptor_->system_services_worker_.get());
  EXPECT_TRUE(adaptor_->system_services_worker_->IsRunning());
  EXPECT_FALSE(adaptor_->arc_worker_);
}

TEST_F(SystemProxyAdaptorTest, KerberosEnabled) {
  adaptor_->system_services_worker_ = adaptor_->CreateWorker();
  ASSERT_TRUE(adaptor_->system_services_worker_.get());

  int fds[2];
  ASSERT_TRUE(base::CreateLocalNonBlockingPipe(fds));
  base::ScopedFD read_scoped_fd(fds[0]);
  // Reset the worker stdin pipe to read the input from the other endpoint.
  adaptor_->system_services_worker_->stdin_pipe_.reset(fds[1]);

  SetAuthenticationDetailsRequest request;
  request.set_kerberos_enabled(true);
  request.set_active_principal_name(kPrincipalName);
  request.set_traffic_type(TrafficOrigin::SYSTEM);

  std::vector<uint8_t> proto_blob(request.ByteSizeLong());
  request.SerializeToArray(proto_blob.data(), proto_blob.size());

  // First create a worker object.
  adaptor_->SetAuthenticationDetails(proto_blob);
  brillo_loop_.RunOnce(false);

  // Expect that the availability of kerberos auth has been sent to the worker.
  worker::WorkerConfigs config;
  ASSERT_TRUE(ReadProtobuf(read_scoped_fd.get(), &config));
  EXPECT_TRUE(config.has_kerberos_config());
  EXPECT_TRUE(config.kerberos_config().enabled());
  EXPECT_EQ(config.kerberos_config().krb5cc_path(), "/tmp/ccache");
  EXPECT_EQ(config.kerberos_config().krb5conf_path(), "/tmp/krb5.conf");

  // Expect that the availability of kerberos auth has been sent to the kerberos
  // client.
  EXPECT_TRUE(adaptor_->kerberos_client_->kerberos_enabled_);
  EXPECT_EQ(adaptor_->kerberos_client_->principal_name_, kPrincipalName);
}

TEST_F(SystemProxyAdaptorTest, ShutDownProcess) {
  EXPECT_CALL(*bus_, GetObjectProxy(patchpanel::kPatchPanelServiceName, _))
      .Times(2)
      .WillRepeatedly(Return(mock_patchpanel_proxy_.get()));
  adaptor_->CreateWorkerIfNeeded(/*user_traffic=*/false);
  adaptor_->CreateWorkerIfNeeded(/*user_traffic=*/true);
  EXPECT_TRUE(adaptor_->system_services_worker_);
  EXPECT_TRUE(adaptor_->arc_worker_);

  ShutDownRequest request;
  request.set_traffic_type(TrafficOrigin::ALL);
  std::vector<uint8_t> proto_blob(request.ByteSizeLong());
  request.SerializeToArray(proto_blob.data(), proto_blob.size());
  adaptor_->ShutDownProcess(proto_blob);

  EXPECT_FALSE(adaptor_->system_services_worker_);
  EXPECT_FALSE(adaptor_->arc_worker_);
}

// Verifies that only the worker that tunnels ARC traffic is shut down.
TEST_F(SystemProxyAdaptorTest, ShutDownArc) {
  EXPECT_CALL(*bus_, GetObjectProxy(patchpanel::kPatchPanelServiceName, _))
      .Times(2)
      .WillRepeatedly(Return(mock_patchpanel_proxy_.get()));
  adaptor_->CreateWorkerIfNeeded(/*user_traffic=*/false);
  adaptor_->CreateWorkerIfNeeded(/*user_traffic=*/true);
  EXPECT_TRUE(adaptor_->system_services_worker_);
  EXPECT_TRUE(adaptor_->arc_worker_);

  ShutDownRequest request;
  request.set_traffic_type(TrafficOrigin::USER);
  std::vector<uint8_t> proto_blob(request.ByteSizeLong());
  request.SerializeToArray(proto_blob.data(), proto_blob.size());
  adaptor_->ShutDownProcess(proto_blob);

  EXPECT_TRUE(adaptor_->system_services_worker_);
  EXPECT_FALSE(adaptor_->arc_worker_);
}

TEST_F(SystemProxyAdaptorTest, ConnectNamespace) {
  EXPECT_FALSE(active_worker_signal_called_);
  EXPECT_CALL(*mock_exported_object_, SendSignal(_))
      .WillOnce(Invoke(this, &SystemProxyAdaptorTest::OnWorkerActive));

  adaptor_->system_services_worker_ = adaptor_->CreateWorker();
  adaptor_->ConnectNamespace(/* user_traffic= */ false);
  EXPECT_TRUE(active_worker_signal_called_);
}

// Test that verifies that authentication requests are result in sending a
// signal to notify credentials are missing and credentials and protection space
// if correctly forwarded to the worker processes.
TEST_F(SystemProxyAdaptorTest, ProtectionSpaceAuthenticationRequired) {
  EXPECT_CALL(*mock_exported_object_, SendSignal(_))
      .WillOnce(
          Invoke(this, &SystemProxyAdaptorTest::OnAuthenticationRequired));

  worker::ProtectionSpace protection_space;
  protection_space.set_origin("http://test.proxy.com");
  protection_space.set_realm("my realm");
  protection_space.set_scheme("basic");
  std::string msg;
  protection_space.SerializeToString(&msg);
  AddCredentialsToAuthCache(protection_space, kUser, kPassword);

  adaptor_->system_services_worker_ = adaptor_->CreateWorker();
  int fds[2];
  ASSERT_TRUE(base::CreateLocalNonBlockingPipe(fds));
  base::ScopedFD read_scoped_fd(fds[0]);
  // Reset the worker stdin pipe to read the input from the other endpoint.
  adaptor_->system_services_worker_->stdin_pipe_.reset(fds[1]);
  adaptor_->RequestAuthenticationCredentials(protection_space,
                                             /* bad_credentials = */ false);

  brillo_loop_.RunOnce(false);

  worker::WorkerConfigs config;
  ASSERT_TRUE(ReadProtobuf(read_scoped_fd.get(), &config));
  EXPECT_TRUE(config.has_credentials());

  const worker::Credentials& reply = config.credentials();
  EXPECT_TRUE(reply.has_protection_space());
  EXPECT_EQ(reply.username(), kUser);
  EXPECT_EQ(reply.password(), kPassword);
  EXPECT_EQ(reply.protection_space().SerializeAsString(),
            protection_space.SerializeAsString());
}

// Test that verifies that authentication requests that resolve to an empty
// credentials set are forwarded to the worker processes.
TEST_F(SystemProxyAdaptorTest, ProtectionSpaceNoCredentials) {
  EXPECT_CALL(*mock_exported_object_, SendSignal(_))
      .WillOnce(
          Invoke(this, &SystemProxyAdaptorTest::OnAuthenticationRequired));

  worker::ProtectionSpace protection_space;
  protection_space.set_origin("http://test.proxy.com");
  protection_space.set_realm("my realm");
  protection_space.set_scheme("basic");
  std::string msg;
  protection_space.SerializeToString(&msg);

  adaptor_->system_services_worker_ = adaptor_->CreateWorker();
  int fds[2];
  ASSERT_TRUE(base::CreateLocalNonBlockingPipe(fds));
  base::ScopedFD read_scoped_fd(fds[0]);
  // Reset the worker stdin pipe to read the input from the other endpoint.
  adaptor_->system_services_worker_->stdin_pipe_.reset(fds[1]);
  adaptor_->RequestAuthenticationCredentials(protection_space,
                                             /* bad_credentials = */ false);

  brillo_loop_.RunOnce(false);

  worker::WorkerConfigs config;
  ASSERT_TRUE(ReadProtobuf(read_scoped_fd.get(), &config));
  EXPECT_TRUE(config.has_credentials());

  const worker::Credentials& reply = config.credentials();
  EXPECT_TRUE(reply.has_protection_space());
  EXPECT_EQ(reply.username(), "");
  EXPECT_EQ(reply.password(), "");
  EXPECT_EQ(reply.protection_space().SerializeAsString(),
            protection_space.SerializeAsString());
}

TEST_F(SystemProxyAdaptorTest, ClearUserCredentials) {
  adaptor_->system_services_worker_ = adaptor_->CreateWorker();
  ASSERT_TRUE(adaptor_->system_services_worker_.get());

  int fds[2];
  ASSERT_TRUE(base::CreateLocalNonBlockingPipe(fds));
  base::ScopedFD read_scoped_fd(fds[0]);
  // Reset the worker stdin pipe to read the input from the other endpoint.
  adaptor_->system_services_worker_->stdin_pipe_.reset(fds[1]);

  ClearUserCredentialsRequest request;
  std::vector<uint8_t> proto_blob(request.ByteSizeLong());
  request.SerializeToArray(proto_blob.data(), proto_blob.size());
  adaptor_->ClearUserCredentials(proto_blob);
  brillo_loop_.RunOnce(false);

  // Expect that a request to clear user credentials has been sent to the
  // worker.
  worker::WorkerConfigs config;
  ASSERT_TRUE(ReadProtobuf(read_scoped_fd.get(), &config));
  EXPECT_TRUE(config.has_clear_user_credentials());
}

// Tests that the sandboxed worker is restarted if the request to clear the
// credentials fails.
TEST_F(SystemProxyAdaptorTest, ClearUserCredentialsRestartService) {
  EXPECT_CALL(*bus_, GetObjectProxy(patchpanel::kPatchPanelServiceName, _))
      .WillOnce(Return(mock_patchpanel_proxy_.get()));

  adaptor_->system_services_worker_ = adaptor_->CreateWorker();
  ASSERT_TRUE(adaptor_->system_services_worker_.get());
  EXPECT_EQ(1, adaptor_->create_worker_count_);

  ClearUserCredentialsRequest request;
  std::vector<uint8_t> proto_blob(request.ByteSizeLong());
  request.SerializeToArray(proto_blob.data(), proto_blob.size());
  // This request will fail because we didn't set up a communication pipe.
  adaptor_->ClearUserCredentials(proto_blob);
  brillo_loop_.RunOnce(false);

  ASSERT_TRUE(adaptor_->system_services_worker_.get());
  EXPECT_EQ(2, adaptor_->create_worker_count_);
}

}  // namespace system_proxy
