// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/l2tp_connection.h"

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/strcat.h>
#include <base/run_loop.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libpasswordprovider/fake_password_provider.h>
#include <libpasswordprovider/password.h>

#include "shill/mock_control.h"
#include "shill/mock_device_info.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/net/mock_process_manager.h"
#include "shill/ppp_daemon.h"
#include "shill/rpc_task.h"
#include "shill/test_event_dispatcher.h"
#include "shill/vpn/fake_vpn_util.h"
#include "shill/vpn/vpn_connection_under_test.h"

namespace shill {

class L2TPConnectionUnderTest : public L2TPConnection {
 public:
  L2TPConnectionUnderTest(std::unique_ptr<Config> config,
                          std::unique_ptr<Callbacks> callbacks,
                          ControlInterface* control_interface,
                          DeviceInfo* device_info,
                          EventDispatcher* dispatcher,
                          ProcessManager* process_manager)
      : L2TPConnection(std::move(config),
                       std::move(callbacks),
                       control_interface,
                       device_info,
                       dispatcher,
                       process_manager) {
    vpn_util_ = std::make_unique<FakeVPNUtil>();
    password_provider_ =
        std::make_unique<password_provider::FakePasswordProvider>();
  }

  base::FilePath SetTempDir() {
    CHECK(temp_dir_.CreateUniqueTempDir());
    return temp_dir_.GetPath();
  }

  bool InvokeWritePPPDConfig() { return WritePPPDConfig(); }

  bool InvokeWriteL2TPDConfig() { return WriteL2TPDConfig(); }

  void InvokeStartXl2tpd() { StartXl2tpd(); }

  void InvokeGetLogin(std::string* user, std::string* password) {
    GetLogin(user, password);
  }

  void InvokeNotify(const std::string& reason,
                    const std::map<std::string, std::string> dict) {
    Notify(reason, dict);
  }

  void SetLoginPassword(const std::string& password_str) {
    int fds[2];
    base::CreateLocalNonBlockingPipe(fds);
    base::ScopedFD read_dbus_fd(fds[0]);
    base::ScopedFD write_scoped_fd(fds[1]);

    size_t data_size = password_str.length();
    base::WriteFileDescriptor(write_scoped_fd.get(), password_str);
    auto password = password_provider::Password::CreateFromFileDescriptor(
        read_dbus_fd.get(), data_size);
    ASSERT_TRUE(password);

    password_provider_->SavePassword(*password);
  }

  void set_config(std::unique_ptr<Config> config) {
    config_ = std::move(config);
  }

  void set_state(State state) { state_ = state; }
};

namespace {

using testing::_;
using testing::AllOf;
using testing::DoAll;
using testing::Return;
using testing::SaveArg;
using testing::WithArg;

// Expected contents in WritePPPDConfig test, missing the last line for plugin.
constexpr char kExpectedPPPDConf[] = R"(ipcp-accept-local
ipcp-accept-remote
refuse-eap
noccp
noauth
crtscts
mtu 1410
mru 1410
lock
connect-delay 5000
nodefaultroute
nosystemconfig
usepeerdns
lcp-echo-failure 4
lcp-echo-interval 30
logfd -1
)";

// The expected contents of l2tpd.conf excluding the line for "pppoptfile" which
// value is not fixed.
constexpr char kExpectedXl2tpdConf[] = R"([lac managed]
require chap = no
refuse pap = yes
require authentication = yes
length bit = yes
redial = yes
autodial = yes
lns = 1.2.3.4
name = test_user
bps = 1000000
redial timeout = 2
max redials = 30
)";

class MockCallbacks {
 public:
  MOCK_METHOD(void,
              OnConnected,
              (const std::string& link_name,
               int interface_index,
               std::unique_ptr<IPConfig::Properties> ipv4_properties,
               std::unique_ptr<IPConfig::Properties> ipv6_properties));
  MOCK_METHOD(void, OnFailure, (Service::ConnectFailure));
  MOCK_METHOD(void, OnStopped, ());
};

class L2TPConnectionTest : public testing::Test {
 public:
  L2TPConnectionTest()
      : manager_(&control_, &dispatcher_, &metrics_), device_info_(&manager_) {
    auto callbacks = std::make_unique<VPNConnection::Callbacks>(
        base::BindRepeating(&MockCallbacks::OnConnected,
                            base::Unretained(&callbacks_)),
        base::BindOnce(&MockCallbacks::OnFailure,
                       base::Unretained(&callbacks_)),
        base::BindOnce(&MockCallbacks::OnStopped,
                       base::Unretained(&callbacks_)));

    l2tp_connection_ = std::make_unique<L2TPConnectionUnderTest>(
        std::make_unique<L2TPConnection::Config>(), std::move(callbacks),
        &control_, &device_info_, &dispatcher_, &process_manager_);
  }

 protected:
  MockControl control_;
  EventDispatcherForTest dispatcher_;
  MockMetrics metrics_;
  MockManager manager_;
  MockDeviceInfo device_info_;
  MockProcessManager process_manager_;

  MockCallbacks callbacks_;
  std::unique_ptr<L2TPConnectionUnderTest> l2tp_connection_;
};

TEST_F(L2TPConnectionTest, WritePPPDConfig) {
  base::FilePath temp_dir = l2tp_connection_->SetTempDir();

  auto config = std::make_unique<L2TPConnection::Config>();
  config->lcp_echo = true;
  l2tp_connection_->set_config(std::move(config));

  EXPECT_TRUE(l2tp_connection_->InvokeWritePPPDConfig());

  // L2TPConnection should write the config to the `pppd.conf` file under
  // the temp dir it created.
  base::FilePath expected_path = temp_dir.Append("pppd.conf");
  ASSERT_TRUE(base::PathExists(expected_path));
  std::string actual_content;
  ASSERT_TRUE(base::ReadFileToString(expected_path, &actual_content));
  EXPECT_EQ(actual_content, base::StrCat({kExpectedPPPDConf, "plugin ",
                                          PPPDaemon::kShimPluginPath}));

  // The file should be deleted after destroying the L2TPConnection object.
  l2tp_connection_ = nullptr;
  ASSERT_FALSE(base::PathExists(expected_path));
}

TEST_F(L2TPConnectionTest, WriteXl2tpdConfig) {
  base::FilePath temp_dir = l2tp_connection_->SetTempDir();

  auto config = std::make_unique<L2TPConnection::Config>();
  config->remote_ip = "1.2.3.4";
  config->require_chap = false;
  config->refuse_pap = true;
  config->require_auth = true;
  config->length_bit = true;
  config->user = "test_user";
  l2tp_connection_->set_config(std::move(config));

  ASSERT_TRUE(l2tp_connection_->InvokeWritePPPDConfig());
  EXPECT_TRUE(l2tp_connection_->InvokeWriteL2TPDConfig());

  // L2TPConnection should write the config to the `l2tpd.conf` file under
  // the temp dir it created.
  base::FilePath expected_path = temp_dir.Append("l2tpd.conf");
  ASSERT_TRUE(base::PathExists(expected_path));
  std::string actual_content;
  ASSERT_TRUE(base::ReadFileToString(expected_path, &actual_content));
  const std::string kExpectedContents =
      base::StrCat({kExpectedXl2tpdConf,
                    "pppoptfile = ", temp_dir.Append("pppd.conf").value()});
  EXPECT_EQ(actual_content, kExpectedContents);

  // The file should be deleted after destroying the L2TPConnection object.
  l2tp_connection_ = nullptr;
  ASSERT_FALSE(base::PathExists(expected_path));
}

TEST_F(L2TPConnectionTest, StartXl2tpd) {
  l2tp_connection_->SetTempDir();

  std::map<std::string, std::string> actual_env;
  const base::FilePath kExpectedProgramPath("/usr/sbin/xl2tpd");
  constexpr uint64_t kExpectedCapMask = CAP_TO_MASK(CAP_NET_ADMIN);
  EXPECT_CALL(process_manager_,
              StartProcessInMinijail(
                  _, kExpectedProgramPath, _, _,
                  AllOf(MinijailOptionsMatchUserGroup("vpn", "vpn"),
                        MinijailOptionsMatchCapMask(kExpectedCapMask),
                        MinijailOptionsMatchInheritSupplementaryGroup(true)),
                  _))
      .WillOnce(WithArg<3>(
          [&actual_env](const std::map<std::string, std::string>& environment) {
            actual_env = environment;
            return 123;
          }));
  l2tp_connection_->InvokeStartXl2tpd();

  // Environment should contains variables needed by pppd.
  EXPECT_NE(actual_env.find(kRpcTaskServiceVariable), actual_env.end());
  EXPECT_NE(actual_env.find(kRpcTaskPathVariable), actual_env.end());
  EXPECT_NE(actual_env.find("LNS_ADDRESS"), actual_env.end());
}

TEST_F(L2TPConnectionTest, Xl2tpdExitedUnexpectedly) {
  l2tp_connection_->SetTempDir();
  l2tp_connection_->set_state(VPNConnection::State::kConnecting);

  base::OnceCallback<void(int)> exit_cb;
  EXPECT_CALL(process_manager_, StartProcessInMinijail(_, _, _, _, _, _))
      .WillOnce(
          WithArg<5>([&exit_cb](base::OnceCallback<void(int)> exit_callback) {
            exit_cb = std::move(exit_callback);
            return 123;
          }));

  l2tp_connection_->InvokeStartXl2tpd();

  std::move(exit_cb).Run(1);

  EXPECT_CALL(callbacks_, OnFailure(_));
  dispatcher_.task_environment().RunUntilIdle();
}

TEST_F(L2TPConnectionTest, Disconnect) {
  l2tp_connection_->SetTempDir();
  l2tp_connection_->set_state(VPNConnection::State::kConnected);

  // Just to make |external_task_| not empty.
  l2tp_connection_->InvokeStartXl2tpd();

  base::OnceCallback<void(int)> exit_cb;
  const base::FilePath kExpectedProgramPath("/usr/sbin/xl2tpd-control");
  constexpr uint64_t kExpectedCapMask = 0;
  EXPECT_CALL(process_manager_,
              StartProcessInMinijail(
                  _, kExpectedProgramPath, _, _,
                  AllOf(MinijailOptionsMatchUserGroup("vpn", "vpn"),
                        MinijailOptionsMatchCapMask(kExpectedCapMask)),
                  _))
      .WillOnce(
          WithArg<5>([&exit_cb](base::OnceCallback<void(int)> exit_callback) {
            exit_cb = std::move(exit_callback);
            return 123;
          }));

  l2tp_connection_->Disconnect();
  dispatcher_.task_environment().RunUntilIdle();
  ASSERT_TRUE(!exit_cb.is_null());
  std::move(exit_cb).Run(0);

  EXPECT_CALL(callbacks_, OnStopped());
  dispatcher_.task_environment().RunUntilIdle();
}

TEST_F(L2TPConnectionTest, PPPGetLogin) {
  constexpr char kUser[] = "user";
  constexpr char kPassword[] = "password";
  auto config = std::make_unique<L2TPConnection::Config>();
  config->user = kUser;
  config->password = kPassword;

  l2tp_connection_->set_config(std::move(config));

  std::string actual_user;
  std::string actual_password;
  l2tp_connection_->InvokeGetLogin(&actual_user, &actual_password);
  EXPECT_EQ(actual_user, kUser);
  EXPECT_EQ(actual_password, kPassword);
}

TEST_F(L2TPConnectionTest, PPPNotifyConnected) {
  l2tp_connection_->set_state(VPNConnection::State::kConnecting);

  constexpr char kIfName[] = "ppp0";
  constexpr int kIfIndex = 321;
  constexpr char kLocalIPAddress[] = "10.0.0.2";
  std::map<std::string, std::string> config{
      {kPPPInterfaceName, kIfName}, {kPPPInternalIP4Address, kLocalIPAddress}};

  // No callbacks should be invoked when authenticating.
  EXPECT_CALL(callbacks_, OnConnected(_, _, _, _)).Times(0);
  EXPECT_CALL(callbacks_, OnFailure(_)).Times(0);
  EXPECT_CALL(callbacks_, OnStopped()).Times(0);
  l2tp_connection_->InvokeNotify(kPPPReasonAuthenticating, config);
  l2tp_connection_->InvokeNotify(kPPPReasonAuthenticated, config);
  dispatcher_.task_environment().RunUntilIdle();

  // Expects OnConnected() when kPPPReasonConnect event comes.
  auto actual_ip_properties = std::make_unique<IPConfig::Properties>();
  EXPECT_CALL(callbacks_, OnConnected(kIfName, kIfIndex, _, _));
  EXPECT_CALL(device_info_, GetIndex(kIfName)).WillOnce(Return(kIfIndex));
  l2tp_connection_->InvokeNotify(kPPPReasonConnect, config);
  dispatcher_.task_environment().RunUntilIdle();
}

TEST_F(L2TPConnectionTest, PPPNotifyConnectedWithoutDeviceInfoReady) {
  l2tp_connection_->set_state(VPNConnection::State::kConnecting);

  constexpr char kIfName[] = "ppp0";
  constexpr int kIfIndex = 321;
  std::map<std::string, std::string> config{{kPPPInterfaceName, kIfName}};

  // The object should register the callback with DeviceInfo if the interface is
  // not known by shill now.
  DeviceInfo::LinkReadyCallback link_ready_cb;
  EXPECT_CALL(callbacks_, OnConnected(kIfName, kIfIndex, _, _)).Times(0);
  EXPECT_CALL(device_info_, GetIndex(kIfName)).WillOnce(Return(-1));
  EXPECT_CALL(device_info_, AddVirtualInterfaceReadyCallback(kIfName, _))
      .WillOnce([&](const std::string&, DeviceInfo::LinkReadyCallback cb) {
        link_ready_cb = std::move(cb);
      });
  l2tp_connection_->InvokeNotify(kPPPReasonConnect, config);
  dispatcher_.task_environment().RunUntilIdle();

  // Expects OnConnected() when the link is ready.
  std::move(link_ready_cb).Run(kIfName, kIfIndex);
  EXPECT_CALL(callbacks_, OnConnected(kIfName, kIfIndex, _, _));
  dispatcher_.task_environment().RunUntilIdle();
}

TEST_F(L2TPConnectionTest, PPPNotifyDisconnect) {
  l2tp_connection_->set_state(VPNConnection::State::kConnected);
  std::map<std::string, std::string> dict;
  // Nothing should happen on the disconnect event.
  EXPECT_CALL(callbacks_, OnFailure(_)).Times(0);
  l2tp_connection_->InvokeNotify(kPPPReasonDisconnect, dict);
  dispatcher_.task_environment().RunUntilIdle();
}

TEST_F(L2TPConnectionTest, PPPNotifyExit) {
  l2tp_connection_->set_state(VPNConnection::State::kConnected);
  std::map<std::string, std::string> dict;
  dict[kPPPExitStatus] = "19";
  EXPECT_CALL(callbacks_, OnFailure(Service::kFailurePPPAuth));
  l2tp_connection_->InvokeNotify(kPPPReasonExit, dict);
  dispatcher_.task_environment().RunUntilIdle();

  // The signal shouldn't be sent out twice if the event comes again.
  l2tp_connection_->InvokeNotify(kPPPReasonExit, dict);
  dispatcher_.task_environment().RunUntilIdle();
}

TEST_F(L2TPConnectionTest, UseLoginPassword) {
  base::FilePath temp_dir = l2tp_connection_->SetTempDir();

  const std::string kUser = "test_user";
  const std::string kPassword = "random_password";

  auto config = std::make_unique<L2TPConnection::Config>();
  config->user = kUser;
  config->use_login_password = true;
  l2tp_connection_->SetLoginPassword(kPassword);
  l2tp_connection_->set_config(std::move(config));

  ASSERT_TRUE(l2tp_connection_->InvokeWritePPPDConfig());
  ASSERT_TRUE(l2tp_connection_->InvokeWriteL2TPDConfig());

  // The generated config file should contain "refuse pap = yes".
  base::FilePath expected_path = temp_dir.Append("l2tpd.conf");
  std::string actual_content;
  ASSERT_TRUE(base::ReadFileToString(expected_path, &actual_content));
  EXPECT_NE(actual_content.find("refuse pap = yes"), std::string::npos);

  std::string actual_user;
  std::string actual_password;
  l2tp_connection_->InvokeGetLogin(&actual_user, &actual_password);
  EXPECT_EQ(actual_user, kUser);
  EXPECT_EQ(actual_password, kPassword);
}

}  // namespace
}  // namespace shill
