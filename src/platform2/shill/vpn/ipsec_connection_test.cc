// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/ipsec_connection.h"

#include <sys/socket.h>
#include <sys/un.h>

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/run_loop.h>
#include <base/strings/string_util.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/mock_control.h"
#include "shill/mock_device_info.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/net/mock_process_manager.h"
#include "shill/test_event_dispatcher.h"
#include "shill/vpn/fake_vpn_util.h"
#include "shill/vpn/vpn_connection_under_test.h"

namespace shill {

class IPsecConnectionUnderTest : public IPsecConnection {
 public:
  IPsecConnectionUnderTest(std::unique_ptr<Config> config,
                           std::unique_ptr<Callbacks> callbacks,
                           std::unique_ptr<VPNConnection> l2tp_connection,
                           DeviceInfo* device_info,
                           EventDispatcher* dispatcher,
                           ProcessManager* process_manager)
      : IPsecConnection(std::move(config),
                        std::move(callbacks),
                        std::move(l2tp_connection),
                        device_info,
                        dispatcher,
                        process_manager) {
    vpn_util_ = std::make_unique<FakeVPNUtil>();
  }

  IPsecConnectionUnderTest(const IPsecConnectionUnderTest&) = delete;
  IPsecConnectionUnderTest& operator=(const IPsecConnectionUnderTest&) = delete;

  base::FilePath SetTempDir() {
    CHECK(temp_dir_.CreateUniqueTempDir());
    return temp_dir_.GetPath();
  }

  void InvokeScheduleConnectTask(ConnectStep step) {
    IPsecConnection::ScheduleConnectTask(step);
  }

  void InvokeParseLocalVirtualIPs(
      const std::vector<std::string>& swanctl_output) {
    IPsecConnection::ParseLocalVirtualIPs(swanctl_output);
  }

  void InvokeClearVirtualIPs() { IPsecConnection::ClearVirtualIPs(); }

  void set_config(std::unique_ptr<Config> config) {
    config_ = std::move(config);
  }

  void set_strongswan_conf_path(const base::FilePath& path) {
    strongswan_conf_path_ = path;
  }

  void set_swanctl_conf_path(const base::FilePath& path) {
    swanctl_conf_path_ = path;
  }

  void set_charon_pid(pid_t pid) { charon_pid_ = pid; }

  void set_vici_socket_path(const base::FilePath& path) {
    vici_socket_path_ = path;
  }

  void set_state(State state) { state_ = state; }

  void set_l2tp_connection(std::unique_ptr<VPNConnection> l2tp_in) {
    l2tp_connection_ = std::move(l2tp_in);
  }

  const std::string& local_virtual_ipv4() const { return local_virtual_ipv4_; }

  const std::string& local_virtual_ipv6() const { return local_virtual_ipv6_; }

  std::vector<std::string> dns_servers() { return dns_servers_; }

  MOCK_METHOD(void, ScheduleConnectTask, (ConnectStep), (override));
};

namespace {

using ConnectStep = IPsecConnection::ConnectStep;

using testing::_;
using testing::AllOf;
using testing::DoAll;
using testing::Return;
using testing::WithArg;

constexpr char kExpectedStrongSwanConf[] = R"(charon {
  accept_unencrypted_mainmode_messages = yes
  ignore_routing_tables = 0
  install_routes = no
  install_virtual_ip = no
  routing_table = 0
  syslog {
    daemon {
      ike = 2
      cfg = 2
      knl = 2
    }
  }
  plugins {
    pkcs11 {
      modules {
        crypto_module {
          path = $1
        }
      }
    }
    resolve {
      file = $2
    }
  }
})";

// Expected contents of swanctl.conf in WriteSwanctlConfigL2TPIPsec test.
constexpr char kExpectedSwanctlConfL2TPIPsecPSK[] = R"(connections {
  vpn {
    local_addrs = "0.0.0.0/0,::/0"
    proposals = "aes128-sha256-modp3072,aes128-sha1-modp2048,3des-sha1-modp1536,3des-sha1-modp1024,default"
    remote_addrs = "10.0.0.1"
    version = "1"
    local-psk {
      auth = "psk"
    }
    remote-psk {
      auth = "psk"
    }
    local-xauth {
      auth = "xauth"
      xauth_id = "xauth_user"
    }
    children {
      managed {
        esp_proposals = "aes128gcm16,aes128-sha256,aes128-sha1,3des-sha1,3des-md5,default"
        local_ts = "dynamic[17/1701]"
        mode = "transport"
        remote_ts = "dynamic[17/1701]"
        set_mark_out = "0x500"
      }
    }
  }
}
secrets {
  ike-1 {
    secret = "this is psk"
  }
  xauth-1 {
    id = "xauth_user"
    secret = "xauth_password"
  }
})";

// Expected contents of swanctl.conf in WriteSwanctlConfigIKEv2 test.
constexpr char kExpectedSwanctlConfIKEv2EAP[] = R"(connections {
  vpn {
    if_id_in = "1"
    if_id_out = "1"
    local_addrs = "0.0.0.0/0,::/0"
    proposals = "aes128-aes192-aes256-camellia128-camellia192-camellia256-aesxcbc-aescmac-sha256-sha384-sha512-ecp256-ecp384-ecp521-ecp256bp-ecp384bp-ecp512bp-curve25519-curve448-modp3072-modp4096-modp6144-modp8192-modp2048,aes128gcm16-aes192gcm16-aes256gcm16-chacha20poly1305-aes128gcm12-aes192gcm12-aes256gcm12-aes128gcm8-aes192gcm8-aes256gcm8-prfsha256-prfsha384-prfsha512-prfaesxcbc-prfaescmac-ecp256-ecp384-ecp521-ecp256bp-ecp384bp-ecp512bp-curve25519-curve448-modp3072-modp4096-modp6144-modp8192-modp2048"
    remote_addrs = "10.0.0.1"
    version = "2"
    vips = "0.0.0.0,::"
    local-xauth {
      auth = "eap-mschapv2"
      eap_id = "xauth_user"
      id = "local_id"
    }
    children {
      managed {
        esp_proposals = "aes128gcm16-aes192gcm16-aes256gcm16,aes128-aes192-aes256-sha256-sha384-sha512-aesxcbc"
        local_ts = "dynamic"
        mode = "tunnel"
        remote_ts = "0.0.0.0/0,::/0"
        set_mark_out = "0x500"
      }
    }
  }
}
secrets {
  xauth-1 {
    id = "xauth_user"
    secret = "xauth_password"
  }
})";

// Output of `swanctl --list-sas` used in SwanctlListSAsL2TP test.
constexpr char kSwanctlListSAsL2TPOutput[] =
    R"(vpn: #1, ESTABLISHED, IKEv1, d182735e14966467_i* ff9e514adb77bea8_r
  local  'CN=10.1.1.10' @ 192.168.1.2[4500]
  remote '10.1.1.10' @ 1.2.3.4[4500]
  AES_CBC-128/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_3072
  established 186s ago, rekeying in 12983s
  managed: #1, reqid 1, INSTALLED, TRANSPORT-in-UDP, ESP:AES_CBC-128/HMAC_SHA2_256_128
    installed 186s ago, rekeying in 3144s, expires in 3775s
    in  cd474435,   7657 bytes,    83 packets,     0s ago
    out c16887e7, 141075 bytes,  1614 packets,     0s ago
    local  192.168.1.2/32[udp/l2tp]
    remote 1.2.3.4/32[udp/l2tp]
)";

constexpr char kSwanctlListSAsIKEv2Output[] =
    R"(vpn: #1, ESTABLISHED, IKEv2, f32cfa4a3b007894_i* 7cc2f86218f11619_r
  local  '192.168.1.2' @ 192.168.1.2[4500] [10.10.10.2 fec0::2]
  remote '192.168.1.3' @ 192.168.1.3[4500]
  AES_CBC-128/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_3072
  established 56s ago, rekeying in 14192s, reauth in 8601s
  managed: #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_CBC-128/HMAC_SHA2_256_128
    installed 56s ago, rekeying in 3266s, expires in 3904s
    in  c13d6df5 (-|0x00000001),  21701 bytes,    66 packets,     0s ago
    out c78f93a7 (-|0x00000001),  11293 bytes,    95 packets,     0s ago
    local  10.10.10.2/32
    remote 0.0.0.0/0)";

// Creates the UNIX socket at |path|, and listens on it if |start_listen| is
// true. Returns the fd of this socket.
base::ScopedFD CreateUnixSocketAt(const base::FilePath& path,
                                  bool start_listen) {
  base::ScopedFD fd(socket(AF_UNIX, SOCK_STREAM, 0));
  CHECK(fd.is_valid());
  struct sockaddr_un addr = {0};
  addr.sun_family = AF_UNIX;
  snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path.value().c_str());
  CHECK_EQ(bind(fd.get(), (struct sockaddr*)&addr, sizeof(addr)), 0);
  if (start_listen) {
    CHECK_EQ(listen(fd.get(), 1), 0);
  }
  return fd;
}

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

class IPsecConnectionTest : public testing::Test {
 public:
  IPsecConnectionTest()
      : manager_(&control_, &dispatcher_, &metrics_), device_info_(&manager_) {
    auto callbacks = std::make_unique<VPNConnection::Callbacks>(
        base::BindRepeating(&MockCallbacks::OnConnected,
                            base::Unretained(&callbacks_)),
        base::BindOnce(&MockCallbacks::OnFailure,
                       base::Unretained(&callbacks_)),
        base::BindOnce(&MockCallbacks::OnStopped,
                       base::Unretained(&callbacks_)));
    auto l2tp_tmp =
        std::make_unique<VPNConnectionUnderTest>(nullptr, &dispatcher_);
    l2tp_connection_ = l2tp_tmp.get();
    ipsec_connection_ = std::make_unique<IPsecConnectionUnderTest>(
        std::make_unique<IPsecConnection::Config>(), std::move(callbacks),
        std::move(l2tp_tmp), &device_info_, &dispatcher_, &process_manager_);
  }

 protected:
  void SetAsIKEv2Connection() {
    auto config = std::make_unique<IPsecConnection::Config>();
    config->ike_version = IPsecConnection::Config::IKEVersion::kV2;
    ipsec_connection_->set_config(std::move(config));
    ipsec_connection_->set_l2tp_connection(nullptr);
  }

  MockControl control_;
  EventDispatcherForTest dispatcher_;
  MockMetrics metrics_;
  MockManager manager_;

  MockCallbacks callbacks_;
  MockDeviceInfo device_info_;
  MockProcessManager process_manager_;

  std::unique_ptr<IPsecConnectionUnderTest> ipsec_connection_;
  VPNConnectionUnderTest* l2tp_connection_;  // owned by ipsec_connection_;
};

TEST_F(IPsecConnectionTest, WriteStrongSwanConfig) {
  base::FilePath temp_dir = ipsec_connection_->SetTempDir();

  // Signal should be send out at the end of the execution.
  EXPECT_CALL(*ipsec_connection_,
              ScheduleConnectTask(ConnectStep::kStrongSwanConfigWritten));

  ipsec_connection_->InvokeScheduleConnectTask(ConnectStep::kStart);

  // IPsecConnection should write the config to the `strongswan.conf` file under
  // the temp dir it created.
  base::FilePath expected_path = temp_dir.Append("strongswan.conf");
  ASSERT_TRUE(base::PathExists(expected_path));
  std::string actual_content;
  ASSERT_TRUE(base::ReadFileToString(expected_path, &actual_content));
  EXPECT_EQ(actual_content,
            base::ReplaceStringPlaceholders(
                kExpectedStrongSwanConf,
                {PKCS11_LIB, temp_dir.Append("resolv.conf").value()}, nullptr));

  // The file should be deleted after destroying the IPsecConnection object.
  ipsec_connection_ = nullptr;
  ASSERT_FALSE(base::PathExists(expected_path));
}

TEST_F(IPsecConnectionTest, StartCharon) {
  ipsec_connection_->set_state(VPNConnection::State::kConnecting);

  const base::FilePath kStrongSwanConfPath("/tmp/strongswan.conf");
  ipsec_connection_->set_strongswan_conf_path(kStrongSwanConfPath);

  // Prepares the file path under the scoped temp dir. The actual file will be
  // created later to simulate the case that it is created by the charon
  // process.
  const auto tmp_dir = ipsec_connection_->SetTempDir();
  const base::FilePath kViciSocketPath = tmp_dir.Append("charon.vici");
  ipsec_connection_->set_vici_socket_path(kViciSocketPath);

  // Expects call for starting charon process.
  const base::FilePath kExpectedProgramPath("/usr/libexec/ipsec/charon");
  const std::vector<std::string> kExpectedArgs = {};
  const std::map<std::string, std::string> kExpectedEnv = {
      {"STRONGSWAN_CONF", kStrongSwanConfPath.value()}};
  constexpr uint64_t kExpectedCapMask = CAP_TO_MASK(CAP_NET_ADMIN) |
                                        CAP_TO_MASK(CAP_NET_BIND_SERVICE) |
                                        CAP_TO_MASK(CAP_NET_RAW);
  EXPECT_CALL(process_manager_,
              StartProcessInMinijail(
                  _, kExpectedProgramPath, kExpectedArgs, kExpectedEnv,
                  AllOf(MinijailOptionsMatchUserGroup("vpn", "vpn"),
                        MinijailOptionsMatchCapMask(kExpectedCapMask),
                        MinijailOptionsMatchInheritSupplementaryGroup(true)),
                  _))
      .WillOnce(Return(123));

  // Triggers the task.
  ipsec_connection_->InvokeScheduleConnectTask(ConnectStep::kStartCharon);
  // Creates the socket file, and then IPsecConnection should be notified and
  // forward the step. We use a RunLoop here instead of RunUtilIdle() since it
  // cannot be guaranteed that FilePathWatcher posted the task before
  // RunUtilIdle() is called.
  base::ScopedFD vici_server_fd =
      CreateUnixSocketAt(kViciSocketPath, /*start_listen=*/true);
  base::RunLoop run_loop;
  EXPECT_CALL(*ipsec_connection_,
              ScheduleConnectTask(ConnectStep::kCharonStarted))
      .WillOnce([&](ConnectStep) { run_loop.Quit(); });
  run_loop.Run();
}

TEST_F(IPsecConnectionTest, StartCharonFailWithStartProcess) {
  ipsec_connection_->set_state(VPNConnection::State::kConnecting);

  EXPECT_CALL(process_manager_, StartProcessInMinijail(_, _, _, _, _, _))
      .WillOnce(Return(-1));
  ipsec_connection_->InvokeScheduleConnectTask(ConnectStep::kStartCharon);
  EXPECT_CALL(callbacks_, OnFailure(_));
  dispatcher_.task_environment().RunUntilIdle();
}

TEST_F(IPsecConnectionTest, StartCharonFailWithCharonExited) {
  ipsec_connection_->set_state(VPNConnection::State::kConnecting);

  base::OnceCallback<void(int)> exit_cb;
  EXPECT_CALL(process_manager_, StartProcessInMinijail(_, _, _, _, _, _))
      .WillOnce(
          WithArg<5>([&exit_cb](base::OnceCallback<void(int)> exit_callback) {
            exit_cb = std::move(exit_callback);
            return 123;
          }));
  ipsec_connection_->InvokeScheduleConnectTask(ConnectStep::kStartCharon);
  std::move(exit_cb).Run(1);

  EXPECT_CALL(callbacks_, OnFailure(_));
  dispatcher_.task_environment().RunUntilIdle();
}

TEST_F(IPsecConnectionTest, StartCharonFailWithSocketNotListening) {
  ipsec_connection_->set_state(VPNConnection::State::kConnecting);

  const auto tmp_dir = ipsec_connection_->SetTempDir();
  const base::FilePath kViciSocketPath = tmp_dir.Append("charon.vici");
  ipsec_connection_->set_vici_socket_path(kViciSocketPath);

  base::OnceCallback<void(int)> exit_cb;
  EXPECT_CALL(process_manager_, StartProcessInMinijail(_, _, _, _, _, _))
      .WillOnce(
          WithArg<5>([&exit_cb](base::OnceCallback<void(int)> exit_callback) {
            exit_cb = std::move(exit_callback);
            return 123;
          }));
  ipsec_connection_->InvokeScheduleConnectTask(ConnectStep::kStartCharon);
  base::ScopedFD vici_server_fd =
      CreateUnixSocketAt(kViciSocketPath, /*start_listen=*/false);
  base::RunLoop run_loop;
  EXPECT_CALL(callbacks_, OnFailure(_)).WillOnce([&](Service::ConnectFailure) {
    run_loop.Quit();
  });
  run_loop.Run();
}

TEST_F(IPsecConnectionTest, WriteSwanctlConfigL2TPIPsec) {
  base::FilePath temp_dir = ipsec_connection_->SetTempDir();

  // Creates a config with PSK. Cert will be covered by tast tests.
  auto config = std::make_unique<IPsecConnection::Config>();
  config->ike_version = IPsecConnection::Config::IKEVersion::kV1;
  config->remote = "10.0.0.1";
  config->local_proto_port = "17/1701";
  config->remote_proto_port = "17/1701";
  config->psk = "this is psk";
  config->xauth_user = "xauth_user";
  config->xauth_password = "xauth_password";
  ipsec_connection_->set_config(std::move(config));

  // Signal should be sent out at the end of the execution.
  EXPECT_CALL(*ipsec_connection_,
              ScheduleConnectTask(ConnectStep::kSwanctlConfigWritten));

  ipsec_connection_->InvokeScheduleConnectTask(ConnectStep::kCharonStarted);

  // IPsecConnection should write the config to the `swanctl.conf` file under
  // the temp dir it created.
  base::FilePath expected_path = temp_dir.Append("swanctl.conf");
  ASSERT_TRUE(base::PathExists(expected_path));
  std::string actual_content;
  ASSERT_TRUE(base::ReadFileToString(expected_path, &actual_content));
  EXPECT_EQ(actual_content, kExpectedSwanctlConfL2TPIPsecPSK);

  // The file should be deleted after destroying the IPsecConnection object.
  ipsec_connection_ = nullptr;
  ASSERT_FALSE(base::PathExists(expected_path));
}

TEST_F(IPsecConnectionTest, WriteSwanctlConfigIKEv2) {
  base::FilePath temp_dir = ipsec_connection_->SetTempDir();

  // Creates a config with PSK. Cert will be covered by tast tests.
  auto config = std::make_unique<IPsecConnection::Config>();
  config->ike_version = IPsecConnection::Config::IKEVersion::kV2;
  config->remote = "10.0.0.1";
  config->local_id = "local_id";
  config->xauth_user = "xauth_user";
  config->xauth_password = "xauth_password";
  ipsec_connection_->set_config(std::move(config));

  // Signal should be sent out at the end of the execution.
  EXPECT_CALL(*ipsec_connection_,
              ScheduleConnectTask(ConnectStep::kSwanctlConfigWritten));

  ipsec_connection_->InvokeScheduleConnectTask(ConnectStep::kCharonStarted);

  // IPsecConnection should write the config to the `swanctl.conf` file under
  // the temp dir it created.
  base::FilePath expected_path = temp_dir.Append("swanctl.conf");
  ASSERT_TRUE(base::PathExists(expected_path));
  std::string actual_content;
  ASSERT_TRUE(base::ReadFileToString(expected_path, &actual_content));
  EXPECT_EQ(actual_content, kExpectedSwanctlConfIKEv2EAP);

  // The file should be deleted after destroying the IPsecConnection object.
  ipsec_connection_ = nullptr;
  ASSERT_FALSE(base::PathExists(expected_path));
}

TEST_F(IPsecConnectionTest, SwanctlLoadConfig) {
  const base::FilePath kStrongSwanConfPath("/tmp/strongswan.conf");
  ipsec_connection_->set_strongswan_conf_path(kStrongSwanConfPath);

  const base::FilePath kSwanctlConfPath("/tmp/swanctl.conf");
  ipsec_connection_->set_swanctl_conf_path(kSwanctlConfPath);

  // Expects call for starting swanctl process.
  ProcessManager::ExitWithStdoutCallback exit_cb;
  const base::FilePath kExpectedProgramPath("/usr/sbin/swanctl");
  const std::vector<std::string> kExpectedArgs = {"--load-all", "--file",
                                                  kSwanctlConfPath.value()};
  const std::map<std::string, std::string> kExpectedEnv = {
      {"STRONGSWAN_CONF", kStrongSwanConfPath.value()}};
  constexpr uint64_t kExpectedCapMask = 0;
  EXPECT_CALL(process_manager_,
              StartProcessInMinijailWithStdout(
                  _, kExpectedProgramPath, kExpectedArgs, kExpectedEnv,
                  AllOf(MinijailOptionsMatchUserGroup("vpn", "vpn"),
                        MinijailOptionsMatchCapMask(kExpectedCapMask),
                        MinijailOptionsMatchInheritSupplementaryGroup(true)),
                  _))
      .WillOnce(WithArg<5>(
          [&exit_cb](ProcessManager::ExitWithStdoutCallback exit_callback) {
            exit_cb = std::move(exit_callback);
            return 123;
          }));

  ipsec_connection_->InvokeScheduleConnectTask(
      ConnectStep::kSwanctlConfigWritten);

  // Signal should be sent out if swanctl exits with 0.
  EXPECT_CALL(*ipsec_connection_,
              ScheduleConnectTask(ConnectStep::kSwanctlConfigLoaded));
  std::move(exit_cb).Run(0, "");
}

TEST_F(IPsecConnectionTest, SwanctlLoadConfigFailExecution) {
  ipsec_connection_->set_state(VPNConnection::State::kConnecting);

  EXPECT_CALL(process_manager_,
              StartProcessInMinijailWithStdout(_, _, _, _, _, _))
      .WillOnce(Return(-1));
  ipsec_connection_->InvokeScheduleConnectTask(
      ConnectStep::kSwanctlConfigWritten);

  EXPECT_CALL(callbacks_, OnFailure(_));
  dispatcher_.task_environment().RunUntilIdle();
}

TEST_F(IPsecConnectionTest, SwanctlLoadConfigFailExitCodeNonZero) {
  ipsec_connection_->set_state(VPNConnection::State::kConnecting);

  ProcessManager::ExitWithStdoutCallback exit_cb;
  EXPECT_CALL(process_manager_,
              StartProcessInMinijailWithStdout(_, _, _, _, _, _))
      .WillOnce(WithArg<5>(
          [&exit_cb](ProcessManager::ExitWithStdoutCallback exit_callback) {
            exit_cb = std::move(exit_callback);
            return 123;
          }));

  ipsec_connection_->InvokeScheduleConnectTask(
      ConnectStep::kSwanctlConfigWritten);

  std::move(exit_cb).Run(1, "");

  EXPECT_CALL(callbacks_, OnFailure(_));
  dispatcher_.task_environment().RunUntilIdle();
}

TEST_F(IPsecConnectionTest, SwanctlInitiateConnection) {
  const base::FilePath kStrongSwanConfPath("/tmp/strongswan.conf");
  ipsec_connection_->set_strongswan_conf_path(kStrongSwanConfPath);

  const base::FilePath kSwanctlConfPath("/tmp/swanctl.conf");
  ipsec_connection_->set_swanctl_conf_path(kSwanctlConfPath);

  // Expects call for starting swanctl process.
  ProcessManager::ExitWithStdoutCallback exit_cb;
  const base::FilePath kExpectedProgramPath("/usr/sbin/swanctl");
  const std::vector<std::string> kExpectedArgs = {"--initiate", "-c", "managed",
                                                  "--timeout", "30"};
  const std::map<std::string, std::string> kExpectedEnv = {
      {"STRONGSWAN_CONF", kStrongSwanConfPath.value()}};
  constexpr uint64_t kExpectedCapMask = 0;
  EXPECT_CALL(process_manager_,
              StartProcessInMinijailWithStdout(
                  _, kExpectedProgramPath, kExpectedArgs, kExpectedEnv,
                  AllOf(MinijailOptionsMatchUserGroup("vpn", "vpn"),
                        MinijailOptionsMatchCapMask(kExpectedCapMask),
                        MinijailOptionsMatchInheritSupplementaryGroup(true)),
                  _))
      .WillOnce(WithArg<5>(
          [&exit_cb](ProcessManager::ExitWithStdoutCallback exit_callback) {
            exit_cb = std::move(exit_callback);
            return 123;
          }));

  ipsec_connection_->InvokeScheduleConnectTask(
      ConnectStep::kSwanctlConfigLoaded);

  // Signal should be sent out if swanctl exits with 0.
  EXPECT_CALL(*ipsec_connection_,
              ScheduleConnectTask(ConnectStep::kIPsecConnected));
  std::move(exit_cb).Run(0, "");
}

TEST_F(IPsecConnectionTest, SwanctlListSAsL2TP) {
  const base::FilePath kStrongSwanConfPath("/tmp/strongswan.conf");
  ipsec_connection_->set_strongswan_conf_path(kStrongSwanConfPath);

  ProcessManager::ExitWithStdoutCallback exit_cb;
  const base::FilePath kExpectedProgramPath("/usr/sbin/swanctl");
  const std::vector<std::string> kExpectedArgs = {"--list-sas"};
  const std::map<std::string, std::string> kExpectedEnv = {
      {"STRONGSWAN_CONF", kStrongSwanConfPath.value()}};
  constexpr uint64_t kExpectedCapMask = 0;
  EXPECT_CALL(process_manager_,
              StartProcessInMinijailWithStdout(
                  _, kExpectedProgramPath, kExpectedArgs, kExpectedEnv,
                  AllOf(MinijailOptionsMatchUserGroup("vpn", "vpn"),
                        MinijailOptionsMatchCapMask(kExpectedCapMask),
                        MinijailOptionsMatchInheritSupplementaryGroup(true)),
                  _))
      .WillOnce(WithArg<5>(
          [&exit_cb](ProcessManager::ExitWithStdoutCallback exit_callback) {
            exit_cb = std::move(exit_callback);
            return 123;
          }));

  ipsec_connection_->InvokeScheduleConnectTask(ConnectStep::kIPsecConnected);

  // Signal should be sent out if swanctl exits with 0.
  EXPECT_CALL(*ipsec_connection_,
              ScheduleConnectTask(ConnectStep::kIPsecStatusRead));
  std::move(exit_cb).Run(0, kSwanctlListSAsL2TPOutput);

  // Checks the parsed cipher suites.
  EXPECT_EQ(ipsec_connection_->ike_encryption_algo(),
            Metrics::kVpnIpsecEncryptionAlgorithm_AES_CBC_128);
  EXPECT_EQ(ipsec_connection_->ike_integrity_algo(),
            Metrics::kVpnIpsecIntegrityAlgorithm_HMAC_SHA2_256_128);
  EXPECT_EQ(ipsec_connection_->ike_dh_group(),
            Metrics::kVpnIpsecDHGroup_MODP_3072);
  EXPECT_EQ(ipsec_connection_->esp_encryption_algo(),
            Metrics::kVpnIpsecEncryptionAlgorithm_AES_CBC_128);
  EXPECT_EQ(ipsec_connection_->esp_integrity_algo(),
            Metrics::kVpnIpsecIntegrityAlgorithm_HMAC_SHA2_256_128);
}

TEST_F(IPsecConnectionTest, SwanctlListSAsIKEv2) {
  SetAsIKEv2Connection();

  ProcessManager::ExitWithStdoutCallback exit_cb;
  EXPECT_CALL(process_manager_,
              StartProcessInMinijailWithStdout(_, _, _, _, _, _))
      .WillOnce(WithArg<5>(
          [&exit_cb](ProcessManager::ExitWithStdoutCallback exit_callback) {
            exit_cb = std::move(exit_callback);
            return 123;
          }));

  ipsec_connection_->InvokeScheduleConnectTask(ConnectStep::kIPsecConnected);
  EXPECT_CALL(*ipsec_connection_,
              ScheduleConnectTask(ConnectStep::kIPsecStatusRead));
  std::move(exit_cb).Run(0, kSwanctlListSAsIKEv2Output);

  // Checks the parsed virtual ip.
  EXPECT_EQ(ipsec_connection_->local_virtual_ipv4(), "10.10.10.2");
  EXPECT_EQ(ipsec_connection_->local_virtual_ipv6(), "fec0::2");

  // Checks the parsed cipher suites.
  EXPECT_EQ(ipsec_connection_->ike_encryption_algo(),
            Metrics::kVpnIpsecEncryptionAlgorithm_AES_CBC_128);
  EXPECT_EQ(ipsec_connection_->ike_integrity_algo(),
            Metrics::kVpnIpsecIntegrityAlgorithm_HMAC_SHA2_256_128);
  EXPECT_EQ(ipsec_connection_->ike_dh_group(),
            Metrics::kVpnIpsecDHGroup_MODP_3072);
  EXPECT_EQ(ipsec_connection_->esp_encryption_algo(),
            Metrics::kVpnIpsecEncryptionAlgorithm_AES_CBC_128);
  EXPECT_EQ(ipsec_connection_->esp_integrity_algo(),
            Metrics::kVpnIpsecIntegrityAlgorithm_HMAC_SHA2_256_128);
}

TEST_F(IPsecConnectionTest, SwanctlListSAsIKEv2ParseVIPFailed) {
  SetAsIKEv2Connection();
  ipsec_connection_->set_state(VPNConnection::State::kConnecting);

  ProcessManager::ExitWithStdoutCallback exit_cb;
  EXPECT_CALL(process_manager_,
              StartProcessInMinijailWithStdout(_, _, _, _, _, _))
      .WillOnce(WithArg<5>(
          [&exit_cb](ProcessManager::ExitWithStdoutCallback exit_callback) {
            exit_cb = std::move(exit_callback);
            return 123;
          }));

  ipsec_connection_->InvokeScheduleConnectTask(ConnectStep::kIPsecConnected);
  EXPECT_CALL(*ipsec_connection_,
              ScheduleConnectTask(ConnectStep::kIPsecStatusRead))
      .Times(0);
  std::move(exit_cb).Run(0, "");  // Passes an empty string.
  EXPECT_CALL(callbacks_, OnFailure(Service::kFailureInternal));
  dispatcher_.task_environment().RunUntilIdle();
}

TEST_F(IPsecConnectionTest, ParseLocalVirtualIP) {
  const std::string kTestLinePrefix =
      "local  '192.168.1.245' @ 192.168.1.245[4500] [";
  const std::string kTestLineSuffix = "]";
  const std::string kIPv4Address1 = "10.10.10.1";
  const std::string kIPv4Address2 = "10.10.10.2";
  const std::string kIPv6Address1 = "fec0::1";
  const std::string kIPv6Address2 = "fec0::2";
  const std::string kWrongIP = "10..10.10.1";
  const std::string kFirstLine = "";
  const std::string kBlank = " ";

  // The swanctl output includes an IPv4 address for the overlay IP.
  ipsec_connection_->InvokeParseLocalVirtualIPs(std::vector<std::string>{
      kFirstLine, kTestLinePrefix + kIPv4Address1 + kTestLineSuffix});
  ASSERT_EQ(kIPv4Address1, ipsec_connection_->local_virtual_ipv4());
  ASSERT_TRUE(ipsec_connection_->local_virtual_ipv6().empty());
  ipsec_connection_->InvokeClearVirtualIPs();

  // The swanctl output includes an IPv6 address for the overlay IP.
  ipsec_connection_->InvokeParseLocalVirtualIPs(std::vector<std::string>{
      kFirstLine, kTestLinePrefix + kIPv6Address1 + kTestLineSuffix});
  ASSERT_TRUE(ipsec_connection_->local_virtual_ipv4().empty());
  ASSERT_EQ(kIPv6Address1, ipsec_connection_->local_virtual_ipv6());
  ipsec_connection_->InvokeClearVirtualIPs();

  // The swanctl output includes a wrong IP
  // (this is unexpected because swanctl should return the error
  // for the wrong IP addresses in advance).
  ipsec_connection_->InvokeParseLocalVirtualIPs(std::vector<std::string>{
      kFirstLine, kTestLinePrefix + kWrongIP + kTestLineSuffix});
  ASSERT_TRUE(ipsec_connection_->local_virtual_ipv4().empty());
  ASSERT_TRUE(ipsec_connection_->local_virtual_ipv6().empty());
  ipsec_connection_->InvokeClearVirtualIPs();

  // The swanctl output includes an IPv4 address and an IPv6 address
  // for the overlay IP (dual stack case).
  ipsec_connection_->InvokeParseLocalVirtualIPs(std::vector<std::string>{
      kFirstLine, kTestLinePrefix + kIPv4Address1 + kBlank + kIPv6Address1 +
                      kTestLineSuffix});
  ASSERT_EQ(kIPv4Address1, ipsec_connection_->local_virtual_ipv4());
  ASSERT_EQ(kIPv6Address1, ipsec_connection_->local_virtual_ipv6());
  ipsec_connection_->InvokeClearVirtualIPs();

  // The swanctl output includes two IPv4 addresses
  // (this is unexpected because swanctl should select one IPv4 address
  // for the overlay IP before).
  ipsec_connection_->InvokeParseLocalVirtualIPs(std::vector<std::string>{
      kFirstLine, kTestLinePrefix + kIPv4Address1 + kBlank + kIPv4Address2 +
                      kTestLineSuffix});
  ASSERT_TRUE(ipsec_connection_->local_virtual_ipv4().empty());
  ASSERT_TRUE(ipsec_connection_->local_virtual_ipv6().empty());
  ipsec_connection_->InvokeClearVirtualIPs();

  // The swanctl output includes two IPv6 addresses
  // (this is unexpected because swanctl should select one IPv6 address
  // for the overlay IP in advance).
  ipsec_connection_->InvokeParseLocalVirtualIPs(std::vector<std::string>{
      kFirstLine, kTestLinePrefix + kIPv6Address1 + kBlank + kIPv6Address2 +
                      kTestLineSuffix});
  ASSERT_TRUE(ipsec_connection_->local_virtual_ipv4().empty());
  ASSERT_TRUE(ipsec_connection_->local_virtual_ipv6().empty());
  ipsec_connection_->InvokeClearVirtualIPs();

  // The swanctl output includes a wrong IP address and an IPv4 address
  // (this is unexpected because swanctl should return the error
  // for wrong IP addresses in advance).
  ipsec_connection_->InvokeParseLocalVirtualIPs(std::vector<std::string>{
      kFirstLine,
      kTestLinePrefix + kWrongIP + kBlank + kIPv4Address1 + kTestLineSuffix});
  ASSERT_TRUE(ipsec_connection_->local_virtual_ipv4().empty());
  ASSERT_TRUE(ipsec_connection_->local_virtual_ipv6().empty());
  ipsec_connection_->InvokeClearVirtualIPs();

  // The swanctl output includes an IPv4 address and a wrong IP address
  // (this is unexpected because swanctl should return the error
  // for wrong IP addresses in advance).
  ipsec_connection_->InvokeParseLocalVirtualIPs(std::vector<std::string>{
      kFirstLine,
      kTestLinePrefix + kIPv4Address1 + kBlank + kWrongIP + kTestLineSuffix});
  ASSERT_TRUE(ipsec_connection_->local_virtual_ipv4().empty());
  ASSERT_TRUE(ipsec_connection_->local_virtual_ipv6().empty());
  ipsec_connection_->InvokeClearVirtualIPs();

  // The swanctl output includes an IPv4 address and IPv6 address
  // without separator between them (this is unexpected because
  // swanctl should put a whitespace between them).
  ipsec_connection_->InvokeParseLocalVirtualIPs(std::vector<std::string>{
      kFirstLine,
      kTestLinePrefix + kIPv4Address1 + kIPv6Address1 + kTestLineSuffix});
  ASSERT_TRUE(ipsec_connection_->local_virtual_ipv4().empty());
  ASSERT_TRUE(ipsec_connection_->local_virtual_ipv6().empty());
  ipsec_connection_->InvokeClearVirtualIPs();

  // The swanctl output includes three IP addresses
  // (this is unexpected because swanctl should select one IPv4 address
  // and one IPv6 address at most).
  ipsec_connection_->InvokeParseLocalVirtualIPs(std::vector<std::string>{
      kFirstLine, kTestLinePrefix + kIPv4Address1 + kBlank + kIPv6Address1 +
                      kBlank + kIPv4Address2 + kTestLineSuffix});
  ASSERT_TRUE(ipsec_connection_->local_virtual_ipv4().empty());
  ASSERT_TRUE(ipsec_connection_->local_virtual_ipv6().empty());
  ipsec_connection_->InvokeClearVirtualIPs();
}

TEST_F(IPsecConnectionTest, StartL2TPLayerAndConnected) {
  ipsec_connection_->set_state(VPNConnection::State::kConnecting);
  // L2TP connect.
  ipsec_connection_->InvokeScheduleConnectTask(ConnectStep::kIPsecStatusRead);
  EXPECT_CALL(*l2tp_connection_, OnConnect());
  dispatcher_.task_environment().RunUntilIdle();

  // L2TP connected.
  const std::string kIfName = "ppp0";
  constexpr int kIfIndex = 123;
  std::unique_ptr<IPConfig::Properties> ipv4_properties;
  std::unique_ptr<IPConfig::Properties> ipv6_properties;
  l2tp_connection_->TriggerConnected(kIfName, kIfIndex,
                                     std::move(ipv4_properties),
                                     std::move(ipv6_properties));

  EXPECT_CALL(callbacks_, OnConnected(kIfName, kIfIndex, _, _));
  dispatcher_.task_environment().RunUntilIdle();
}

TEST_F(IPsecConnectionTest, OnL2TPFailure) {
  ipsec_connection_->set_state(VPNConnection::State::kConnected);
  l2tp_connection_->set_state(VPNConnection::State::kConnecting);
  l2tp_connection_->TriggerFailure(Service::kFailureInternal, "");

  EXPECT_CALL(callbacks_, OnFailure(Service::kFailureInternal));
  dispatcher_.task_environment().RunUntilIdle();
}

TEST_F(IPsecConnectionTest, OnL2TPStopped) {
  ipsec_connection_->set_state(VPNConnection::State::kDisconnecting);
  l2tp_connection_->set_state(VPNConnection::State::kDisconnecting);
  l2tp_connection_->TriggerStopped();

  // If charon is still running, it should be stopped.
  constexpr pid_t kCharonPid = 123;
  ipsec_connection_->set_charon_pid(kCharonPid);
  EXPECT_CALL(process_manager_, StopProcess(kCharonPid));

  EXPECT_CALL(callbacks_, OnStopped());
  dispatcher_.task_environment().RunUntilIdle();
}

TEST_F(IPsecConnectionTest, ParseDNSServers) {
  SetAsIKEv2Connection();
  ipsec_connection_->set_state(VPNConnection::State::kConnecting);

  // Simulates that charon creates the file.
  const auto tmp_dir = ipsec_connection_->SetTempDir();
  const base::FilePath kResolvConfPath = tmp_dir.Append("resolv.conf");
  CHECK(
      base::WriteFile(kResolvConfPath,
                      base::JoinString({"nameserver 1.2.3.4   # by strongSwan",
                                        "nameserver 1.2.3.5   # by strongSwan"},
                                       "\n")));
  EXPECT_CALL(device_info_, CreateXFRMInterface(_, _, _, _, _))
      .WillRepeatedly(Return(true));

  ipsec_connection_->InvokeScheduleConnectTask(ConnectStep::kIPsecStatusRead);
  const auto acutal_dns_servers = ipsec_connection_->dns_servers();
  EXPECT_EQ(acutal_dns_servers.size(), 2);
  EXPECT_EQ(acutal_dns_servers[0], "1.2.3.4");
  EXPECT_EQ(acutal_dns_servers[1], "1.2.3.5");
}

TEST_F(IPsecConnectionTest, ParseDNSServersEmptyFile) {
  SetAsIKEv2Connection();
  ipsec_connection_->set_state(VPNConnection::State::kConnecting);

  // Simulates that charon does not create the file.
  const auto tmp_dir = ipsec_connection_->SetTempDir();
  EXPECT_CALL(device_info_, CreateXFRMInterface(_, _, _, _, _))
      .WillRepeatedly(Return(true));

  ipsec_connection_->InvokeScheduleConnectTask(ConnectStep::kIPsecStatusRead);
  const auto acutal_dns_servers = ipsec_connection_->dns_servers();
  EXPECT_EQ(acutal_dns_servers.size(), 0);
}

TEST_F(IPsecConnectionTest, CreateXFRMInterfaceAndNotifyConnected) {
  SetAsIKEv2Connection();
  ipsec_connection_->SetTempDir();
  ipsec_connection_->set_state(VPNConnection::State::kConnecting);

  constexpr int kLoIndex = 10;
  constexpr int kIfIndex = 123;
  std::string actual_if_name;
  std::string actual_if_id;
  DeviceInfo::LinkReadyCallback registered_link_ready_cb;
  EXPECT_CALL(device_info_, GetIndex("lo")).WillOnce(Return(kLoIndex));
  EXPECT_CALL(device_info_, CreateXFRMInterface(_, kLoIndex, _, _, _))
      .WillOnce([&](const std::string& if_name, int, int if_id,
                    DeviceInfo::LinkReadyCallback link_ready_cb,
                    base::OnceClosure failure_cb) {
        actual_if_name = if_name;
        actual_if_id = if_id;
        registered_link_ready_cb = std::move(link_ready_cb);
        return true;
      });

  ipsec_connection_->InvokeScheduleConnectTask(ConnectStep::kIPsecStatusRead);

  std::move(registered_link_ready_cb).Run(actual_if_name, kIfIndex);
  EXPECT_CALL(callbacks_, OnConnected(actual_if_name, kIfIndex, _, _));
  dispatcher_.task_environment().RunUntilIdle();
}

TEST_F(IPsecConnectionTest, CreateXFRMInterfaceFailed) {
  SetAsIKEv2Connection();
  ipsec_connection_->SetTempDir();
  ipsec_connection_->set_state(VPNConnection::State::kConnecting);

  constexpr int kLoIndex = 10;
  base::OnceClosure registered_failure_cb;
  EXPECT_CALL(device_info_, GetIndex("lo")).WillOnce(Return(kLoIndex));
  EXPECT_CALL(device_info_, CreateXFRMInterface(_, kLoIndex, _, _, _))
      .WillOnce(
          [&registered_failure_cb](const std::string& if_name, int, int if_id,
                                   DeviceInfo::LinkReadyCallback link_ready_cb,
                                   base::OnceClosure failure_cb) {
            registered_failure_cb = std::move(failure_cb);
            return true;
          });

  ipsec_connection_->InvokeScheduleConnectTask(ConnectStep::kIPsecStatusRead);

  std::move(registered_failure_cb).Run();
  EXPECT_CALL(callbacks_, OnFailure(Service::kFailureInternal));
  dispatcher_.task_environment().RunUntilIdle();
}

TEST_F(IPsecConnectionTest, StartCharonWithPreviousPIDFile) {
  const base::FilePath kPIDPath("/run/ipsec/charon.pid");

  EXPECT_CALL(*ipsec_connection_,
              ScheduleConnectTask(ConnectStep::kStartCharon))
      .Times(0);
  EXPECT_CALL(process_manager_, IsTerminating(kPIDPath))
      .WillOnce(Return(true))
      .WillRepeatedly(Return(false));

  ipsec_connection_->InvokeScheduleConnectTask(
      ConnectStep::kStrongSwanConfigWritten);

  EXPECT_CALL(*ipsec_connection_,
              ScheduleConnectTask(ConnectStep::kStartCharon));
  dispatcher_.task_environment().FastForwardUntilNoTasksRemain();
}

}  // namespace
}  // namespace shill
