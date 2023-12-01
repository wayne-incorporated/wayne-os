// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/memory/weak_ptr.h>
#include <gtest/gtest.h>

#include "shill/error.h"
#include "shill/external_task.h"
#include "shill/ipconfig.h"
#include "shill/mock_control.h"
#include "shill/net/mock_process_manager.h"
#include "shill/ppp_daemon.h"
#include "shill/rpc_task.h"
#include "shill/service.h"

namespace shill {

using testing::_;
using testing::Invoke;
using testing::Return;
using testing::Test;
using testing::WithArg;

class PPPDaemonTest : public Test, public RpcTaskDelegate {
 public:
  PPPDaemonTest() : weak_ptr_factory_(this) {}
  PPPDaemonTest(const PPPDaemonTest&) = delete;
  PPPDaemonTest& operator=(const PPPDaemonTest&) = delete;

  ~PPPDaemonTest() override = default;

  std::unique_ptr<ExternalTask> Start(const PPPDaemon::Options& options,
                                      const std::string& device,
                                      Error* error) {
    PPPDaemon::DeathCallback callback(
        base::BindOnce(&PPPDaemonTest::DeathCallback, base::Unretained(this)));
    return PPPDaemon::Start(&control_, &process_manager_,
                            weak_ptr_factory_.GetWeakPtr(), options, device,
                            std::move(callback), error);
  }

  bool CaptureArgv(const std::vector<std::string>& argv) {
    argv_ = argv;
    return true;
  }

  MOCK_METHOD(void, GetLogin, (std::string*, std::string*), (override));
  MOCK_METHOD(void,
              Notify,
              (const std::string&, (const std::map<std::string, std::string>&)),
              (override));

 protected:
  MockControl control_;
  MockProcessManager process_manager_;

  std::vector<std::string> argv_;
  base::WeakPtrFactory<PPPDaemonTest> weak_ptr_factory_;

  MOCK_METHOD(void, DeathCallback, (pid_t, int));
};

TEST_F(PPPDaemonTest, PluginUsed) {
  EXPECT_CALL(process_manager_, StartProcess(_, _, _, _, _, _, _))
      .WillOnce(WithArg<2>(Invoke(this, &PPPDaemonTest::CaptureArgv)));

  Error error;
  PPPDaemon::Options options;
  std::unique_ptr<ExternalTask> task(Start(options, "eth0", &error));

  for (size_t i = 0; i < argv_.size(); ++i) {
    if (argv_[i] == "plugin") {
      EXPECT_EQ(argv_[i + 1], PPPDaemon::kShimPluginPath);
    }
  }
}

TEST_F(PPPDaemonTest, OptionsConverted) {
  EXPECT_CALL(process_manager_, StartProcess(_, _, _, _, _, _, _))
      .WillOnce(WithArg<2>(Invoke(this, &PPPDaemonTest::CaptureArgv)));

  PPPDaemon::Options options;
  options.no_detach = true;
  options.no_default_route = true;
  options.use_peer_dns = true;
  options.lcp_echo_interval = 1;
  options.lcp_echo_failure = 1;
  options.max_fail = 1;
  options.use_ipv6 = true;

  Error error;
  std::unique_ptr<ExternalTask> task(Start(options, "eth0", &error));

  std::set<std::string> expected_arguments = {
      "nodetach",         "nodefaultroute", "usepeerdns", "lcp-echo-interval",
      "lcp-echo-failure", "maxfail",        "+ipv6",      "ipv6cp-use-ipaddr",
  };
  for (const auto& argument : argv_) {
    expected_arguments.erase(argument);
  }
  EXPECT_TRUE(expected_arguments.empty());
}

TEST_F(PPPDaemonTest, ErrorPropagated) {
  EXPECT_CALL(process_manager_, StartProcess(_, _, _, _, _, _, _))
      .WillOnce(Return(-1));

  PPPDaemon::Options options;
  Error error;
  std::unique_ptr<ExternalTask> task(Start(options, "eth0", &error));

  EXPECT_NE(error.type(), Error::kSuccess);
  EXPECT_EQ(nullptr, task);
}

TEST_F(PPPDaemonTest, GetInterfaceName) {
  std::map<std::string, std::string> config;
  config[kPPPInterfaceName] = "ppp0";
  config["foo"] = "bar";
  EXPECT_EQ("ppp0", PPPDaemon::GetInterfaceName(config));
}

TEST_F(PPPDaemonTest, ParseIPConfiguration) {
  std::map<std::string, std::string> config;
  config[kPPPInternalIP4Address] = "4.5.6.7";
  config[kPPPExternalIP4Address] = "33.44.55.66";
  config[kPPPGatewayAddress] = "192.168.1.1";
  config[kPPPDNS1] = "1.1.1.1";
  config[kPPPDNS2] = "2.2.2.2";
  config[kPPPInterfaceName] = "ppp0";
  config[kPPPLNSAddress] = "99.88.77.66";
  config[kPPPMRU] = "1492";
  config["foo"] = "bar";  // Unrecognized keys don't cause crash.
  IPConfig::Properties props = PPPDaemon::ParseIPConfiguration(config);
  EXPECT_EQ(IPAddress::kFamilyIPv4, props.address_family);
  EXPECT_EQ(IPAddress::GetMaxPrefixLength(IPAddress::kFamilyIPv4),
            props.subnet_prefix);
  EXPECT_EQ("4.5.6.7", props.address);
  EXPECT_EQ("33.44.55.66", props.peer_address);
  EXPECT_EQ("192.168.1.1", props.gateway);
  ASSERT_EQ(2, props.dns_servers.size());
  EXPECT_EQ("1.1.1.1", props.dns_servers[0]);
  EXPECT_EQ("2.2.2.2", props.dns_servers[1]);
  EXPECT_EQ("99.88.77.66/32", props.exclusion_list[0]);
  EXPECT_EQ(1, props.exclusion_list.size());
  EXPECT_EQ(1492, props.mtu);

  // No gateway specified.
  config.erase(kPPPGatewayAddress);
  IPConfig::Properties props2 = PPPDaemon::ParseIPConfiguration(config);
  EXPECT_EQ("33.44.55.66", props2.gateway);
}

}  // namespace shill
