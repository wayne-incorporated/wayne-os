// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/firewall.h"

#include <string>
#include <vector>

#include <base/strings/string_split.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "patchpanel/iptables.h"
#include "patchpanel/minijailed_process_runner.h"

using testing::_;
using testing::DoAll;
using testing::ElementsAreArray;
using testing::Mock;
using testing::Return;
using testing::SaveArg;
using testing::StrEq;

namespace patchpanel {
namespace {

std::vector<std::string> SplitArgs(const std::string& args) {
  return base::SplitString(args, " ", base::WhitespaceHandling::TRIM_WHITESPACE,
                           base::SplitResult::SPLIT_WANT_NONEMPTY);
}

class MockProcessRunner : public MinijailedProcessRunner {
 public:
  MockProcessRunner() = default;
  ~MockProcessRunner() = default;

  MOCK_METHOD5(iptables,
               int(Iptables::Table table,
                   Iptables::Command command,
                   const std::vector<std::string>& argv,
                   bool log_failures,
                   std::string* output));
  MOCK_METHOD5(ip6tables,
               int(Iptables::Table table,
                   Iptables::Command command,
                   const std::vector<std::string>& argv,
                   bool log_failures,
                   std::string* output));
};

void Verify_iptables(MockProcessRunner& runner,
                     const std::string& args,
                     int return_value = 0) {
  auto argv = SplitArgs(args);
  const auto table = Iptables::TableFromName(argv[0]);
  const auto command = Iptables::CommandFromName(argv[1]);
  argv.erase(argv.begin());
  argv.erase(argv.begin());
  ASSERT_TRUE(table.has_value())
      << "incorrect table name in expected args: " << args;
  ASSERT_TRUE(command.has_value())
      << "incorrect command name in expected args: " << args;
  EXPECT_CALL(runner,
              iptables(*table, *command, ElementsAreArray(argv), _, nullptr))
      .WillOnce(Return(return_value));
}

void Verify_ip6tables(MockProcessRunner& runner,
                      const std::string& args,
                      int return_value = 0) {
  auto argv = SplitArgs(args);
  const auto table = Iptables::TableFromName(argv[0]);
  const auto command = Iptables::CommandFromName(argv[1]);
  argv.erase(argv.begin());
  argv.erase(argv.begin());
  ASSERT_TRUE(table.has_value())
      << "incorrect table name in expected args: " << args;
  ASSERT_TRUE(command.has_value())
      << "incorrect command name in expected args: " << args;
  EXPECT_CALL(runner,
              ip6tables(*table, *command, ElementsAreArray(argv), _, nullptr))
      .WillOnce(Return(return_value));
}
}  // namespace

TEST(FirewallTest, AddAcceptRules_InvalidPorts) {
  auto runner = new MockProcessRunner();
  Firewall firewall(runner);

  EXPECT_CALL(*runner, iptables(_, _, _, _, _)).Times(0);
  EXPECT_CALL(*runner, ip6tables(_, _, _, _, _)).Times(0);

  EXPECT_FALSE(firewall.AddAcceptRules(ModifyPortRuleRequest::TCP, 0, "iface"));
  EXPECT_FALSE(firewall.AddAcceptRules(ModifyPortRuleRequest::UDP, 0, "iface"));
  EXPECT_FALSE(
      firewall.DeleteAcceptRules(ModifyPortRuleRequest::TCP, 0, "iface"));
  EXPECT_FALSE(
      firewall.DeleteAcceptRules(ModifyPortRuleRequest::UDP, 0, "iface"));
}

TEST(FirewallTest, AddAcceptRules_ValidInterfaceName) {
  auto runner = new MockProcessRunner();
  Firewall firewall(runner);

  Verify_iptables(*runner,
                  "filter -I ingress_port_firewall -p tcp --dport 80 -i "
                  "shortname -j ACCEPT -w");
  Verify_ip6tables(*runner,
                   "filter -I ingress_port_firewall -p tcp --dport 80 -i "
                   "shortname -j ACCEPT -w");
  EXPECT_TRUE(
      firewall.AddAcceptRules(ModifyPortRuleRequest::TCP, 80, "shortname"));
  Mock::VerifyAndClearExpectations(runner);

  Verify_iptables(*runner,
                  "filter -I ingress_port_firewall -p udp --dport 53 -i "
                  "shortname -j ACCEPT -w");
  Verify_ip6tables(*runner,
                   "filter -I ingress_port_firewall -p udp --dport 53 -i "
                   "shortname -j ACCEPT -w");
  EXPECT_TRUE(
      firewall.AddAcceptRules(ModifyPortRuleRequest::UDP, 53, "shortname"));
  Mock::VerifyAndClearExpectations(runner);

  Verify_iptables(*runner,
                  "filter -I ingress_port_firewall -p tcp --dport 80 -i "
                  "middle-dash -j ACCEPT -w");
  Verify_ip6tables(*runner,
                   "filter -I ingress_port_firewall -p tcp --dport 80 -i "
                   "middle-dash -j ACCEPT -w");
  EXPECT_TRUE(
      firewall.AddAcceptRules(ModifyPortRuleRequest::TCP, 80, "middle-dash"));
  Mock::VerifyAndClearExpectations(runner);

  Verify_iptables(*runner,
                  "filter -I ingress_port_firewall -p udp --dport 53 -i "
                  "middle-dash -j ACCEPT -w");
  Verify_ip6tables(*runner,
                   "filter -I ingress_port_firewall -p udp --dport 53 -i "
                   "middle-dash -j ACCEPT -w");
  EXPECT_TRUE(
      firewall.AddAcceptRules(ModifyPortRuleRequest::UDP, 53, "middle-dash"));
  Mock::VerifyAndClearExpectations(runner);

  Verify_iptables(*runner,
                  "filter -I ingress_port_firewall -p tcp --dport 80 -i "
                  "middle.dot -j ACCEPT -w");
  Verify_ip6tables(*runner,
                   "filter -I ingress_port_firewall -p tcp --dport 80 -i "
                   "middle.dot -j ACCEPT -w");
  EXPECT_TRUE(
      firewall.AddAcceptRules(ModifyPortRuleRequest::TCP, 80, "middle.dot"));
  Mock::VerifyAndClearExpectations(runner);

  Verify_iptables(*runner,
                  "filter -I ingress_port_firewall -p udp --dport 53 -i "
                  "middle.dot -j ACCEPT -w");
  Verify_ip6tables(*runner,
                   "filter -I ingress_port_firewall -p udp --dport 53 -i "
                   "middle.dot -j ACCEPT -w");
  EXPECT_TRUE(
      firewall.AddAcceptRules(ModifyPortRuleRequest::UDP, 53, "middle.dot"));
  Mock::VerifyAndClearExpectations(runner);
}

TEST(FirewallTest, AddAcceptRules_InvalidInterfaceName) {
  auto runner = new MockProcessRunner();
  Firewall firewall(runner);

  EXPECT_CALL(*runner, iptables(_, _, _, _, _)).Times(0);
  EXPECT_CALL(*runner, ip6tables(_, _, _, _, _)).Times(0);

  EXPECT_FALSE(firewall.AddAcceptRules(ModifyPortRuleRequest::TCP, 80,
                                       "reallylonginterfacename"));
  EXPECT_FALSE(
      firewall.AddAcceptRules(ModifyPortRuleRequest::TCP, 80, "with spaces"));
  EXPECT_FALSE(
      firewall.AddAcceptRules(ModifyPortRuleRequest::TCP, 80, "with$ymbols"));
  EXPECT_FALSE(
      firewall.AddAcceptRules(ModifyPortRuleRequest::TCP, 80, "-startdash"));
  EXPECT_FALSE(
      firewall.AddAcceptRules(ModifyPortRuleRequest::TCP, 80, "enddash-"));
  EXPECT_FALSE(
      firewall.AddAcceptRules(ModifyPortRuleRequest::TCP, 80, ".startdot"));
  EXPECT_FALSE(
      firewall.AddAcceptRules(ModifyPortRuleRequest::TCP, 80, "enddot."));

  EXPECT_FALSE(firewall.AddAcceptRules(ModifyPortRuleRequest::UDP, 53,
                                       "reallylonginterfacename"));
  EXPECT_FALSE(
      firewall.AddAcceptRules(ModifyPortRuleRequest::UDP, 53, "with spaces"));
  EXPECT_FALSE(
      firewall.AddAcceptRules(ModifyPortRuleRequest::UDP, 53, "with$ymbols"));
  EXPECT_FALSE(
      firewall.AddAcceptRules(ModifyPortRuleRequest::UDP, 53, "-startdash"));
  EXPECT_FALSE(
      firewall.AddAcceptRules(ModifyPortRuleRequest::UDP, 53, "enddash-"));
  EXPECT_FALSE(
      firewall.AddAcceptRules(ModifyPortRuleRequest::UDP, 53, ".startdot"));
  EXPECT_FALSE(
      firewall.AddAcceptRules(ModifyPortRuleRequest::UDP, 53, "enddot."));

  EXPECT_FALSE(firewall.DeleteAcceptRules(ModifyPortRuleRequest::TCP, 80,
                                          "reallylonginterfacename"));
  EXPECT_FALSE(firewall.DeleteAcceptRules(ModifyPortRuleRequest::TCP, 80,
                                          "with spaces"));
  EXPECT_FALSE(firewall.DeleteAcceptRules(ModifyPortRuleRequest::TCP, 80,
                                          "with$ymbols"));
  EXPECT_FALSE(
      firewall.DeleteAcceptRules(ModifyPortRuleRequest::TCP, 80, "-startdash"));
  EXPECT_FALSE(
      firewall.DeleteAcceptRules(ModifyPortRuleRequest::TCP, 80, "enddash-"));
  EXPECT_FALSE(
      firewall.DeleteAcceptRules(ModifyPortRuleRequest::TCP, 80, ".startdot"));
  EXPECT_FALSE(
      firewall.DeleteAcceptRules(ModifyPortRuleRequest::TCP, 80, "enddot."));

  EXPECT_FALSE(firewall.DeleteAcceptRules(ModifyPortRuleRequest::UDP, 53,
                                          "reallylonginterfacename"));
  EXPECT_FALSE(firewall.DeleteAcceptRules(ModifyPortRuleRequest::UDP, 53,
                                          "with spaces"));
  EXPECT_FALSE(firewall.DeleteAcceptRules(ModifyPortRuleRequest::UDP, 53,
                                          "with$ymbols"));
  EXPECT_FALSE(
      firewall.DeleteAcceptRules(ModifyPortRuleRequest::UDP, 53, "-startdash"));
  EXPECT_FALSE(
      firewall.DeleteAcceptRules(ModifyPortRuleRequest::UDP, 53, "enddash-"));
  EXPECT_FALSE(
      firewall.DeleteAcceptRules(ModifyPortRuleRequest::UDP, 53, ".startdot"));
  EXPECT_FALSE(
      firewall.DeleteAcceptRules(ModifyPortRuleRequest::UDP, 53, "enddot."));
}

TEST(FirewallTest, AddAcceptRules_IptablesFails) {
  auto runner = new MockProcessRunner();
  Firewall firewall(runner);

  EXPECT_CALL(*runner, iptables(Iptables::Table::kFilter, _, _, _, _))
      .WillRepeatedly(Return(1));
  EXPECT_CALL(*runner, ip6tables(Iptables::Table::kFilter, _, _, _, _))
      .Times(0);

  // Punch hole for TCP port 80, should fail.
  ASSERT_FALSE(
      firewall.AddAcceptRules(ModifyPortRuleRequest::TCP, 80, "iface"));
  // Punch hole for UDP port 53, should fail.
  ASSERT_FALSE(
      firewall.AddAcceptRules(ModifyPortRuleRequest::UDP, 53, "iface"));
}

TEST(FirewallTest, AddAcceptRules_Ip6tablesFails) {
  auto runner = new MockProcessRunner();
  Firewall firewall(runner);

  Verify_iptables(*runner,
                  "filter -I ingress_port_firewall -p tcp --dport 80 -i iface "
                  "-j ACCEPT -w");
  Verify_iptables(*runner,
                  "filter -I ingress_port_firewall -p udp --dport 53 -i iface "
                  "-j ACCEPT -w");
  Verify_iptables(*runner,
                  "filter -D ingress_port_firewall -p tcp --dport 80 -i iface "
                  "-j ACCEPT -w");
  Verify_iptables(*runner,
                  "filter -D ingress_port_firewall -p udp --dport 53 -i iface "
                  "-j ACCEPT -w");
  EXPECT_CALL(*runner, ip6tables(Iptables::Table::kFilter, _, _, _, _))
      .WillRepeatedly(Return(1));

  // Punch hole for TCP port 80, should fail because 'ip6tables' fails.
  ASSERT_FALSE(
      firewall.AddAcceptRules(ModifyPortRuleRequest::TCP, 80, "iface"));
  // Punch hole for UDP port 53, should fail because 'ip6tables' fails.
  ASSERT_FALSE(
      firewall.AddAcceptRules(ModifyPortRuleRequest::UDP, 53, "iface"));
}

TEST(FirewallTest, AddLoopbackLockdownRules_InvalidPort) {
  auto runner = new MockProcessRunner();
  Firewall firewall(runner);

  EXPECT_CALL(*runner, iptables(Iptables::Table::kFilter, _, _, _, _)).Times(0);
  EXPECT_CALL(*runner, ip6tables(Iptables::Table::kFilter, _, _, _, _))
      .Times(0);

  // Try to lock down TCP port 0, port 0 is not a valid port.
  EXPECT_FALSE(
      firewall.AddLoopbackLockdownRules(ModifyPortRuleRequest::TCP, 0));
  // Try to lock down UDP port 0, port 0 is not a valid port.
  EXPECT_FALSE(
      firewall.AddLoopbackLockdownRules(ModifyPortRuleRequest::UDP, 0));
}

TEST(FirewallTest, AddLoopbackLockdownRules_Success) {
  auto runner = new MockProcessRunner();
  Firewall firewall(runner);

  Verify_iptables(
      *runner,
      "filter -I egress_port_firewall -p tcp --dport 80 -o lo -m owner ! "
      "--uid-owner chronos -j REJECT -w");
  Verify_ip6tables(
      *runner,
      "filter -I egress_port_firewall -p tcp --dport 80 -o lo -m owner ! "
      "--uid-owner chronos -j REJECT -w");
  ASSERT_TRUE(
      firewall.AddLoopbackLockdownRules(ModifyPortRuleRequest::TCP, 80));
  Mock::VerifyAndClearExpectations(runner);

  Verify_iptables(
      *runner,
      "filter -I egress_port_firewall -p udp --dport 53 -o lo -m owner ! "
      "--uid-owner chronos -j REJECT -w");
  Verify_ip6tables(
      *runner,
      "filter -I egress_port_firewall -p udp --dport 53 -o lo -m owner ! "
      "--uid-owner chronos -j REJECT -w");
  ASSERT_TRUE(
      firewall.AddLoopbackLockdownRules(ModifyPortRuleRequest::UDP, 53));
  Mock::VerifyAndClearExpectations(runner);

  Verify_iptables(
      *runner,
      "filter -I egress_port_firewall -p tcp --dport 1234 -o lo -m owner ! "
      "--uid-owner chronos -j REJECT -w");
  Verify_ip6tables(
      *runner,
      "filter -I egress_port_firewall -p tcp --dport 1234 -o lo -m owner ! "
      "--uid-owner chronos -j REJECT -w");
  ASSERT_TRUE(
      firewall.AddLoopbackLockdownRules(ModifyPortRuleRequest::TCP, 1234));
  Mock::VerifyAndClearExpectations(runner);

  Verify_iptables(
      *runner,
      "filter -I egress_port_firewall -p tcp --dport 8080 -o lo -m owner ! "
      "--uid-owner chronos -j REJECT -w");
  Verify_ip6tables(
      *runner,
      "filter -I egress_port_firewall -p tcp --dport 8080 -o lo -m owner ! "
      "--uid-owner chronos -j REJECT -w");
  ASSERT_TRUE(
      firewall.AddLoopbackLockdownRules(ModifyPortRuleRequest::TCP, 8080));
  Mock::VerifyAndClearExpectations(runner);
}

TEST(FirewallTest, AddLoopbackLockdownRules_IptablesFails) {
  auto runner = new MockProcessRunner();
  Firewall firewall(runner);

  EXPECT_CALL(*runner, iptables(Iptables::Table::kFilter, _, _, _, _))
      .WillRepeatedly(Return(1));
  EXPECT_CALL(*runner, ip6tables(Iptables::Table::kFilter, _, _, _, _))
      .Times(0);

  // Lock down TCP port 80, should fail.
  ASSERT_FALSE(
      firewall.AddLoopbackLockdownRules(ModifyPortRuleRequest::TCP, 80));
  // Lock down UDP port 53, should fail.
  ASSERT_FALSE(
      firewall.AddLoopbackLockdownRules(ModifyPortRuleRequest::UDP, 53));
}

TEST(FirewallTest, AddLoopbackLockdownRules_Ip6tablesFails) {
  auto runner = new MockProcessRunner();
  Firewall firewall(runner);

  Verify_iptables(
      *runner,
      "filter -I egress_port_firewall -p tcp --dport 80 -o lo -m owner ! "
      "--uid-owner chronos -j REJECT -w");
  Verify_iptables(
      *runner,
      "filter -D egress_port_firewall -p tcp --dport 80 -o lo -m owner ! "
      "--uid-owner chronos -j REJECT -w");
  Verify_iptables(
      *runner,
      "filter -I egress_port_firewall -p udp --dport 53 -o lo -m owner ! "
      "--uid-owner chronos -j REJECT -w");
  Verify_iptables(
      *runner,
      "filter -D egress_port_firewall -p udp --dport 53 -o lo -m owner ! "
      "--uid-owner chronos -j REJECT -w");
  EXPECT_CALL(*runner, ip6tables(Iptables::Table::kFilter, _, _, _, _))
      .WillRepeatedly(Return(1));

  // Lock down TCP port 80, should fail because 'ip6tables' fails.
  ASSERT_FALSE(
      firewall.AddLoopbackLockdownRules(ModifyPortRuleRequest::TCP, 80));
  // Lock down UDP port 53, should fail because 'ip6tables' fails.
  ASSERT_FALSE(
      firewall.AddLoopbackLockdownRules(ModifyPortRuleRequest::UDP, 53));
}

TEST(FirewallTest, AddIpv4ForwardRules_InvalidArguments) {
  auto runner = new MockProcessRunner();
  Firewall firewall(runner);

  // Invalid input interface. No iptables commands are issued.
  EXPECT_CALL(*runner, iptables(_, _, _, _, _)).Times(0);
  EXPECT_CALL(*runner, ip6tables(_, _, _, _, _)).Times(0);
  ASSERT_FALSE(firewall.AddIpv4ForwardRule(ModifyPortRuleRequest::TCP, "", 80,
                                           "-startdash", "100.115.92.5", 8080));
  ASSERT_FALSE(firewall.AddIpv4ForwardRule(ModifyPortRuleRequest::UDP, "", 80,
                                           "enddash-", "100.115.92.5", 8080));
  ASSERT_FALSE(firewall.DeleteIpv4ForwardRule(
      ModifyPortRuleRequest::TCP, "", 80, ".startdot", "100.115.92.5", 8080));
  ASSERT_FALSE(firewall.DeleteIpv4ForwardRule(
      ModifyPortRuleRequest::UDP, "", 80, "enddot.", "100.115.92.5", 8080));
  Mock::VerifyAndClearExpectations(runner);

  // Empty interface. No iptables commands are issused.
  EXPECT_CALL(*runner, iptables(_, _, _, _, _)).Times(0);
  EXPECT_CALL(*runner, ip6tables(_, _, _, _, _)).Times(0);
  ASSERT_FALSE(firewall.AddIpv4ForwardRule(ModifyPortRuleRequest::TCP, "", 80,
                                           "", "100.115.92.5", 8080));
  ASSERT_FALSE(firewall.AddIpv4ForwardRule(ModifyPortRuleRequest::UDP, "", 80,
                                           "", "100.115.92.5", 8080));
  ASSERT_FALSE(firewall.DeleteIpv4ForwardRule(ModifyPortRuleRequest::TCP, "",
                                              80, "", "100.115.92.5", 8080));
  ASSERT_FALSE(firewall.DeleteIpv4ForwardRule(ModifyPortRuleRequest::UDP, "",
                                              80, "", "100.115.92.5", 8080));
  Mock::VerifyAndClearExpectations(runner);

  // Invalid input dst address. No iptables commands are issused.
  EXPECT_CALL(*runner, iptables(_, _, _, _, _)).Times(0);
  EXPECT_CALL(*runner, ip6tables(_, _, _, _, _)).Times(0);
  ASSERT_FALSE(firewall.AddIpv4ForwardRule(ModifyPortRuleRequest::TCP,
                                           "256.256.256.256", 80, "iface",
                                           "100.115.92.5", 8080));
  ASSERT_FALSE(firewall.AddIpv4ForwardRule(ModifyPortRuleRequest::UDP,
                                           "qodpjqwpod", 80, "iface",
                                           "100.115.92.5", 8080));
  Mock::VerifyAndClearExpectations(runner);

  // Trying to delete an IPv4 forward rule with an invalid input address will
  // still trigger an explicit iptables -D command for the associated FORWARD
  // ACCEPT rule. Two such commands are expected.
  Verify_iptables(*runner,
                  "filter -D FORWARD -i iface -p tcp -d 100.115.92.5 --dport "
                  "8080 -j ACCEPT -w");
  Verify_iptables(*runner,
                  "filter -D FORWARD -i iface -p udp -d 100.115.92.5 --dport "
                  "8080 -j ACCEPT -w");
  ASSERT_FALSE(firewall.DeleteIpv4ForwardRule(
      ModifyPortRuleRequest::TCP, "1.1", 80, "iface", "100.115.92.5", 8080));
  ASSERT_FALSE(firewall.DeleteIpv4ForwardRule(ModifyPortRuleRequest::UDP,
                                              "2001:db8::1", 80, "iface",
                                              "100.115.92.5", 8080));
  Mock::VerifyAndClearExpectations(runner);

  // Trying to delete an IPv4 forward rule with an invalid input port will
  // still trigger an explicit iptables -D command for the associated FORWARD
  // ACCEPT rule. Two such commands are expected.
  Verify_iptables(*runner,
                  "filter -D FORWARD -i iface -p tcp -d 100.115.92.5 --dport "
                  "8080 -j ACCEPT -w");
  Verify_iptables(*runner,
                  "filter -D FORWARD -i iface -p udp -d 100.115.92.5 --dport "
                  "8080 -j ACCEPT -w");
  ASSERT_FALSE(firewall.DeleteIpv4ForwardRule(ModifyPortRuleRequest::TCP, "", 0,
                                              "iface", "100.115.92.5", 8080));
  ASSERT_FALSE(firewall.DeleteIpv4ForwardRule(ModifyPortRuleRequest::UDP, "", 0,
                                              "iface", "100.115.92.5", 8080));
  Mock::VerifyAndClearExpectations(runner);

  // Invalid output dst address. No iptables commands are issused.
  EXPECT_CALL(*runner, iptables(_, _, _, _, _)).Times(0);
  EXPECT_CALL(*runner, ip6tables(_, _, _, _, _)).Times(0);
  ASSERT_FALSE(firewall.AddIpv4ForwardRule(ModifyPortRuleRequest::TCP, "", 80,
                                           "iface", "", 8080));
  ASSERT_FALSE(firewall.AddIpv4ForwardRule(ModifyPortRuleRequest::UDP, "", 80,
                                           "iface", "qodpjqwpod", 8080));
  ASSERT_FALSE(firewall.DeleteIpv4ForwardRule(ModifyPortRuleRequest::TCP, "",
                                              80, "iface", "1.1", 8080));
  ASSERT_FALSE(firewall.DeleteIpv4ForwardRule(
      ModifyPortRuleRequest::UDP, "", 80, "iface", "2001:db8::1", 8080));
  Mock::VerifyAndClearExpectations(runner);

  // Invalid output dst port. No iptables commands are issused.
  EXPECT_CALL(*runner, iptables(_, _, _, _, _)).Times(0);
  EXPECT_CALL(*runner, ip6tables(_, _, _, _, _)).Times(0);
  ASSERT_FALSE(firewall.AddIpv4ForwardRule(ModifyPortRuleRequest::TCP, "", 80,
                                           "iface", "100.115.92.5", 0));
  ASSERT_FALSE(firewall.AddIpv4ForwardRule(ModifyPortRuleRequest::UDP, "", 80,
                                           "iface", "100.115.92.5", 0));
  ASSERT_FALSE(firewall.DeleteIpv4ForwardRule(ModifyPortRuleRequest::TCP, "",
                                              80, "iface", "100.115.92.5", 0));
  ASSERT_FALSE(firewall.DeleteIpv4ForwardRule(ModifyPortRuleRequest::UDP, "",
                                              80, "iface", "100.115.92.5", 0));
  Mock::VerifyAndClearExpectations(runner);
}

TEST(FirewallTest, AddIpv4ForwardRules_IptablesFails) {
  auto runner = new MockProcessRunner();
  Firewall firewall(runner);

  // AddIpv4ForwardRule: Firewall should return at the first failure and issue
  // only a single command.
  Verify_iptables(
      *runner,
      "nat -I ingress_port_forwarding -i iface -p tcp --dport 80 -j DNAT "
      "--to-destination 100.115.92.6:8080 -w",
      1);
  EXPECT_CALL(*runner, ip6tables(_, _, _, _, _)).Times(0);
  ASSERT_FALSE(firewall.AddIpv4ForwardRule(ModifyPortRuleRequest::TCP, "", 80,
                                           "iface", "100.115.92.6", 8080));
  Mock::VerifyAndClearExpectations(runner);
}

TEST(FirewallTest, AddIpv4ForwardRules_IptablesPartialFailure) {
  auto runner = new MockProcessRunner();
  Firewall firewall(runner);

  Verify_iptables(
      *runner,
      "nat -I ingress_port_forwarding -i iface -p udp --dport 80 -j DNAT "
      "--to-destination 100.115.92.6:8080 -w");
  Verify_iptables(*runner,
                  "filter -A FORWARD -i iface -p udp -d 100.115.92.6 --dport "
                  "8080 -j ACCEPT -w",
                  1);
  Verify_iptables(
      *runner,
      "nat -D ingress_port_forwarding -i iface -p udp --dport 80 -j DNAT "
      "--to-destination 100.115.92.6:8080 -w");
  EXPECT_CALL(*runner, ip6tables(_, _, _, _, _)).Times(0);
  ASSERT_FALSE(firewall.AddIpv4ForwardRule(ModifyPortRuleRequest::UDP, "", 80,
                                           "iface", "100.115.92.6", 8080));
  Mock::VerifyAndClearExpectations(runner);
}

TEST(FirewallTest, DeleteIpv4ForwardRules_IptablesFails) {
  auto runner = new MockProcessRunner();
  Firewall firewall(runner);

  // DeleteIpv4ForwardRule: Firewall should try to delete both the DNAT rule
  // and the FORWARD rule regardless of iptables failures.
  //  Verify_iptables(*runner, "nat -D ingress_port_forwarding -i iface -p tcp
  //  --dport 80 -j DNAT --to-destination 100.115.92.6:8080 -w");
  //  Verify_iptables(*runner, "filter -D FORWARD -i iface -p tcp -d
  //  100.115.92.6 --dport 8080 -j ACCEPT -w");
  Verify_iptables(
      *runner,
      "nat -D ingress_port_forwarding -i iface -p tcp --dport 80 -j DNAT "
      "--to-destination 100.115.92.6:8080 -w",
      1);
  Verify_iptables(*runner,
                  "filter -D FORWARD -i iface -p tcp -d 100.115.92.6 --dport "
                  "8080 -j ACCEPT -w",
                  1);
  EXPECT_CALL(*runner, ip6tables(_, _, _, _, _)).Times(0);
  ASSERT_FALSE(firewall.DeleteIpv4ForwardRule(
      ModifyPortRuleRequest::TCP, "", 80, "iface", "100.115.92.6", 8080));
  Mock::VerifyAndClearExpectations(runner);

  Verify_iptables(
      *runner,
      "nat -D ingress_port_forwarding -i iface -p udp --dport 80 -j DNAT "
      "--to-destination 100.115.92.6:8080 -w");
  Verify_iptables(*runner,
                  "filter -D FORWARD -i iface -p udp -d 100.115.92.6 --dport "
                  "8080 -j ACCEPT -w");
  EXPECT_CALL(*runner, ip6tables(_, _, _, _, _)).Times(0);
  ASSERT_TRUE(firewall.DeleteIpv4ForwardRule(ModifyPortRuleRequest::UDP, "", 80,
                                             "iface", "100.115.92.6", 8080));
  Mock::VerifyAndClearExpectations(runner);
}

TEST(FirewallTest, AddIpv4ForwardRules_ValidRules) {
  auto runner = new MockProcessRunner();
  Firewall firewall(runner);

  Verify_iptables(
      *runner,
      "nat -I ingress_port_forwarding -i wlan0 -p tcp --dport 80 -j DNAT "
      "--to-destination 100.115.92.2:8080 -w");
  Verify_iptables(*runner,
                  "filter -A FORWARD -i wlan0 -p tcp -d 100.115.92.2 --dport "
                  "8080 -j ACCEPT -w");
  ASSERT_TRUE(firewall.AddIpv4ForwardRule(ModifyPortRuleRequest::TCP, "", 80,
                                          "wlan0", "100.115.92.2", 8080));
  Mock::VerifyAndClearExpectations(runner);

  Verify_iptables(
      *runner,
      "nat -I ingress_port_forwarding -i vmtap0 -p tcp -d 100.115.92.2 --dport "
      "5555 -j DNAT --to-destination 127.0.0.1:5550 -w");
  Verify_iptables(*runner,
                  "filter -A FORWARD -i vmtap0 -p tcp -d 127.0.0.1 --dport "
                  "5550 -j ACCEPT -w");
  ASSERT_TRUE(firewall.AddIpv4ForwardRule(ModifyPortRuleRequest::TCP,
                                          "100.115.92.2", 5555, "vmtap0",
                                          "127.0.0.1", 5550));
  Mock::VerifyAndClearExpectations(runner);

  Verify_iptables(
      *runner,
      "nat -I ingress_port_forwarding -i eth0 -p udp --dport 5353 -j DNAT "
      "--to-destination 192.168.1.1:5353 -w");
  Verify_iptables(*runner,
                  "filter -A FORWARD -i eth0 -p udp -d 192.168.1.1 --dport "
                  "5353 -j ACCEPT -w");
  ASSERT_TRUE(firewall.AddIpv4ForwardRule(ModifyPortRuleRequest::UDP, "", 5353,
                                          "eth0", "192.168.1.1", 5353));
  Mock::VerifyAndClearExpectations(runner);

  Verify_iptables(
      *runner,
      "nat -D ingress_port_forwarding -i mlan0 -p tcp --dport 5000 -j DNAT "
      "--to-destination 10.0.0.24:5001 -w");
  Verify_iptables(*runner,
                  "filter -D FORWARD -i mlan0 -p tcp -d 10.0.0.24 --dport 5001 "
                  "-j ACCEPT -w");
  ASSERT_TRUE(firewall.DeleteIpv4ForwardRule(ModifyPortRuleRequest::TCP, "",
                                             5000, "mlan0", "10.0.0.24", 5001));
  Mock::VerifyAndClearExpectations(runner);

  Verify_iptables(
      *runner,
      "nat -D ingress_port_forwarding -i vmtap0 -p tcp -d 100.115.92.2 --dport "
      "5555 -j DNAT --to-destination 127.0.0.1:5550 -w");
  Verify_iptables(*runner,
                  "filter -D FORWARD -i vmtap0 -p tcp -d 127.0.0.1 --dport "
                  "5550 -j ACCEPT -w");
  ASSERT_TRUE(firewall.DeleteIpv4ForwardRule(ModifyPortRuleRequest::TCP,
                                             "100.115.92.2", 5555, "vmtap0",
                                             "127.0.0.1", 5550));
  Mock::VerifyAndClearExpectations(runner);

  Verify_iptables(
      *runner,
      "nat -D ingress_port_forwarding -i eth1 -p udp --dport 443 -j DNAT "
      "--to-destination 1.2.3.4:443 -w");
  Verify_iptables(
      *runner,
      "filter -D FORWARD -i eth1 -p udp -d 1.2.3.4 --dport 443 -j ACCEPT -w");
  ASSERT_TRUE(firewall.DeleteIpv4ForwardRule(ModifyPortRuleRequest::UDP, "",
                                             443, "eth1", "1.2.3.4", 443));
}

TEST(FirewallTest, AddIpv4ForwardRules_PartialFailure) {
  auto runner = new MockProcessRunner();
  Firewall firewall(runner);

  // When the second issued FORWARD command fails, expect a delete command to
  // cleanup the ingress_port_forwarding command that succeeded.
  Verify_iptables(
      *runner,
      "nat -I ingress_port_forwarding -i wlan0 -p tcp --dport 80 -j DNAT "
      "--to-destination 100.115.92.2:8080 -w");
  Verify_iptables(*runner,
                  "filter -A FORWARD -i wlan0 -p tcp -d 100.115.92.2 --dport "
                  "8080 -j ACCEPT -w",
                  1);
  Verify_iptables(
      *runner,
      "nat -D ingress_port_forwarding -i wlan0 -p tcp --dport 80 -j DNAT "
      "--to-destination 100.115.92.2:8080 -w");
  ASSERT_FALSE(firewall.AddIpv4ForwardRule(ModifyPortRuleRequest::TCP, "", 80,
                                           "wlan0", "100.115.92.2", 8080));
}
}  // namespace patchpanel
