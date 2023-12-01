// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/firewall.h"

#include <arpa/inet.h>
#include <linux/capability.h>
#include <netinet/in.h>

#include <string>
#include <vector>

#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

#include "patchpanel/datapath.h"
#include "patchpanel/iptables.h"
#include "patchpanel/net_util.h"

namespace {

// Interface names must be shorter than 'IFNAMSIZ' chars.
// See http://man7.org/linux/man-pages/man7/netdevice.7.html
// 'IFNAMSIZ' is 16 in recent kernels.
// See
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/if.h?h=v4.14#n33
constexpr size_t kInterfaceNameSize = 16;

// Interface names are passed directly to the 'iptables' command. Rather than
// auditing 'iptables' source code to see how it handles malformed names,
// do some sanitization on the names beforehand.
bool IsValidInterfaceName(const std::string& iface) {
  // |iface| should be shorter than |kInterfaceNameSize| chars and have only
  // alphanumeric characters (embedded hypens and periods are also permitted).
  if (iface.length() >= kInterfaceNameSize) {
    return false;
  }
  if (base::StartsWith(iface, "-", base::CompareCase::SENSITIVE) ||
      base::EndsWith(iface, "-", base::CompareCase::SENSITIVE) ||
      base::StartsWith(iface, ".", base::CompareCase::SENSITIVE) ||
      base::EndsWith(iface, ".", base::CompareCase::SENSITIVE)) {
    return false;
  }
  for (auto c : iface) {
    if (!std::isalnum(c) && (c != '-') && (c != '.')) {
      return false;
    }
  }
  return true;
}

}  // namespace

namespace patchpanel {

const std::string ProtocolName(Protocol proto) {
  if (proto == ModifyPortRuleRequest::INVALID_PROTOCOL) {
    NOTREACHED() << "Unexpected L4 protocol value";
  }
  return base::ToLowerASCII(ModifyPortRuleRequest::Protocol_Name(proto));
}

Firewall::Firewall() : Firewall(new MinijailedProcessRunner()) {}

Firewall::Firewall(MinijailedProcessRunner* process_runner) {
  process_runner_.reset(process_runner);
}

bool Firewall::AddAcceptRules(Protocol protocol,
                              uint16_t port,
                              const std::string& interface) {
  if (port == 0U) {
    LOG(ERROR) << "Port 0 is not a valid port";
    return false;
  }

  if (!IsValidInterfaceName(interface)) {
    LOG(ERROR) << "Invalid interface name '" << interface << "'";
    return false;
  }

  if (!AddAcceptRule(IpFamily::kIPv4, protocol, port, interface)) {
    LOG(ERROR) << "Could not add IPv4 ACCEPT rule";
    return false;
  }

  if (!AddAcceptRule(IpFamily::kIPv6, protocol, port, interface)) {
    LOG(ERROR) << "Could not add IPv6 ACCEPT rule";
    DeleteAcceptRule(IpFamily::kIPv4, protocol, port, interface);
    return false;
  }

  return true;
}

bool Firewall::DeleteAcceptRules(Protocol protocol,
                                 uint16_t port,
                                 const std::string& interface) {
  if (port == 0U) {
    LOG(ERROR) << "Port 0 is not a valid port";
    return false;
  }

  if (!IsValidInterfaceName(interface)) {
    LOG(ERROR) << "Invalid interface name '" << interface << "'";
    return false;
  }

  bool ip4_success =
      DeleteAcceptRule(IpFamily::kIPv4, protocol, port, interface);
  bool ip6_success =
      DeleteAcceptRule(IpFamily::kIPv6, protocol, port, interface);
  return ip4_success && ip6_success;
}

bool Firewall::AddIpv4ForwardRule(Protocol protocol,
                                  const std::string& input_ip,
                                  uint16_t port,
                                  const std::string& interface,
                                  const std::string& dst_ip,
                                  uint16_t dst_port) {
  if (!ModifyIpv4DNATRule(protocol, input_ip, port, interface, dst_ip, dst_port,
                          Iptables::Command::kI)) {
    return false;
  }

  if (!ModifyIpv4ForwardChain(protocol, interface, dst_ip, dst_port,
                              Iptables::Command::kA)) {
    ModifyIpv4DNATRule(protocol, input_ip, port, interface, dst_ip, dst_port,
                       Iptables::Command::kD);
    return false;
  }

  return true;
}

bool Firewall::DeleteIpv4ForwardRule(Protocol protocol,
                                     const std::string& input_ip,
                                     uint16_t port,
                                     const std::string& interface,
                                     const std::string& dst_ip,
                                     uint16_t dst_port) {
  bool success = true;
  if (!ModifyIpv4DNATRule(protocol, input_ip, port, interface, dst_ip, dst_port,
                          Iptables::Command::kD)) {
    success = false;
  }
  if (!ModifyIpv4ForwardChain(protocol, interface, dst_ip, dst_port,
                              Iptables::Command::kD)) {
    success = false;
  }
  return success;
}

bool Firewall::ModifyIpv4DNATRule(Protocol protocol,
                                  const std::string& input_ip,
                                  uint16_t port,
                                  const std::string& interface,
                                  const std::string& dst_ip,
                                  uint16_t dst_port,
                                  Iptables::Command command) {
  if (!input_ip.empty() && GetIpFamily(input_ip) != AF_INET) {
    LOG(ERROR) << "Invalid input IPv4 address '" << input_ip << "'";
    return false;
  }

  if (port == 0U) {
    LOG(ERROR) << "Port 0 is not a valid port";
    return false;
  }

  if (!IsValidInterfaceName(interface) || interface.empty()) {
    LOG(ERROR) << "Invalid interface name '" << interface << "'";
    return false;
  }

  if (GetIpFamily(dst_ip) != AF_INET) {
    LOG(ERROR) << "Invalid destination IPv4 address '" << dst_ip << "'";
    return false;
  }

  if (dst_port == 0U) {
    LOG(ERROR) << "Destination port 0 is not a valid port";
    return false;
  }

  // Only support deleting existing forwarding rules or inserting rules in the
  // first position: ARC++ generic inbound DNAT rule always need to go last.
  if (command != Iptables::Command::kI && command != Iptables::Command::kD) {
    LOG(ERROR) << "Invalid iptables command '" << command << "'";
    return false;
  }

  std::vector<std::string> argv{
      kIngressPortForwardingChain,
      "-i",
      interface,
      "-p",  // protocol
      ProtocolName(protocol),
  };
  if (!input_ip.empty()) {
    argv.push_back("-d");  // input destination ip
    argv.push_back(input_ip);
  }
  argv.push_back("--dport");  // input destination port
  argv.push_back(std::to_string(port));
  argv.push_back("-j");
  argv.push_back("DNAT");
  argv.push_back("--to-destination");  // new output destination ip:port
  argv.push_back(dst_ip + ":" + std::to_string(dst_port));
  argv.push_back("-w");  // Wait for xtables lock.
  return RunIptables(IpFamily::kIPv4, Iptables::Table::kNat, command, argv);
}

bool Firewall::ModifyIpv4ForwardChain(Protocol protocol,
                                      const std::string& interface,
                                      const std::string& dst_ip,
                                      uint16_t dst_port,
                                      Iptables::Command command) {
  if (!IsValidInterfaceName(interface) || interface.empty()) {
    LOG(ERROR) << "Invalid interface name '" << interface << "'";
    return false;
  }

  if (GetIpFamily(dst_ip) != AF_INET) {
    LOG(ERROR) << "Invalid IPv4 destination address '" << dst_ip << "'";
    return false;
  }

  if (dst_port == 0U) {
    LOG(ERROR) << "Destination port 0 is not a valid port";
    return false;
  }

  // Order does not matter for the FORWARD chain: both -A or -I are possible.
  if (command != Iptables::Command::kA && command != Iptables::Command::kI &&
      command != Iptables::Command::kD) {
    LOG(ERROR) << "Invalid iptables command '" << command << "'";
    return false;
  }

  std::vector<std::string> argv{
      "FORWARD",
      "-i",
      interface,
      "-p",  // protocol
      ProtocolName(protocol),
      "-d",  // destination ip
      dst_ip,
      "--dport",  // destination port
      std::to_string(dst_port),
      "-j",
      "ACCEPT",
      "-w",
  };  // Wait for xtables lock.
  return RunIptables(IpFamily::kIPv4, Iptables::Table::kFilter, command, argv);
}

bool Firewall::AddLoopbackLockdownRules(Protocol protocol, uint16_t port) {
  if (port == 0U) {
    LOG(ERROR) << "Port 0 is not a valid port";
    return false;
  }

  if (!AddLoopbackLockdownRule(IpFamily::kIPv4, protocol, port)) {
    LOG(ERROR) << "Could not add loopback IPv4 REJECT rule";
    return false;
  }

  if (!AddLoopbackLockdownRule(IpFamily::kIPv6, protocol, port)) {
    LOG(ERROR) << "Could not add loopback IPv6 REJECT rule";
    DeleteLoopbackLockdownRule(IpFamily::kIPv4, protocol, port);
    return false;
  }

  return true;
}

bool Firewall::DeleteLoopbackLockdownRules(Protocol protocol, uint16_t port) {
  if (port == 0U) {
    LOG(ERROR) << "Port 0 is not a valid port";
    return false;
  }

  bool ip4_success =
      DeleteLoopbackLockdownRule(IpFamily::kIPv4, protocol, port);
  bool ip6_success =
      DeleteLoopbackLockdownRule(IpFamily::kIPv6, protocol, port);
  return ip4_success && ip6_success;
}

bool Firewall::AddAcceptRule(IpFamily ip_family,
                             Protocol protocol,
                             uint16_t port,
                             const std::string& interface) {
  std::vector<std::string> argv{
      kIngressPortFirewallChain,
      "-p",  // protocol
      ProtocolName(protocol),
      "--dport",  // destination port
      std::to_string(port),
  };
  if (!interface.empty()) {
    argv.push_back("-i");  // interface
    argv.push_back(interface);
  }
  argv.push_back("-j");
  argv.push_back("ACCEPT");
  argv.push_back("-w");  // Wait for xtables lock.

  return RunIptables(ip_family, Iptables::Table::kFilter, Iptables::Command::kI,
                     argv);
}

bool Firewall::DeleteAcceptRule(IpFamily ip_family,
                                Protocol protocol,
                                uint16_t port,
                                const std::string& interface) {
  std::vector<std::string> argv{
      kIngressPortFirewallChain,
      "-p",  // protocol
      ProtocolName(protocol),
      "--dport",  // destination port
      std::to_string(port),
  };
  if (!interface.empty()) {
    argv.push_back("-i");  // interface
    argv.push_back(interface);
  }
  argv.push_back("-j");
  argv.push_back("ACCEPT");
  argv.push_back("-w");  // Wait for xtables lock.

  return RunIptables(ip_family, Iptables::Table::kFilter, Iptables::Command::kD,
                     argv);
}

bool Firewall::AddLoopbackLockdownRule(IpFamily ip_family,
                                       Protocol protocol,
                                       uint16_t port) {
  std::vector<std::string> argv{
      kEgressPortFirewallChain,
      "-p",  // protocol
      ProtocolName(protocol),
      "--dport",  // destination port
      std::to_string(port),
      "-o",  // output interface
      "lo",
      "-m",  // match extension
      "owner",
      "!",
      "--uid-owner",
      "chronos",
      "-j",
      "REJECT",
      "-w",  // Wait for xtables lock.
  };

  return RunIptables(ip_family, Iptables::Table::kFilter, Iptables::Command::kI,
                     argv);
}

bool Firewall::DeleteLoopbackLockdownRule(IpFamily ip_family,
                                          Protocol protocol,
                                          uint16_t port) {
  std::vector<std::string> argv{
      kEgressPortFirewallChain,
      "-p",  // protocol
      ProtocolName(protocol),
      "--dport",  // destination port
      std::to_string(port),
      "-o",  // output interface
      "lo",
      "-m",  // match extension
      "owner",
      "!",
      "--uid-owner",
      "chronos",
      "-j",
      "REJECT",
      "-w",  // Wait for xtables lock.
  };

  // TODO(b/278486416):  add IPv4 or IPv6
  return RunIptables(ip_family, Iptables::Table::kFilter, Iptables::Command::kD,
                     argv);
}

bool Firewall::RunIptables(IpFamily ip_family,
                           Iptables::Table table,
                           Iptables::Command command,
                           const std::vector<std::string>& argv) {
  if (ip_family == IpFamily::kIPv4)
    return process_runner_->iptables(table, command, argv, false) == 0;

  if (ip_family == IpFamily::kIPv6)
    return process_runner_->ip6tables(table, command, argv, false) == 0;

  return false;
}

}  // namespace patchpanel
