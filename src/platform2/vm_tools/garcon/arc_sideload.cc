// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/garcon/arc_sideload.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <cstring>
#include <string>
#include <sys/types.h>
#include <utility>
#include <vector>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>

#include "base/command_line.h"
#include "base/logging.h"
#include "base/process/launch.h"
#include "base/strings/string_piece.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "vm_tools/garcon/package_kit_proxy.h"

namespace vm_tools {
namespace garcon {

namespace {

constexpr char kDeviceName[] = "eth0";
constexpr char kBridgePort[] = "5555";
constexpr char kBridgeHost[] = "arc";

// Wrapper to store the exit code and output of running a command.
using CommandOutput = std::pair<int, std::string>;

// Run the command given in |argv| (including all its flags). Returns its exit
// code and output.
CommandOutput RunCommand(base::CommandLine::StringVector argv) {
  CommandOutput ret{0, ""};
  // TODO(crbug.com/1047543): For some reason this call does not work as
  // documented. It always returns false (i.e. the app does not exit cleanly)
  // even when the output of the command is correct and what we expect. Until we
  // fix it we will be unable to detect when the adb sideload configuration
  // fails.
  base::GetAppOutputAndError(base::CommandLine{argv}, &ret.second);
  ret.first = 0;
  return ret;
}

// Determine the ipv4 address of the system and write it into out_result.
// Returns true on success, false otherwise. If we do not succeed, a useful
// error message will be written into out_result.
bool GetIpv4Address(std::string* out_result) {
  struct ifaddrs* head;
  if (getifaddrs(&head) != 0) {
    *out_result = std::string("getifaddrs failed: ") + strerror(errno);
    return false;
  }

  bool success = false;
  *out_result = std::string("Failed to find device ") + kDeviceName;
  for (struct ifaddrs* current = head; current != nullptr;
       current = current->ifa_next) {
    if (current->ifa_addr->sa_family != AF_INET)
      continue;
    if (std::strcmp(current->ifa_name, kDeviceName) != 0)
      continue;

    char host_info[NI_MAXHOST];
    if (getnameinfo(current->ifa_addr, sizeof(struct sockaddr_in), host_info,
                    NI_MAXHOST, NULL, 0, NI_NUMERICHOST) != 0) {
      *out_result = std::string("Failed to get name for device ") + kDeviceName;
    } else {
      *out_result = std::string(host_info);
      success = true;
    }
    break;
  }
  freeifaddrs(head);
  return success;
}

// Determine the address of the adb device and write it into out_result.
// Returns true on success, false otherwise. If we do not succeed, a useful
// error message will be written into out_result.
bool GetArcBridgeAddress(std::string* out_result) {
  struct addrinfo* head;
  struct addrinfo hints;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  int retcode = getaddrinfo(kBridgeHost, nullptr, &hints, &head);
  if (retcode != 0) {
    *out_result = std::string("getaddrinfo failed: ") + gai_strerror(retcode);
    return false;
  }

  bool success = false;
  if (head->ai_next != nullptr) {
    *out_result = std::string("Multiple addresses found for ") + kBridgeHost;
  } else {
    char addrstr[100];
    struct sockaddr_in* ipv4_addr = (struct sockaddr_in*)head->ai_addr;
    struct in_addr* ptr = &ipv4_addr->sin_addr;
    if (!inet_ntop(head->ai_family, ptr, addrstr, sizeof(addrstr))) {
      *out_result = std::string("inet_ntop failed: ") + strerror(errno);
    } else {
      *out_result = std::string(addrstr);
      success = true;
    }
  }

  freeaddrinfo(head);
  return success;
}

}  // namespace

bool ArcSideload::Enable(std::string* out_error) {
  // This only needs to be done once per-session, so we short circuit in the
  // event that another instance succeeded.
  if (enable_completed_successfully_this_session_)
    return true;

  std::string ip_address;
  if (!GetIpv4Address(&ip_address)) {
    *out_error = "Failed to determine ipv4 address: " + ip_address;
    return false;
  }

  std::string bridge_ip;
  if (!GetArcBridgeAddress(&bridge_ip)) {
    *out_error = "Failed to determine bridge address: " + bridge_ip;
    return false;
  }

  // Configure the kernel to allow routing.
  CommandOutput sysctl_cmd = RunCommand(
      {"sudo", "--", "sysctl", "-w", "net.ipv4.conf.eth0.route_localnet=1"});
  if (sysctl_cmd.first != 0) {
    *out_error = "Failed to configure eth0 for routing: " + sysctl_cmd.second;
    return false;
  }

  // Set up the routing rules.
  CommandOutput ipt_out_cmd =
      RunCommand({"sudo", "--", "iptables", "-t", "nat", "-A", "OUTPUT", "-p",
                  "tcp", "-d", "127.0.0.1", "--dport", "5555", "-j", "DNAT",
                  "--to", bridge_ip + ":" + kBridgePort});
  if (ipt_out_cmd.first != 0) {
    *out_error = "Failed to configure iptables to output to the bridge: " +
                 ipt_out_cmd.second;
    return false;
  }
  CommandOutput ipt_route_cmd =
      RunCommand({"sudo", "--", "iptables", "-t", "nat", "-A", "POSTROUTING",
                  "-p", "tcp", "-s", "127.0.0.1", "-d", bridge_ip, "--dport",
                  kBridgePort, "-j", "SNAT", "--to", std::string(ip_address)});
  if (ipt_route_cmd.first != 0) {
    *out_error = "Failed to configure iptables to route to the container: " +
                 ipt_route_cmd.second;
    return false;
  }

  LOG(INFO) << "Enabled arc sideloading";
  enable_completed_successfully_this_session_ = true;
  return true;
}

bool ArcSideload::enable_completed_successfully_this_session_ = false;

}  // namespace garcon
}  // namespace vm_tools
