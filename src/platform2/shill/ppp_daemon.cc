// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/ppp_daemon.h"

#include <stdint.h>

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

extern "C" {
// A struct member in pppd.h has the name 'class'.
#define class class_num
// pppd.h defines a bool type.
#define bool pppd_bool_t
#include <pppd/pppd.h>
#undef bool
#undef class
}

#include <base/files/file_path.h>
#include <base/memory/weak_ptr.h>
#include <base/strings/string_number_conversions.h>

#include "shill/control_interface.h"
#include "shill/error.h"
#include "shill/external_task.h"
#include "shill/logging.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kPPP;
}  // namespace Logging

namespace {

const char kDaemonPath[] = "/usr/sbin/pppd";
const uint32_t kUnspecifiedValue = UINT32_MAX;

}  // namespace

PPPDaemon::Options::Options()
    : debug(false),
      no_detach(false),
      no_default_route(false),
      use_peer_dns(false),
      use_shim_plugin(true),
      lcp_echo_interval(kUnspecifiedValue),
      lcp_echo_failure(kUnspecifiedValue),
      max_fail(kUnspecifiedValue),
      use_ipv6(false) {}

const char PPPDaemon::kShimPluginPath[] = SHIMDIR "/shill-pppd-plugin.so";

std::unique_ptr<ExternalTask> PPPDaemon::Start(
    ControlInterface* control_interface,
    ProcessManager* process_manager,
    const base::WeakPtr<RpcTaskDelegate>& task_delegate,
    const PPPDaemon::Options& options,
    const std::string& device,
    PPPDaemon::DeathCallback death_callback,
    Error* error) {
  std::vector<std::string> arguments;

  // pppd runs under the non-root 'shill' group, so we need to explicitly tell
  // pppd to allow certain privileged options.
  arguments.push_back("privgroup");
  arguments.push_back("shill");

  if (options.debug) {
    arguments.push_back("debug");
  }
  if (options.no_detach) {
    arguments.push_back("nodetach");
  }
  if (options.no_default_route) {
    arguments.push_back("nodefaultroute");
  }
  if (options.use_peer_dns) {
    arguments.push_back("usepeerdns");
  }
  if (options.use_shim_plugin) {
    arguments.push_back("plugin");
    arguments.push_back(kShimPluginPath);
  }
  if (options.lcp_echo_interval != kUnspecifiedValue) {
    arguments.push_back("lcp-echo-interval");
    arguments.push_back(base::NumberToString(options.lcp_echo_interval));
  }
  if (options.lcp_echo_failure != kUnspecifiedValue) {
    arguments.push_back("lcp-echo-failure");
    arguments.push_back(base::NumberToString(options.lcp_echo_failure));
  }
  if (options.max_fail != kUnspecifiedValue) {
    arguments.push_back("maxfail");
    arguments.push_back(base::NumberToString(options.max_fail));
  }
  if (options.use_ipv6) {
    arguments.push_back("+ipv6");
    arguments.push_back("ipv6cp-use-ipaddr");
  }

  arguments.push_back(device);

  auto task =
      std::make_unique<ExternalTask>(control_interface, process_manager,
                                     task_delegate, std::move(death_callback));

  std::map<std::string, std::string> environment;
  if (task->Start(base::FilePath(kDaemonPath), arguments, environment, true,
                  error)) {
    return task;
  }
  return nullptr;
}

// static
std::string PPPDaemon::GetInterfaceName(
    const std::map<std::string, std::string>& configuration) {
  if (base::Contains(configuration, kPPPInterfaceName)) {
    return configuration.find(kPPPInterfaceName)->second;
  }
  return std::string();
}

// static
IPConfig::Properties PPPDaemon::ParseIPConfiguration(
    const std::map<std::string, std::string>& configuration) {
  IPConfig::Properties properties;
  properties.address_family = IPAddress::kFamilyIPv4;
  properties.subnet_prefix =
      IPAddress::GetMaxPrefixLength(properties.address_family);
  for (const auto& it : configuration) {
    const auto& key = it.first;
    const auto& value = it.second;
    SLOG(2) << "Processing: " << key << " -> " << value;
    if (key == kPPPInternalIP4Address) {
      properties.address = value;
    } else if (key == kPPPExternalIP4Address) {
      properties.peer_address = value;
    } else if (key == kPPPGatewayAddress) {
      properties.gateway = value;
    } else if (key == kPPPDNS1) {
      properties.dns_servers.insert(properties.dns_servers.begin(), value);
    } else if (key == kPPPDNS2) {
      properties.dns_servers.push_back(value);
    } else if (key == kPPPLNSAddress) {
      // This is really a L2TPIPsec property. But it's sent to us by
      // our PPP plugin.
      size_t prefix = IPAddress::GetMaxPrefixLength(properties.address_family);
      properties.exclusion_list.push_back(value + "/" +
                                          base::NumberToString(prefix));
    } else if (key == kPPPMRU) {
      int mru;
      if (!base::StringToInt(value, &mru)) {
        LOG(WARNING) << "Failed to parse MRU: " << value;
        continue;
      }
      properties.mtu = mru;
    } else {
      SLOG(2) << "Key ignored.";
    }
  }
  if (properties.gateway.empty()) {
    // The gateway may be unspecified, since this is a point-to-point
    // link. Set to the peer's address, so that Connection can set the
    // routing table.
    properties.gateway = properties.peer_address;
  }
  return properties;
}

// static
Service::ConnectFailure PPPDaemon::ExitStatusToFailure(int exit) {
  switch (exit) {
    case EXIT_OK:
      return Service::kFailureNone;
    case EXIT_PEER_AUTH_FAILED:
    case EXIT_AUTH_TOPEER_FAILED:
      return Service::kFailurePPPAuth;
    default:
      return Service::kFailureUnknown;
  }
}

// static
Service::ConnectFailure PPPDaemon::ParseExitFailure(
    const std::map<std::string, std::string>& dict) {
  const auto it = dict.find(kPPPExitStatus);
  if (it == dict.end()) {
    LOG(ERROR) << "Failed to find the failure status in the dict";
    return Service::kFailureInternal;
  }
  int exit = 0;
  if (!base::StringToInt(it->second, &exit)) {
    LOG(ERROR) << "Failed to parse the failure status from the dict, value: "
               << it->second;
    return Service::kFailureInternal;
  }
  return ExitStatusToFailure(exit);
}

}  // namespace shill
