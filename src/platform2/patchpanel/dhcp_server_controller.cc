// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/dhcp_server_controller.h"

#include <linux/capability.h>

#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

#include "patchpanel/system.h"

namespace patchpanel {
namespace {
constexpr char kDnsmasqPath[] = "/usr/sbin/dnsmasq";
constexpr char kLeaseTime[] = "12h";  // 12 hours
}  // namespace

using Config = DHCPServerController::Config;

// static
std::optional<Config> Config::Create(
    const net_base::IPv4CIDR& host_cidr,
    const net_base::IPv4Address& start_ip,
    const net_base::IPv4Address& end_ip,
    const std::vector<net_base::IPv4Address>& dns_servers,
    const std::vector<std::string>& domain_searches,
    const std::optional<int>& mtu,
    const DHCPOptions& dhcp_options) {
  // The start_ip and end_ip should be in the same subnet as host_cidr.
  if (!(host_cidr.InSameSubnetWith(start_ip) &&
        host_cidr.InSameSubnetWith(end_ip))) {
    return std::nullopt;
  }

  // end_ip should not be smaller than or start_ip.
  if (end_ip < start_ip) {
    return std::nullopt;
  }

  // Transform std::vector<IPv4Address> to std::vector<std::string>.
  std::vector<std::string> dns_server_strs;
  for (const auto& ip : dns_servers) {
    dns_server_strs.push_back(ip.ToString());
  }

  const std::string mtu_str = (mtu) ? std::to_string(*mtu) : "";

  return Config(host_cidr.address().ToString(),
                host_cidr.ToNetmask().ToString(), start_ip.ToString(),
                end_ip.ToString(), base::JoinString(dns_server_strs, ","),
                base::JoinString(domain_searches, ","), mtu_str, dhcp_options);
}

Config::Config(const std::string& host_ip,
               const std::string& netmask,
               const std::string& start_ip,
               const std::string& end_ip,
               const std::string& dns_servers,
               const std::string& domain_searches,
               const std::string& mtu,
               const DHCPOptions& dhcp_options)
    : host_ip_(host_ip),
      netmask_(netmask),
      start_ip_(start_ip),
      end_ip_(end_ip),
      dns_servers_(dns_servers),
      domain_searches_(domain_searches),
      mtu_(mtu),
      dhcp_options_(dhcp_options) {}

std::ostream& operator<<(std::ostream& os, const Config& config) {
  os << "{host_ip: " << config.host_ip() << ", netmask: " << config.netmask()
     << ", start_ip: " << config.start_ip() << ", end_ip: " << config.end_ip()
     << "}";
  return os;
}

DHCPServerController::DHCPServerController(const std::string& ifname)
    : ifname_(ifname), process_manager_(shill::ProcessManager::GetInstance()) {}

DHCPServerController::~DHCPServerController() {
  Stop();
}

bool DHCPServerController::Start(const Config& config,
                                 ExitCallback exit_callback) {
  if (IsRunning()) {
    LOG(ERROR) << "DHCP server is still running: " << ifname_
               << ", old config=" << *config_;
    return false;
  }

  LOG(INFO) << "Starting DHCP server at: " << ifname_ << ", config: " << config;
  std::vector<std::string> dnsmasq_args = {
      "--dhcp-authoritative",  // dnsmasq is the only DHCP server on a network.
      "--keep-in-foreground",  // Use foreground mode to prevent forking.
      "--log-dhcp",            // Log the DHCP event.
      "--no-ping",             // (b/257377981): Speed up the negotiation.
      "--port=0",              // Disable DNS.
      "--leasefile-ro",        // Do not use leasefile.
      base::StringPrintf("--interface=%s", ifname_.c_str()),
      base::StringPrintf("--dhcp-range=%s,%s,%s,%s", config.start_ip().c_str(),
                         config.end_ip().c_str(), config.netmask().c_str(),
                         kLeaseTime),
      base::StringPrintf("--dhcp-option=option:netmask,%s",
                         config.netmask().c_str()),
      base::StringPrintf("--dhcp-option=option:router,%s",
                         config.host_ip().c_str()),
  };
  if (!config.dns_servers().empty()) {
    dnsmasq_args.push_back(base::StringPrintf(
        "--dhcp-option=option:dns-server,%s", config.dns_servers().c_str()));
  }
  if (!config.domain_searches().empty()) {
    dnsmasq_args.push_back(
        base::StringPrintf("--dhcp-option=option:domain-search,%s",
                           config.domain_searches().c_str()));
  }
  if (!config.mtu().empty()) {
    dnsmasq_args.push_back(base::StringPrintf("--dhcp-option=option:mtu,%s",
                                              config.mtu().c_str()));
  }
  for (const auto& [tag, content] : config.dhcp_options()) {
    dnsmasq_args.push_back(
        base::StringPrintf("--dhcp-option-force=%u,%s", tag, content.c_str()));
  }

  shill::ProcessManager::MinijailOptions minijail_options = {};
  minijail_options.user = kPatchpaneldUser;
  minijail_options.group = kPatchpaneldGroup;
  minijail_options.capmask = CAP_TO_MASK(CAP_NET_ADMIN) |
                             CAP_TO_MASK(CAP_NET_BIND_SERVICE) |
                             CAP_TO_MASK(CAP_NET_RAW);

  const pid_t pid = process_manager_->StartProcessInMinijail(
      FROM_HERE, base::FilePath(kDnsmasqPath), dnsmasq_args, /*environment=*/{},
      minijail_options,
      base::BindOnce(&DHCPServerController::OnProcessExitedUnexpectedly,
                     weak_ptr_factory_.GetWeakPtr()));
  if (pid < 0) {
    LOG(ERROR) << "Failed to start the DHCP server: " << ifname_;
    return false;
  }

  pid_ = pid;
  config_ = config;
  exit_callback_ = std::move(exit_callback);
  return true;
}

void DHCPServerController::Stop() {
  if (!IsRunning()) {
    return;
  }

  LOG(INFO) << "Stopping DHCP server at: " << ifname_;
  process_manager_->StopProcess(*pid_);

  pid_ = std::nullopt;
  config_ = std::nullopt;
  exit_callback_.Reset();
}

bool DHCPServerController::IsRunning() const {
  return pid_.has_value();
}

void DHCPServerController::OnProcessExitedUnexpectedly(int exit_status) {
  LOG(ERROR) << "dnsmasq exited unexpectedly, status: " << exit_status;

  pid_ = std::nullopt;
  config_ = std::nullopt;
  std::move(exit_callback_).Run(exit_status);
}

}  // namespace patchpanel
