// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/network/network.h"

#include <algorithm>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <base/notreached.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/service_constants.h>
#include <chromeos/patchpanel/dbus/client.h>

#include "shill/connection.h"
#include "shill/event_dispatcher.h"
#include "shill/ipconfig.h"
#include "shill/logging.h"
#include "shill/metrics.h"
#include "shill/net/ip_address.h"
#include "shill/net/rtnl_handler.h"
#include "shill/network/network_applier.h"
#include "shill/network/network_priority.h"
#include "shill/network/proc_fs_stub.h"
#include "shill/network/slaac_controller.h"
#include "shill/routing_table.h"
#include "shill/routing_table_entry.h"
#include "shill/service.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kDevice;
}  // namespace Logging

namespace {
// Constant string advertised in DHCP Vendor option 43 by Android devices
// sharing a metered network (typically a Cellular network) via tethering
// over a WiFi hotspot or a USB ethernet connection.
constexpr char kAndroidMeteredHotspotVendorOption[] = "ANDROID_METERED";
}  // namespace

Network::Network(int interface_index,
                 const std::string& interface_name,
                 Technology technology,
                 bool fixed_ip_params,
                 ControlInterface* control_interface,
                 EventDispatcher* dispatcher,
                 Metrics* metrics)
    : interface_index_(interface_index),
      interface_name_(interface_name),
      technology_(technology),
      logging_tag_(interface_name),
      fixed_ip_params_(fixed_ip_params),
      proc_fs_(std::make_unique<ProcFsStub>(interface_name_)),
      control_interface_(control_interface),
      dispatcher_(dispatcher),
      metrics_(metrics),
      dhcp_provider_(DHCPProvider::GetInstance()),
      routing_table_(RoutingTable::GetInstance()),
      rtnl_handler_(RTNLHandler::GetInstance()),
      network_applier_(NetworkApplier::GetInstance()) {}

Network::~Network() {
  for (auto* ev : event_handlers_) {
    ev->OnNetworkDestroyed(interface_index_);
  }
}

void Network::RegisterEventHandler(EventHandler* handler) {
  if (std::find(event_handlers_.begin(), event_handlers_.end(), handler) !=
      event_handlers_.end()) {
    return;
  }
  event_handlers_.push_back(handler);
}

void Network::UnregisterEventHandler(EventHandler* handler) {
  auto it = std::find(event_handlers_.begin(), event_handlers_.end(), handler);
  if (it != event_handlers_.end()) {
    event_handlers_.erase(it);
  }
}

void Network::Start(const Network::StartOptions& opts) {
  ignore_link_monitoring_ = opts.ignore_link_monitoring;
  ipv4_gateway_found_ = false;
  ipv6_gateway_found_ = false;

  probing_configuration_ = opts.probing_configuration;

  // accept_ra and link_protocol_ipv6 should not be set at the same time.
  DCHECK(!(opts.accept_ra && link_protocol_ipv6_properties_));

  // TODO(b/232177767): Log the StartOptions and other parameters.
  if (state_ != State::kIdle) {
    LOG(INFO) << logging_tag_
              << ": Network has been started, stop it before starting with the "
                 "new options";
    StopInternal(/*is_failure=*/false, /*trigger_callback=*/false);
  }

  EnableARPFiltering();

  // If the execution of this function fails, StopInternal() will be called and
  // turn the state to kIdle.
  state_ = State::kConfiguring;

  bool ipv6_started = false;
  if (opts.accept_ra) {
    slaac_controller_ = CreateSLAACController();
    slaac_controller_->RegisterCallback(
        base::BindRepeating(&Network::OnUpdateFromSLAAC, AsWeakPtr()));
    slaac_controller_->Start();
    ipv6_started = true;
  }
  if (ipv6_static_properties_) {
    dispatcher_->PostTask(
        FROM_HERE,
        base::BindOnce(&Network::ConfigureStaticIPv6Address, AsWeakPtr()));
    ipv6_started = true;
  }
  if (link_protocol_ipv6_properties_) {
    proc_fs_->SetIPFlag(IPAddress::kFamilyIPv6, ProcFsStub::kIPFlagDisableIPv6,
                        "0");
    set_ip6config(
        std::make_unique<IPConfig>(control_interface_, interface_name_));
    ip6config_->set_properties(*link_protocol_ipv6_properties_);
    dispatcher_->PostTask(FROM_HERE,
                          base::BindOnce(&Network::SetupConnection, AsWeakPtr(),
                                         ip6config_.get()));
    ipv6_started = true;
  }

  // Note that currently, the existence of ipconfig_ indicates if the IPv4 part
  // of Network has been started.
  bool dhcp_started = false;
  if (opts.dhcp) {
    auto dhcp_opts = *opts.dhcp;
    if (static_network_config_.ipv4_address_cidr) {
      dhcp_opts.use_arp_gateway = false;
    }
    dhcp_controller_ = dhcp_provider_->CreateController(interface_name_,
                                                        dhcp_opts, technology_);
    dhcp_controller_->RegisterCallbacks(
        base::BindRepeating(&Network::OnIPConfigUpdatedFromDHCP, AsWeakPtr()),
        base::BindRepeating(&Network::OnDHCPDrop, AsWeakPtr()));
    set_ipconfig(std::make_unique<IPConfig>(control_interface_, interface_name_,
                                            IPConfig::kTypeDHCP));
    dhcp_started = dhcp_controller_->RequestIP();
  } else if (link_protocol_ipv4_properties_) {
    set_ipconfig(
        std::make_unique<IPConfig>(control_interface_, interface_name_));
    ipconfig_->set_properties(*link_protocol_ipv4_properties_);
  } else {
    // This could happen on IPv6-only networks.
    DCHECK(ipv6_started);
  }

  if (link_protocol_ipv4_properties_ ||
      static_network_config_.ipv4_address_cidr) {
    // If the parameters contain an IP address, apply them now and bring the
    // interface up.  When DHCP information arrives, it will supplement the
    // static information.
    dispatcher_->PostTask(
        FROM_HERE, base::BindOnce(&Network::OnIPv4ConfigUpdated, AsWeakPtr()));
  } else if (!dhcp_started && !ipv6_started) {
    // Neither v4 nor v6 is running, trigger the failure callback directly.
    LOG(WARNING) << logging_tag_ << ": Failed to start IP provisioning";
    dispatcher_->PostTask(
        FROM_HERE,
        base::BindOnce(&Network::StopInternal, AsWeakPtr(),
                       /*is_failure=*/true, /*trigger_callback=*/true));
  }

  LOG(INFO) << logging_tag_ << ": Started IP provisioning, dhcp: "
            << (dhcp_started ? "started" : "no")
            << ", accept_ra: " << std::boolalpha << opts.accept_ra;
  if (static_network_config_.ipv4_address_cidr.has_value()) {
    LOG(INFO) << logging_tag_ << ": has IPv4 static config "
              << static_network_config_;
  }
  if (link_protocol_ipv4_properties_) {
    LOG(INFO) << logging_tag_ << ": has IPv4 link properties "
              << *link_protocol_ipv4_properties_;
  }
  if (ipv6_static_properties_) {
    LOG(INFO) << logging_tag_ << ": has IPv6 static properties "
              << *ipv6_static_properties_;
  }
  if (link_protocol_ipv6_properties_) {
    LOG(INFO) << logging_tag_ << ": has IPv6 link properties "
              << *link_protocol_ipv6_properties_;
  }
}

std::unique_ptr<SLAACController> Network::CreateSLAACController() {
  auto slaac_controller = std::make_unique<SLAACController>(
      interface_index_, proc_fs_.get(), rtnl_handler_, dispatcher_);
  return slaac_controller;
}

void Network::SetupConnection(IPConfig* ipconfig) {
  DCHECK(ipconfig);
  LOG(INFO) << logging_tag_ << ": Setting "
            << IPAddress::GetAddressFamilyName(
                   ipconfig->properties().address_family)
            << " connection";
  if (connection_ == nullptr) {
    connection_ = CreateConnection();
  }
  connection_->UpdateFromIPConfig(ipconfig->properties());
  connection_->UpdateRoutingPolicy(GetAddresses());
  network_applier_->ApplyDNS(priority_,
                             ipconfig_ ? &ipconfig_->properties() : nullptr,
                             ip6config_ ? &ip6config_->properties() : nullptr);
  if (state_ != State::kConnected && technology_ != Technology::kVPN) {
    // The Network becomes connected, wait for 30 seconds to report its IP type.
    // Skip VPN since it's already reported separately in VPNService.
    dispatcher_->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&Network::ReportIPType,
                       weak_factory_for_connection_.GetWeakPtr()),
        base::Seconds(30));
  }
  state_ = State::kConnected;
  ConfigureStaticIPv6Address();
  for (auto* ev : event_handlers_) {
    ev->OnConnectionUpdated(interface_index_);
  }

  const bool ipconfig_changed = current_ipconfig_ != ipconfig;
  current_ipconfig_ = ipconfig;
  if (ipconfig_changed && !current_ipconfig_change_handler_.is_null()) {
    current_ipconfig_change_handler_.Run();
  }
}

std::unique_ptr<Connection> Network::CreateConnection() const {
  return std::make_unique<Connection>(interface_index_, interface_name_,
                                      fixed_ip_params_, technology_);
}

void Network::Stop() {
  StopInternal(/*is_failure=*/false, /*trigger_callback=*/true);
}

void Network::StopInternal(bool is_failure, bool trigger_callback) {
  std::stringstream ss;
  if (ipconfig()) {
    ss << ", IPv4 config: " << *ipconfig();
  }
  if (ip6config()) {
    ss << ", IPv6 config: " << *ip6config();
  }
  LOG(INFO) << logging_tag_ << ": Stopping "
            << (is_failure ? "after failure" : "normally") << ss.str();

  weak_factory_for_connection_.InvalidateWeakPtrs();

  network_validation_result_.reset();
  StopPortalDetection();
  StopConnectionDiagnostics();

  const bool should_trigger_callback =
      state_ != State::kIdle && trigger_callback;
  bool ipconfig_changed = false;
  if (dhcp_controller_) {
    dhcp_controller_->ReleaseIP(DHCPController::kReleaseReasonDisconnect);
    dhcp_controller_ = nullptr;
  }
  if (ipconfig()) {
    set_ipconfig(nullptr);
    link_protocol_ipv4_properties_ = {};
    ipconfig_changed = true;
  }
  if (slaac_controller_) {
    slaac_controller_->Stop();
    slaac_controller_ = nullptr;
  }
  if (ip6config()) {
    set_ip6config(nullptr);
    link_protocol_ipv6_properties_ = {};
    ipconfig_changed = true;
  }
  // Emit updated IP configs if there are any changes.
  if (ipconfig_changed) {
    for (auto* ev : event_handlers_) {
      ev->OnIPConfigsPropertyUpdated(interface_index_);
    }
  }
  if (current_ipconfig_) {
    current_ipconfig_ = nullptr;
    if (!current_ipconfig_change_handler_.is_null()) {
      current_ipconfig_change_handler_.Run();
    }
  }
  state_ = State::kIdle;
  connection_ = nullptr;
  priority_ = NetworkPriority{};
  if (should_trigger_callback) {
    for (auto* ev : event_handlers_) {
      ev->OnNetworkStopped(interface_index_, is_failure);
    }
  }
}

void Network::InvalidateIPv6Config() {
  SLOG(2) << logging_tag_ << ": " << __func__;
  if (!ip6config_) {
    return;
  }

  SLOG(2) << logging_tag_ << "Waiting for new IPv6 configuration";
  if (slaac_controller_) {
    slaac_controller_->Stop();
    slaac_controller_->Start();
  }

  set_ip6config(nullptr);
  for (auto* ev : event_handlers_) {
    ev->OnIPConfigsPropertyUpdated(interface_index_);
  }
}

void Network::OnIPv4ConfigUpdated() {
  if (!ipconfig()) {
    return;
  }
  saved_network_config_ =
      ipconfig()->ApplyNetworkConfig(static_network_config_);
  if (static_network_config_.ipv4_address_cidr.has_value() &&
      dhcp_controller_) {
    // If we are using a statically configured IP address instead of a leased IP
    // address, release any acquired lease so it may be used by others.  This
    // allows us to merge other non-leased parameters (like DNS) when they're
    // available from a DHCP server and not overridden by static parameters, but
    // at the same time we avoid taking up a dynamic IP address the DHCP server
    // could assign to someone else who might actually use it.
    dhcp_controller_->ReleaseIP(DHCPController::kReleaseReasonStaticIP);
  }
  SetupConnection(ipconfig());
  for (auto* ev : event_handlers_) {
    ev->OnIPConfigsPropertyUpdated(interface_index_);
  }
}

void Network::OnStaticIPConfigChanged(const NetworkConfig& config) {
  static_network_config_ = config;
  if (state_ == State::kIdle) {
    // This can happen after service is selected but before the Network starts.
    return;
  }

  if (ipconfig() == nullptr) {
    LOG(WARNING)
        << interface_name_
        << " is not configured with IPv4. Skip applying static IP config";
    return;
  }

  LOG(INFO) << logging_tag_ << ": static IPv4 config update " << config;

  // Clear the previously applied static IP parameters. The new config will be
  // applied in ConfigureStaticIPTask().
  ipconfig()->ApplyNetworkConfig(saved_network_config_);
  saved_network_config_ = {};

  // TODO(b/232177767): Apply the static IP parameters no matter if there is a
  // valid IPv4 in it.
  if (config.ipv4_address_cidr.has_value()) {
    dispatcher_->PostTask(
        FROM_HERE, base::BindOnce(&Network::OnIPv4ConfigUpdated, AsWeakPtr()));
  }

  if (dhcp_controller_) {
    // Trigger DHCP renew.
    dhcp_controller_->RenewIP();
  }
}

void Network::RegisterCurrentIPConfigChangeHandler(
    base::RepeatingClosure handler) {
  current_ipconfig_change_handler_ = handler;
}

IPConfig* Network::GetCurrentIPConfig() const {
  // Make sure that the |current_ipconfig_| is still valid.
  if (current_ipconfig_ == ipconfig_.get()) {
    return current_ipconfig_;
  }
  if (current_ipconfig_ == ip6config_.get()) {
    return current_ipconfig_;
  }
  return nullptr;
}

void Network::OnIPConfigUpdatedFromDHCP(const IPConfig::Properties& properties,
                                        bool new_lease_acquired) {
  // |dhcp_controller_| cannot be empty when the callback is invoked.
  DCHECK(dhcp_controller_);
  DCHECK(ipconfig());
  LOG(INFO) << logging_tag_ << ": DHCP lease "
            << (new_lease_acquired ? "acquired " : "update ") << properties;
  if (new_lease_acquired) {
    for (auto* ev : event_handlers_) {
      ev->OnGetDHCPLease(interface_index_);
    }
  }
  ipconfig()->UpdateProperties(properties);
  OnIPv4ConfigUpdated();
  // TODO(b/232177767): OnIPv4ConfiguredWithDHCPLease() should be called inside
  // Network::OnIPv4ConfigUpdated() and only if SetupConnection() happened as a
  // result of the new lease. The current call pattern reproduces the same
  // conditions as before crrev/c/3840983.
  if (new_lease_acquired) {
    for (auto* ev : event_handlers_) {
      ev->OnIPv4ConfiguredWithDHCPLease(interface_index_);
    }
  }
}

void Network::OnDHCPDrop(bool is_voluntary) {
  LOG(INFO) << logging_tag_ << ": " << __func__
            << ": is_voluntary = " << is_voluntary;
  if (!is_voluntary) {
    for (auto* ev : event_handlers_) {
      ev->OnGetDHCPFailure(interface_index_);
    }
  }

  // |dhcp_controller_| cannot be empty when the callback is invoked.
  DCHECK(dhcp_controller_);
  DCHECK(ipconfig());
  if (static_network_config_.ipv4_address_cidr.has_value()) {
    // Consider three cases:
    //
    // 1. We're here because DHCP failed while starting up. There
    //    are two subcases:
    //    a. DHCP has failed, and Static IP config has _not yet_
    //       completed. It's fine to do nothing, because we'll
    //       apply the static config shortly.
    //    b. DHCP has failed, and Static IP config has _already_
    //       completed. It's fine to do nothing, because we can
    //       continue to use the static config that's already
    //       been applied.
    //
    // 2. We're here because a previously valid DHCP configuration
    //    is no longer valid. There's still a static IP config,
    //    because the condition in the if clause evaluated to true.
    //    Furthermore, the static config includes an IP address for
    //    us to use.
    //
    //    The current configuration may include some DHCP
    //    parameters, overridden by any static parameters
    //    provided. We continue to use this configuration, because
    //    the only configuration element that is leased to us (IP
    //    address) will be overridden by a static parameter.
    //
    // TODO(b/261681299): When this function is triggered by a renew failure,
    // the current IPConfig can be a mix of DHCP and static IP. We need to
    // revert the DHCP part.
    return;
  }

  ipconfig()->ResetProperties();
  for (auto* ev : event_handlers_) {
    ev->OnIPConfigsPropertyUpdated(interface_index_);
  }

  // Fallback to IPv6 if possible.
  if (ip6config() && ip6config()->properties().HasIPAddressAndDNS()) {
    LOG(INFO) << logging_tag_ << ": operating in IPv6-only because of "
              << (is_voluntary ? "receiving DHCP option 108" : "DHCP failure");
    if (!connection_ || !connection_->IsIPv6()) {
      // Destroy the IPv4 connection (if exists) to clear the state in kernel at
      // first. It is possible that this function is called when we have a valid
      // DHCP lease now (e.g., triggered by a renew failure). We need to
      // withdraw the effect of the previous IPv4 lease at first. Static IP is
      // handled above so it's guaranteed that there is no valid IPv4 lease.
      // Also see b/261681299.
      connection_ = nullptr;
      SetupConnection(ip6config());
    }
    return;
  }

  if (is_voluntary) {
    if (state_ == State::kConfiguring) {
      // DHCPv4 reports to prefer v6 only. Continue to wait for SLAAC.
      return;
    } else {
      LOG(ERROR) << logging_tag_
                 << ": DHCP option 108 received but no valid IPv6 network is "
                    "usable. Likely a network configuration error.";
    }
  }

  StopInternal(/*is_failure=*/true, /*trigger_callback=*/true);
}

bool Network::RenewDHCPLease() {
  if (!dhcp_controller_) {
    return false;
  }
  SLOG(2) << logging_tag_ << ": renewing DHCP lease";
  // If RenewIP() fails, DHCPController will output a ERROR log.
  return dhcp_controller_->RenewIP();
}

void Network::DestroyDHCPLease(const std::string& name) {
  dhcp_provider_->DestroyLease(name);
}

std::optional<base::TimeDelta> Network::TimeToNextDHCPLeaseRenewal() {
  if (!dhcp_controller_) {
    return std::nullopt;
  }
  return dhcp_controller_->TimeToLeaseExpiry();
}

void Network::ConfigureStaticIPv6Address() {
  if (!ipv6_static_properties_ || ipv6_static_properties_->address.empty()) {
    return;
  }
  const auto local = IPAddress::CreateFromStringAndPrefix(
      ipv6_static_properties_->address, ipv6_static_properties_->subnet_prefix,
      IPAddress::kFamilyIPv6);
  if (!local.has_value()) {
    LOG(ERROR) << logging_tag_ << ": Local address "
               << ipv6_static_properties_->address << " is invalid";
    return;
  }
  LOG(INFO) << logging_tag_ << ": configuring static IPv6 address " << *local;
  rtnl_handler_->AddInterfaceAddress(interface_index_, *local,
                                     local->GetDefaultBroadcast());
}

void Network::OnUpdateFromSLAAC(SLAACController::UpdateType update_type) {
  if (update_type == SLAACController::UpdateType::kAddress) {
    OnIPv6AddressChanged();
  } else if (update_type == SLAACController::UpdateType::kRDNSS) {
    OnIPv6DnsServerAddressesChanged();
  }
}

void Network::OnIPv6AddressChanged() {
  auto slaac_addresses = slaac_controller_->GetAddresses();
  if (slaac_addresses.size() == 0) {
    if (ip6config()) {
      LOG(INFO) << logging_tag_ << ": Removing all observed IPv6 addresses";
      set_ip6config(nullptr);
      for (auto* ev : event_handlers_) {
        ev->OnIPConfigsPropertyUpdated(interface_index_);
      }
      // TODO(b/232177767): We may lose the whole IP connectivity here (if there
      // is no IPv4).
    }
    return;
  }

  const auto& primary_address = slaac_addresses[0];
  CHECK_EQ(primary_address.family(), IPAddress::kFamilyIPv6);
  IPConfig::Properties properties;
  if (!primary_address.IntoString(&properties.address)) {
    LOG(ERROR) << logging_tag_
               << ": Unable to convert IPv6 address into a string";
    return;
  }
  properties.subnet_prefix = primary_address.prefix();

  RoutingTableEntry default_route(IPAddress::kFamilyIPv6);
  if (routing_table_->GetDefaultRouteFromKernel(interface_index_,
                                                &default_route)) {
    if (!default_route.gateway.IntoString(&properties.gateway)) {
      LOG(ERROR) << logging_tag_
                 << ": Unable to convert IPv6 gateway into a string";
      return;
    }
  } else {
    // The kernel normally populates the default route before it performs
    // a neighbor solicitation for the new address, so it shouldn't be
    // missing at this point.
    LOG(WARNING) << logging_tag_
                 << ": No default route for global IPv6 address "
                 << properties.address;
  }

  // No matter whether the primary address changes, any address change will
  // need to trigger address-based routing rule to be updated.
  if (connection_) {
    connection_->UpdateRoutingPolicy(GetAddresses());
  }

  std::string addresses_str;
  std::string sep;
  for (const auto& addr : slaac_addresses) {
    addresses_str += sep;
    addresses_str += addr.ToString();
    sep = ",";
  }
  LOG(INFO) << logging_tag_ << ": Updating IPv6 addresses to [" << addresses_str
            << "]";

  if (!ip6config()) {
    set_ip6config(
        std::make_unique<IPConfig>(control_interface_, interface_name_));
  } else if (properties.address == ip6config()->properties().address &&
             properties.subnet_prefix ==
                 ip6config()->properties().subnet_prefix &&
             properties.gateway == ip6config()->properties().gateway) {
    SLOG(2) << logging_tag_ << ": " << __func__ << ": primary address for "
            << interface_name_ << " is unchanged";
    return;
  }

  properties.address_family = IPAddress::kFamilyIPv6;
  properties.method = kTypeIPv6;
  // It is possible for device to receive DNS server notification before IP
  // address notification, so preserve the saved DNS server if it exist.
  properties.dns_servers = ip6config()->properties().dns_servers;
  if (ipv6_static_properties_ &&
      !ipv6_static_properties_->dns_servers.empty()) {
    properties.dns_servers = ipv6_static_properties_->dns_servers;
  }
  ip6config()->set_properties(properties);
  for (auto* ev : event_handlers_) {
    ev->OnGetSLAACAddress(interface_index_);
    ev->OnIPConfigsPropertyUpdated(interface_index_);
  }
  OnIPv6ConfigUpdated();
  // TODO(b/232177767): OnIPv6ConfiguredWithSLAACAddress() should be called
  // inside Network::OnIPv6ConfigUpdated() and only if SetupConnection()
  // happened as a result of the new address (ignoring IPv4 and assuming Network
  // is fully dual-stack). The current call pattern reproduces the same
  // conditions as before crrev/c/3840983.
  for (auto* ev : event_handlers_) {
    ev->OnIPv6ConfiguredWithSLAACAddress(interface_index_);
  }
}

void Network::OnIPv6ConfigUpdated() {
  if (!ip6config()) {
    LOG(WARNING) << logging_tag_ << ": " << __func__
                 << " called but |ip6config_| is empty";
    return;
  }

  // Apply search domains from StaticIPConfig, if the list is not empty and
  // there is a change. This is a workaround to apply search domains from policy
  // on IPv6-only network (b/265680125), since StaticIPConfig is only applied to
  // IPv4 now. This workaround can be removed after we unify IPv4 and IPv6
  // config into a single object. Since currently we don't update it in
  // OnStaticIPConfigChanged() (because it will make the code more tricky to
  // handle IPv6 in that code path), SearchDomains change will not take effect
  // on a connected network. This limitation should be acceptable that it cannot
  // be changed via UI, but only through policy.
  const auto& search_domains = static_network_config_.dns_search_domains;
  if (search_domains.has_value() && !search_domains->empty() &&
      ip6config()->properties().domain_search != *search_domains) {
    ip6config()->UpdateSearchDomains(*search_domains);
  }

  if (ip6config()->properties().HasIPAddressAndDNS()) {
    // Setup connection using IPv6 configuration only if the IPv6 configuration
    // is ready for connection (contained both IP address and DNS servers), and
    // there is no existing IPv4 connection. We always prefer IPv4 configuration
    // over IPv6.
    if (!IsConnected() || connection_->IsIPv6()) {
      SetupConnection(ip6config());
    } else {
      // Still apply IPv6 DNS even if the Connection is setup with IPv4.
      network_applier_->ApplyDNS(
          priority_, ipconfig_ ? &ipconfig_->properties() : nullptr,
          ip6config_ ? &ip6config_->properties() : nullptr);
    }
  }
}

void Network::OnIPv6DnsServerAddressesChanged() {
  std::vector<IPAddress> rdnss = slaac_controller_->GetRDNSSAddresses();
  if (rdnss.size() == 0) {
    if (!ip6config()) {
      return;
    }
    LOG(INFO) << logging_tag_ << ": Removing all observed IPv6 DNS addresses";
    ip6config()->UpdateDNSServers(std::vector<std::string>());
    for (auto* ev : event_handlers_) {
      ev->OnIPConfigsPropertyUpdated(interface_index_);
    }
    return;
  }

  if (!ip6config()) {
    set_ip6config(
        std::make_unique<IPConfig>(control_interface_, interface_name_));
  }

  std::vector<std::string> addresses_str;
  for (const auto& ip : rdnss) {
    std::string address_str;
    if (!ip.IntoString(&address_str)) {
      LOG(ERROR) << interface_name_
                 << ": Unable to convert IPv6 address into a string!";
      continue;
    }
    addresses_str.push_back(address_str);
  }

  // Done if no change in server addresses.
  if (ip6config()->properties().dns_servers == addresses_str) {
    SLOG(2) << logging_tag_ << ": " << __func__ << " IPv6 DNS server list for "
            << interface_name_ << " is unchanged.";
    return;
  }

  LOG(INFO) << logging_tag_ << ": Updating DNS IPv6 addresses to ["
            << base::JoinString(addresses_str, ",") << "]";
  ip6config()->UpdateDNSServers(std::move(addresses_str));
  for (auto* ev : event_handlers_) {
    ev->OnIPConfigsPropertyUpdated(interface_index_);
  }
  OnIPv6ConfigUpdated();
}

void Network::EnableARPFiltering() {
  proc_fs_->SetIPFlag(IPAddress::kFamilyIPv4, ProcFsStub::kIPFlagArpAnnounce,
                      ProcFsStub::kIPFlagArpAnnounceBestLocal);
  proc_fs_->SetIPFlag(IPAddress::kFamilyIPv4, ProcFsStub::kIPFlagArpIgnore,
                      ProcFsStub::kIPFlagArpIgnoreLocalOnly);
}

void Network::SetPriority(NetworkPriority priority) {
  if (!connection_) {
    LOG(WARNING) << logging_tag_ << ": " << __func__
                 << " called but no connection exists";
    return;
  }
  if (priority_ == priority) {
    return;
  }
  connection_->SetPriority(priority);
  network_applier_->ApplyDNS(priority,
                             ipconfig_ ? &ipconfig_->properties() : nullptr,
                             ip6config_ ? &ip6config_->properties() : nullptr);
  priority_ = priority;
}

NetworkPriority Network::GetPriority() {
  return priority_;
}

std::vector<IPAddress> Network::GetAddresses() const {
  std::vector<IPAddress> result;
  if (slaac_controller_) {
    result = slaac_controller_->GetAddresses();
  }

  const auto insert_addr = [&result](const std::string& addr_str, int prefix) {
    auto addr = IPAddress::CreateFromStringAndPrefix(addr_str, prefix);
    if (!addr.has_value()) {
      LOG(ERROR) << "Invalid IP address: " << addr_str << "/" << prefix;
      return;
    }
    result.push_back(std::move(*addr));
  };

  if (link_protocol_ipv6_properties_ &&
      link_protocol_ipv6_properties_->subnet_prefix > 0) {
    insert_addr(link_protocol_ipv6_properties_->address,
                link_protocol_ipv6_properties_->subnet_prefix);
  }

  if (ipconfig() && ipconfig()->properties().subnet_prefix > 0) {
    insert_addr(ipconfig()->properties().address,
                ipconfig()->properties().subnet_prefix);
  }
  // link_protocol_ipv4_properties_ should already be reflected in ipconfig_
  return result;
}

std::vector<IPAddress> Network::GetDNSServers() const {
  std::vector<IPAddress> result;
  if (ipconfig_) {
    for (const auto& dns4 : ipconfig_->properties().dns_servers) {
      auto addr = IPAddress::CreateFromString(dns4);
      if (!addr.has_value()) {
        LOG(ERROR) << logging_tag_ << ": Invalid DNS address: " << dns4;
        continue;
      }
      result.push_back(*addr);
    }
  }
  if (ip6config_) {
    for (const auto& dns6 : ip6config_->properties().dns_servers) {
      auto addr = IPAddress::CreateFromString(dns6);
      if (!addr.has_value()) {
        LOG(ERROR) << logging_tag_ << ": Invalid DNS address: " << dns6;
        continue;
      }
      result.push_back(*addr);
    }
  }
  return result;
}

void Network::OnNeighborReachabilityEvent(
    const patchpanel::Client::NeighborReachabilityEvent& event) {
  using Role = patchpanel::Client::NeighborRole;
  using Status = patchpanel::Client::NeighborStatus;

  const auto ip_address = IPAddress::CreateFromString(event.ip_addr);
  if (!ip_address.has_value()) {
    LOG(ERROR) << logging_tag_ << ": " << __func__ << ": invalid IP address "
               << event.ip_addr;
    return;
  }

  switch (event.status) {
    case Status::kFailed:
    case Status::kReachable:
      break;
    default:
      LOG(ERROR) << logging_tag_ << ": " << __func__ << ": invalid event "
                 << event;
      return;
  }

  if (event.status == Status::kFailed) {
    metrics_->NotifyNeighborLinkMonitorFailure(
        technology_, ip_address->family(), event.role);
  }

  if (state_ == State::kIdle) {
    LOG(INFO) << logging_tag_ << ": " << __func__ << ": Idle state, ignoring "
              << event;
    return;
  }

  if (ignore_link_monitoring_) {
    LOG(INFO) << logging_tag_ << ": " << __func__
              << " link monitor events ignored, ignoring " << event;
    return;
  }

  if (event.role == Role::kGateway ||
      event.role == Role::kGatewayAndDnsServer) {
    IPConfig* ipconfig;
    bool* gateway_found;
    if (ip_address->family() == IPAddress::kFamilyIPv4) {
      ipconfig = ipconfig_.get();
      gateway_found = &ipv4_gateway_found_;
    } else if (ip_address->family() == IPAddress::kFamilyIPv6) {
      ipconfig = ip6config_.get();
      gateway_found = &ipv6_gateway_found_;
    } else {
      NOTREACHED();
      return;
    }
    // It is impossible to observe a reachability event for the current gateway
    // before Network knows the IPConfig for the current connection: patchpanel
    // would not emit reachability event for the correct connection yet.
    if (!ipconfig) {
      LOG(INFO) << logging_tag_ << ": " << __func__ << ": "
                << IPAddress::GetAddressFamilyName(ip_address->family())
                << " not configured, ignoring neighbor reachability event "
                << event;
      return;
    }
    // Ignore reachability events related to a prior connection.
    if (ipconfig->properties().gateway != event.ip_addr) {
      LOG(INFO) << logging_tag_ << ": " << __func__
                << ": ignored neighbor reachability event with conflicting "
                   "gateway address "
                << event;
      return;
    }
    *gateway_found = true;
  }

  for (auto* ev : event_handlers_) {
    ev->OnNeighborReachabilityEvent(interface_index_, *ip_address, event.role,
                                    event.status);
  }
}

// TODO(b/269401899): these accessors adapt to the legacy portal detection
// behavior that runs on IPv4 when an IPv4 address is available, and IPv6 when
// IPv4 address is not available but both IPv6 address and IPv6 DNS are
// available. Should be removed when portal detection migrate to the ideal
// behavior of running on both IPv4 and IPv6 separately.
std::vector<std::string> Network::dns_servers() const {
  if (ipconfig() && !ipconfig()->properties().address.empty()) {
    return ipconfig()->properties().dns_servers;
  }
  if (ip6config() && ip6config()->properties().HasIPAddressAndDNS()) {
    return ip6config()->properties().dns_servers;
  }
  return {};
}

std::optional<IPAddress> Network::local() const {
  if (ipconfig() && !ipconfig()->properties().address.empty()) {
    return IPAddress::CreateFromString((ipconfig()->properties().address));
  }
  if (ip6config() && ip6config()->properties().HasIPAddressAndDNS()) {
    return IPAddress::CreateFromString((ip6config()->properties().address));
  }
  return std::nullopt;
}

std::optional<IPAddress> Network::gateway() const {
  if (ipconfig() && !ipconfig()->properties().address.empty()) {
    return IPAddress::CreateFromString(ipconfig()->properties().gateway);
  }
  if (ip6config() && ip6config()->properties().HasIPAddressAndDNS()) {
    return IPAddress::CreateFromString(ip6config()->properties().gateway);
  }
  return std::nullopt;
}

bool Network::StartPortalDetection(bool reset) {
  if (!IsConnected()) {
    LOG(INFO) << logging_tag_
              << ": Cannot start portal detection: Network is not connected";
    return false;
  }

  if (!reset && IsPortalDetectionInProgress()) {
    LOG(INFO) << logging_tag_ << ": Portal detection is already running.";
    return true;
  }

  if (!local()) {
    LOG(ERROR) << logging_tag_
               << ": Cannot start portal detection: No valid IP address";
    return false;
  }

  portal_detector_ = CreatePortalDetector();
  if (!portal_detector_->Start(interface_name_, *local(), dns_servers(),
                               logging_tag_)) {
    LOG(ERROR) << logging_tag_ << ": Portal detection failed to start.";
    portal_detector_.reset();
    return false;
  }

  LOG(INFO) << logging_tag_ << ": Portal detection started.";
  for (auto* ev : event_handlers_) {
    ev->OnNetworkValidationStart(interface_index_);
  }
  return true;
}

bool Network::RestartPortalDetection() {
  if (!portal_detector_) {
    LOG(ERROR) << logging_tag_
               << ": Portal detection was not started, cannot restart";
    return false;
  }

  if (!local()) {
    LOG(ERROR) << logging_tag_
               << ": Cannot restart portal detection: No valid IP address";
    return false;
  }

  if (!portal_detector_->Restart(interface_name_, *local(), dns_servers(),
                                 logging_tag_)) {
    LOG(ERROR) << logging_tag_ << ": Portal detection failed to restart.";
    StopPortalDetection();
    return false;
  }

  LOG(INFO) << logging_tag_ << ": Portal detection restarted.";
  // TODO(b/216351118): this ignores the portal detection retry delay. The
  // callback should be triggered when the next attempt starts, not when it
  // is scheduled.
  for (auto* ev : event_handlers_) {
    ev->OnNetworkValidationStart(interface_index_);
  }
  return true;
}

void Network::StopPortalDetection() {
  if (IsPortalDetectionInProgress()) {
    LOG(INFO) << logging_tag_ << ": Portal detection stopped.";
    for (auto* ev : event_handlers_) {
      ev->OnNetworkValidationStop(interface_index_);
    }
  }
  portal_detector_.reset();
}

bool Network::IsPortalDetectionInProgress() const {
  return portal_detector_ && portal_detector_->IsInProgress();
}

std::unique_ptr<PortalDetector> Network::CreatePortalDetector() {
  return std::make_unique<PortalDetector>(
      dispatcher_, probing_configuration_,
      base::BindRepeating(&Network::OnPortalDetectorResult, AsWeakPtr()));
}

void Network::OnPortalDetectorResult(const PortalDetector::Result& result) {
  std::string previous_validation_state = "unevaluated";
  if (network_validation_result_) {
    previous_validation_state = PortalDetector::ValidationStateToString(
        network_validation_result_->GetValidationState());
  }
  LOG(INFO) << logging_tag_
            << ": OnPortalDetectorResult: " << previous_validation_state
            << " -> " << result.GetValidationState();

  int portal_status = Metrics::PortalDetectionResultToEnum(result);
  metrics_->SendEnumToUMA(Metrics::kMetricPortalResult, technology_,
                          portal_status);

  if (!IsConnected()) {
    LOG(INFO) << logging_tag_
              << ": Portal detection completed but Network is not connected";
    return;
  }

  network_validation_result_ = result;

  for (auto* ev : event_handlers_) {
    ev->OnNetworkValidationResult(interface_index_, result);
  }
  // If portal detection was not conclusive, also start additional connection
  // diagnostics for the current network connection.
  switch (result.GetValidationState()) {
    case PortalDetector::ValidationState::kNoConnectivity:
    case PortalDetector::ValidationState::kPartialConnectivity:
      StartConnectionDiagnostics();
      break;
    case PortalDetector::ValidationState::kInternetConnectivity:
      // Conclusive result that allows the Service to transition to the
      // "online" state.
    case PortalDetector::ValidationState::kPortalRedirect:
      // Conclusive result that allows to start the portal detection sign-in
      // flow.
      break;
  }
}

void Network::StartConnectionDiagnostics() {
  if (!IsConnected()) {
    LOG(INFO) << logging_tag_
              << ": Not connected, cannot start connection diagnostics";
    return;
  }
  DCHECK(connection_ != nullptr);

  const auto local_address = local();
  if (!local_address) {
    LOG(ERROR)
        << logging_tag_
        << ": Local address unavailable, aborting connection diagnostics";
    return;
  }

  const auto gateway_address = gateway();
  if (!gateway_address) {
    LOG(ERROR) << logging_tag_
               << ": Gateway unavailable, aborting connection diagnostics";
    return;
  }

  connection_diagnostics_ = CreateConnectionDiagnostics(
      *local_address, *gateway_address, dns_servers());
  if (!connection_diagnostics_->Start(probing_configuration_.portal_http_url)) {
    connection_diagnostics_.reset();
    LOG(WARNING) << logging_tag_ << ": Failed to start connection diagnostics";
    return;
  }
  LOG(INFO) << logging_tag_ << ": Connection diagnostics started";
}

void Network::StopConnectionDiagnostics() {
  LOG(INFO) << logging_tag_ << ": Connection diagnostics stopping";
  connection_diagnostics_.reset();
}

std::unique_ptr<ConnectionDiagnostics> Network::CreateConnectionDiagnostics(
    const IPAddress& ip_address,
    const IPAddress& gateway,
    const std::vector<std::string>& dns_list) {
  return std::make_unique<ConnectionDiagnostics>(
      interface_name(), interface_index(), ip_address, gateway, dns_list,
      dispatcher_, metrics_, base::DoNothing());
}

void Network::StartConnectivityTest(
    PortalDetector::ProbingConfiguration probe_config) {
  connectivity_test_portal_detector_ = std::make_unique<PortalDetector>(
      dispatcher_, probe_config,
      base::BindRepeating(&Network::ConnectivityTestCallback,
                          weak_factory_.GetWeakPtr(), logging_tag_));
  auto local_addr = local();
  if (!local_addr) {
    LOG(DFATAL) << logging_tag_ << ": Does not have a valid address";
    return;
  }
  if (connectivity_test_portal_detector_->Start(interface_name_, *local_addr,
                                                dns_servers(), logging_tag_)) {
    LOG(WARNING) << logging_tag_ << ": Failed to start connectivity test";
  } else {
    LOG(INFO) << logging_tag_ << ": Started connectivity test";
  }
}

void Network::ConnectivityTestCallback(const std::string& device_logging_tag,
                                       const PortalDetector::Result& result) {
  LOG(INFO) << device_logging_tag
            << ": Completed connectivity test. HTTP probe phase="
            << result.http_phase << ", status=" << result.http_status
            << ". HTTPS probe phase=" << result.https_phase
            << ", status=" << result.https_status;
  connectivity_test_portal_detector_.reset();
}

bool Network::IsConnectedViaTether() const {
  if (!ipconfig_) {
    return false;
  }
  const auto& vendor_option =
      ipconfig_->properties().vendor_encapsulated_options;
  if (vendor_option.size() != strlen(kAndroidMeteredHotspotVendorOption)) {
    return false;
  }
  return memcmp(kAndroidMeteredHotspotVendorOption, vendor_option.data(),
                vendor_option.size()) == 0;
}

bool Network::HasInternetConnectivity() const {
  return network_validation_result_.has_value() &&
         network_validation_result_->GetValidationState() ==
             PortalDetector::ValidationState::kInternetConnectivity;
}

void Network::ReportIPType() {
  const bool has_ipv4 = ipconfig() && !ipconfig()->properties().address.empty();
  const bool has_ipv6 =
      ip6config() && !ip6config()->properties().address.empty();
  Metrics::IPType ip_type = Metrics::kIPTypeUnknown;
  if (has_ipv4 && has_ipv6) {
    ip_type = Metrics::kIPTypeDualStack;
  } else if (has_ipv4) {
    ip_type = Metrics::kIPTypeIPv4Only;
  } else if (has_ipv6) {
    ip_type = Metrics::kIPTypeIPv6Only;
  }
  metrics_->SendEnumToUMA(Metrics::kMetricIPType, technology_, ip_type);
}

}  // namespace shill
