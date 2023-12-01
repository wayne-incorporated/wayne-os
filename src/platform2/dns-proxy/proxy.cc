// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dns-proxy/proxy.h"

#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/types.h>
#include <sysexits.h>
#include <unistd.h>

#include <optional>
#include <set>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/task/single_thread_task_runner.h>
#include <base/time/time.h>
#include <chromeos/patchpanel/message_dispatcher.h>
#include <chromeos/patchpanel/net_util.h>
#include <shill/dbus-constants.h>
#include <shill/net/rtnl_handler.h>

#include "dns-proxy/ipc.pb.h"

// Using directive is necessary to have the overloaded function for socket data
// structure available.
using patchpanel::operator<<;

namespace dns_proxy {
namespace {
// The DoH provider URLs that come from Chrome may be URI templates instead.
// Per https://datatracker.ietf.org/doc/html/rfc8484#section-4.1 these will
// include the {?dns} parameter template for GET requests. These can be safely
// removed since any compliant server must support both GET and POST requests
// and this services only uses POST.
constexpr char kDNSParamTemplate[] = "{?dns}";
std::string TrimParamTemplate(const std::string& url) {
  const size_t pos = url.find(kDNSParamTemplate);
  if (pos == std::string::npos) {
    return url;
  }
  return url.substr(0, pos);
}

Metrics::ProcessType ProcessTypeOf(Proxy::Type t) {
  switch (t) {
    case Proxy::Type::kSystem:
      return Metrics::ProcessType::kProxySystem;
    case Proxy::Type::kDefault:
      return Metrics::ProcessType::kProxyDefault;
    case Proxy::Type::kARC:
      return Metrics::ProcessType::kProxyARC;
    default:
      NOTREACHED();
  }
}
}  // namespace

constexpr base::TimeDelta kShillPropertyAttemptDelay = base::Milliseconds(200);
constexpr base::TimeDelta kRequestTimeout = base::Seconds(10);
constexpr base::TimeDelta kRequestRetryDelay = base::Milliseconds(200);

constexpr char kSystemProxyType[] = "system";
constexpr char kDefaultProxyType[] = "default";
constexpr char kARCProxyType[] = "arc";
constexpr int32_t kRequestMaxRetry = 1;
constexpr uint16_t kDefaultPort = 13568;  // port 53 in network order.

// static
const char* Proxy::TypeToString(Type t) {
  switch (t) {
    case Type::kSystem:
      return kSystemProxyType;
    case Type::kDefault:
      return kDefaultProxyType;
    case Type::kARC:
      return kARCProxyType;
    default:
      NOTREACHED();
  }
}

// static
std::optional<Proxy::Type> Proxy::StringToType(const std::string& s) {
  if (s == kSystemProxyType)
    return Type::kSystem;

  if (s == kDefaultProxyType)
    return Type::kDefault;

  if (s == kARCProxyType)
    return Type::kARC;

  return std::nullopt;
}

std::ostream& operator<<(std::ostream& stream, Proxy::Type type) {
  stream << Proxy::TypeToString(type);
  return stream;
}

std::ostream& operator<<(std::ostream& stream, Proxy::Options opts) {
  stream << "{" << Proxy::TypeToString(opts.type) << ":" << opts.ifname << "}";
  return stream;
}

std::ostream& operator<<(std::ostream& stream, const Proxy& proxy) {
  stream << "{" << Proxy::TypeToString(proxy.opts_.type) << ":";
  if (!proxy.opts_.ifname.empty()) {
    stream << proxy.opts_.ifname;
  } else if (proxy.device_ && !proxy.device_->ifname.empty()) {
    stream << proxy.device_->ifname;
  } else {
    stream << "_";
  }
  return stream << "}";
}

Proxy::Proxy(const Proxy::Options& opts, int32_t fd)
    : opts_(opts), metrics_proc_type_(ProcessTypeOf(opts_.type)) {
  doh_config_.set_logger(
      base::BindRepeating(&Proxy::LogName, weak_factory_.GetWeakPtr()));
  if (opts_.type == Type::kSystem) {
    doh_config_.set_metrics(&metrics_);
    msg_dispatcher_ =
        std::make_unique<patchpanel::MessageDispatcher<ProxyAddrMessage>>(
            base::ScopedFD(fd));
  }

  addr_listener_ = std::make_unique<shill::RTNLListener>(
      shill::RTNLHandler::kRequestAddr,
      base::BindRepeating(&Proxy::RTNLMessageHandler,
                          weak_factory_.GetWeakPtr()));
  shill::RTNLHandler::GetInstance()->Start(RTMGRP_IPV6_IFADDR);
}

// This ctor is only used for testing.
Proxy::Proxy(const Options& opts,
             std::unique_ptr<patchpanel::Client> patchpanel,
             std::unique_ptr<shill::Client> shill,
             std::unique_ptr<patchpanel::MessageDispatcher<ProxyAddrMessage>>
                 msg_dispatcher)
    : opts_(opts),
      patchpanel_(std::move(patchpanel)),
      shill_(std::move(shill)),
      metrics_proc_type_(ProcessTypeOf(opts_.type)) {
  if (opts_.type == Type::kSystem) {
    msg_dispatcher_ = std::move(msg_dispatcher);
  }
}

int Proxy::OnInit() {
  LOG(INFO) << *this << " Starting DNS proxy";

  /// Run after Daemon::OnInit()
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&Proxy::Setup, weak_factory_.GetWeakPtr()));
  return DBusDaemon::OnInit();
}

void Proxy::OnShutdown(int* code) {
  LOG(INFO) << *this << " Stopping DNS proxy (" << *code << ")";
  addr_listener_.reset();
  if (opts_.type == Type::kSystem) {
    ClearShillDNSProxyAddresses();
    ClearIPAddressesInController();
  }
}

void Proxy::Setup() {
  if (!session_) {
    session_ = std::make_unique<SessionMonitor>(bus_);
  }
  session_->RegisterSessionStateHandler(base::BindRepeating(
      &Proxy::OnSessionStateChanged, weak_factory_.GetWeakPtr()));

  if (!patchpanel_)
    patchpanel_ = patchpanel::Client::New(bus_);

  if (!patchpanel_) {
    metrics_.RecordProcessEvent(
        metrics_proc_type_, Metrics::ProcessEvent::kPatchpanelNotInitialized);
    LOG(ERROR) << *this << " Failed to initialize patchpanel client";
    QuitWithExitCode(EX_UNAVAILABLE);
    return;
  }

  patchpanel_->RegisterOnAvailableCallback(base::BindRepeating(
      &Proxy::OnPatchpanelReady, weak_factory_.GetWeakPtr()));
  patchpanel_->RegisterProcessChangedCallback(base::BindRepeating(
      &Proxy::OnPatchpanelReset, weak_factory_.GetWeakPtr()));
}

void Proxy::OnPatchpanelReady(bool success) {
  if (!success) {
    metrics_.RecordProcessEvent(metrics_proc_type_,
                                Metrics::ProcessEvent::kPatchpanelNotReady);
    LOG(ERROR) << *this << " Failed to connect to patchpanel";
    QuitWithExitCode(EX_UNAVAILABLE);
    return;
  }

  // The default network proxy might actually be carrying Chrome, Crostini or
  // if a VPN is on, even ARC traffic, but we attribute this as as "user"
  // sourced.
  patchpanel::Client::TrafficSource traffic_source;
  switch (opts_.type) {
    case Type::kSystem:
      traffic_source = patchpanel::Client::TrafficSource::kSystem;
      break;
    case Type::kARC:
      traffic_source = patchpanel::Client::TrafficSource::kArc;
      break;
    default:
      traffic_source = patchpanel::Client::TrafficSource::kUser;
  }

  // Note that using getpid() here requires that this minijail is not creating a
  // new PID namespace.
  // The default proxy (only) needs to use the VPN, if applicable, the others
  // expressly need to avoid it.
  auto res = patchpanel_->ConnectNamespace(
      getpid(), opts_.ifname, true /* forward_user_traffic */,
      opts_.type == Type::kDefault /* route_on_vpn */, traffic_source);
  if (!res.first.is_valid()) {
    metrics_.RecordProcessEvent(metrics_proc_type_,
                                Metrics::ProcessEvent::kPatchpanelNoNamespace);
    LOG(ERROR) << *this << " Failed to establish private network namespace";
    QuitWithExitCode(EX_CANTCREAT);
    return;
  }
  ns_fd_ = std::move(res.first);
  ns_ = res.second;
  LOG(INFO) << *this << " Successfully connected private network namespace: "
            << ns_.host_ifname << " <--> " << ns_.peer_ifname;

  // Now it's safe to connect shill.
  InitShill();

  // Track single-networked guests' start up and shut down for redirecting
  // traffic to the proxy.
  if (opts_.type == Type::kDefault)
    patchpanel_->RegisterVirtualDeviceEventHandler(base::BindRepeating(
        &Proxy::OnVirtualDeviceChanged, weak_factory_.GetWeakPtr()));
}

void Proxy::StartDnsRedirection(const std::string& ifname,
                                sa_family_t sa_family,
                                const std::vector<std::string>& nameservers) {
  // Request IPv6 DNS redirection rule only if the IPv6 address is available.
  if (sa_family == AF_INET6 && ns_peer_ipv6_address_.empty()) {
    return;
  }

  // Reset last created rules.
  lifeline_fds_.erase(std::make_pair(ifname, sa_family));

  patchpanel::Client::DnsRedirectionRequestType type;
  switch (opts_.type) {
    case Type::kSystem:
      type = patchpanel::Client::DnsRedirectionRequestType::kExcludeDestination;
      break;
    case Type::kDefault:
      type = patchpanel::Client::DnsRedirectionRequestType::kDefault;
      // If |ifname| is empty, request SetDnsRedirectionRule rule for USER.
      if (ifname.empty()) {
        type = patchpanel::Client::DnsRedirectionRequestType::kUser;
      }
      break;
    case Type::kARC:
      type = patchpanel::Client::DnsRedirectionRequestType::kArc;
      break;
    default:
      LOG(DFATAL) << *this << " Unexpected proxy type " << opts_.type;
      return;
  }

  const auto& peer_addr = sa_family == AF_INET6
                              ? ns_peer_ipv6_address_
                              : ns_.peer_ipv4_address.ToString();
  auto fd = patchpanel_->RedirectDns(type, ifname, peer_addr, nameservers,
                                     ns_.host_ifname);
  // Restart the proxy if DNS redirection rules are failed to be set up. This
  // is necessary because when DNS proxy is running, /etc/resolv.conf is
  // replaced by the IP address of system proxy. This causes non-system traffic
  // to be routed incorrectly without the redirection rules.
  if (!fd.is_valid()) {
    metrics_.RecordProcessEvent(metrics_proc_type_,
                                Metrics::ProcessEvent::kPatchpanelNoRedirect);
    LOG(ERROR) << *this << " Failed to start DNS redirection";
    QuitWithExitCode(EX_CONFIG);
    return;
  }
  lifeline_fds_.emplace(std::make_pair(ifname, sa_family), std::move(fd));
}

void Proxy::StopDnsRedirection(const std::string& ifname,
                               sa_family_t sa_family) {
  lifeline_fds_.erase(std::make_pair(ifname, sa_family));
}

void Proxy::OnPatchpanelReset(bool reset) {
  if (reset) {
    metrics_.RecordProcessEvent(metrics_proc_type_,
                                Metrics::ProcessEvent::kPatchpanelReset);
    LOG(WARNING) << *this << " Patchpanel has been reset";
    return;
  }

  // If patchpanel crashes, the proxy is useless since the connected virtual
  // network is gone. So the best bet is to exit and have the controller restart
  // us. Note if this is the system proxy, it will inform shill on shutdown.
  metrics_.RecordProcessEvent(metrics_proc_type_,
                              Metrics::ProcessEvent::kPatchpanelShutdown);
  LOG(ERROR) << *this << " Patchpanel has been shutdown - restarting DNS proxy";
  QuitWithExitCode(EX_UNAVAILABLE);
}

void Proxy::InitShill() {
  // shill_ should always be null unless a test has injected a client.
  if (!shill_)
    shill_.reset(new shill::Client(bus_));

  shill_->RegisterOnAvailableCallback(
      base::BindOnce(&Proxy::OnShillReady, weak_factory_.GetWeakPtr()));
  shill_->RegisterProcessChangedHandler(
      base::BindRepeating(&Proxy::OnShillReset, weak_factory_.GetWeakPtr()));
}

void Proxy::OnShillReady(bool success) {
  shill_ready_ = success;
  if (!shill_ready_) {
    metrics_.RecordProcessEvent(metrics_proc_type_,
                                Metrics::ProcessEvent::kShillNotReady);
    LOG(ERROR) << *this << " Failed to connect to shill";
    QuitWithExitCode(EX_UNAVAILABLE);
    return;
  }

  shill_->RegisterDefaultDeviceChangedHandler(base::BindRepeating(
      &Proxy::OnDefaultDeviceChanged, weak_factory_.GetWeakPtr()));
  shill_->RegisterDeviceChangedHandler(
      base::BindRepeating(&Proxy::OnDeviceChanged, weak_factory_.GetWeakPtr()));
  if (opts_.type == Proxy::Type::kARC) {
    for (const auto& d : shill_->GetDevices()) {
      OnDeviceChanged(d.get());
    }
  }
}

void Proxy::OnShillReset(bool reset) {
  if (reset) {
    metrics_.RecordProcessEvent(metrics_proc_type_,
                                Metrics::ProcessEvent::kShillReset);
    LOG(WARNING) << *this << " Shill has been reset";

    // If applicable, restore the address of the system proxy.
    if (opts_.type == Type::kSystem && ns_fd_.is_valid()) {
      SetShillDNSProxyAddresses(ns_.peer_ipv4_address.ToString(),
                                ns_peer_ipv6_address_);
      // Start DNS redirection rule to exclude traffic with destination not
      // equal to the underlying name server.
      StartDnsRedirection("" /* ifname */, AF_INET);
      StartDnsRedirection("" /* ifname */, AF_INET6);
    }

    return;
  }

  metrics_.RecordProcessEvent(metrics_proc_type_,
                              Metrics::ProcessEvent::kShillShutdown);
  LOG(WARNING) << *this << " Shill has been shutdown";
  shill_ready_ = false;
  shill_props_.reset();
  shill_.reset();
  InitShill();
}

void Proxy::OnSessionStateChanged(bool login) {
  if (login) {
    LOG(INFO) << *this << " Service enabled by user login";
    Enable();
    return;
  }

  LOG(INFO) << *this << " Service disabled by user logout";
  Disable();
}

void Proxy::Enable() {
  if (!ns_fd_.is_valid() || !device_)
    return;

  if (opts_.type == Type::kSystem) {
    SetShillDNSProxyAddresses(ns_.peer_ipv4_address.ToString(),
                              ns_peer_ipv6_address_);
    SendIPAddressesToController(ns_.peer_ipv4_address.ToString(),
                                ns_peer_ipv6_address_);
    // Start DNS redirection rule to exclude traffic with destination not equal
    // to the underlying name server.
    StartDnsRedirection("" /* ifname */, AF_INET);
    StartDnsRedirection("" /* ifname */, AF_INET6);
    return;
  }

  if (opts_.type == Type::kDefault) {
    // Start DNS redirection rule for user traffic (cups, chronos, update
    // engine, etc).
    StartDnsRedirection("" /* ifname */, AF_INET,
                        doh_config_.ipv4_nameservers());
    StartDnsRedirection("" /* ifname */, AF_INET6,
                        doh_config_.ipv6_nameservers());
  }

  // Process the current set of patchpanel devices and add necessary
  // redirection rules.
  for (const auto& d : patchpanel_->GetDevices()) {
    StartGuestDnsRedirection(d, AF_INET);
    StartGuestDnsRedirection(d, AF_INET6);
  }
}

void Proxy::Disable() {
  if (opts_.type == Type::kSystem && ns_fd_.is_valid()) {
    ClearShillDNSProxyAddresses();
    ClearIPAddressesInController();
  }
  // Teardown DNS redirection rules.
  lifeline_fds_.clear();
}

void Proxy::Stop() {
  doh_config_.clear();
  resolver_.reset();
  device_.reset();
  lifeline_fds_.clear();
  if (opts_.type == Type::kSystem) {
    ClearShillDNSProxyAddresses();
    ClearIPAddressesInController();
  }
}

std::unique_ptr<Resolver> Proxy::NewResolver(base::TimeDelta timeout,
                                             base::TimeDelta retry_delay,
                                             int max_num_retries) {
  return std::make_unique<Resolver>(
      base::BindRepeating(&Proxy::LogName, weak_factory_.GetWeakPtr()), timeout,
      retry_delay, max_num_retries);
}

void Proxy::OnDefaultDeviceChanged(const shill::Client::Device* const device) {
  // ARC proxies will handle changes to their network in OnDeviceChanged.
  if (opts_.type == Proxy::Type::kARC)
    return;

  // Default service is either not ready yet or has just disconnected.
  if (!device) {
    // If it disconnected, shutdown the resolver.
    if (device_) {
      LOG(WARNING) << *this
                   << " is stopping because there is no default service";
      Stop();
    }
    return;
  }

  shill::Client::Device new_default_device = *device;

  // The system proxy should ignore when a VPN is turned on as it must continue
  // to work with the underlying physical interface.
  if (opts_.type == Proxy::Type::kSystem &&
      device->type == shill::Client::Device::Type::kVPN) {
    if (device_)
      return;

    // No device means that the system proxy has started up with a VPN as the
    // default network; which means we need to dig out the physical network
    // device and use that from here forward.
    auto dd = shill_->DefaultDevice(true /* exclude_vpn */);
    if (!dd) {
      LOG(ERROR) << *this << " No default non-VPN device found";
      return;
    }
    new_default_device = *dd.get();
  }

  // While this is enforced in shill as well, only enable resolution if the
  // service online.
  if (new_default_device.state !=
      shill::Client::Device::ConnectionState::kOnline) {
    if (device_) {
      LOG(WARNING) << *this << " is stopping because the default device ["
                   << new_default_device.ifname << "] is offline";
      Stop();
    }
    return;
  }

  if (!device_)
    device_ = std::make_unique<shill::Client::Device>();

  // The default network has changed.
  if (new_default_device.ifname != device_->ifname)
    LOG(INFO) << *this << " is now tracking [" << new_default_device.ifname
              << "]";

  *device_.get() = new_default_device;
  MaybeCreateResolver();
  UpdateNameServers(device_->ipconfig);

  // For the default proxy, we have to update DNS redirection rule. This allows
  // DNS traffic to be redirected to the proxy.
  if (opts_.type == Type::kDefault) {
    // Start DNS redirection rule for user traffic (cups, chronos, update
    // engine, etc).
    StartDnsRedirection("" /* ifname */, AF_INET,
                        doh_config_.ipv4_nameservers());
    StartDnsRedirection("" /* ifname */, AF_INET6,
                        doh_config_.ipv6_nameservers());
    // Process the current set of patchpanel devices and add necessary
    // redirection rules.
    for (const auto& d : patchpanel_->GetDevices()) {
      StartGuestDnsRedirection(d, AF_INET);
      StartGuestDnsRedirection(d, AF_INET6);
    }
  }

  // For the system proxy, we have to tell shill about it. We should start
  // receiving DNS traffic on success. But if this fails, we don't have much
  // choice but to just crash out and try again.
  if (opts_.type == Type::kSystem) {
    SetShillDNSProxyAddresses(ns_.peer_ipv4_address.ToString(),
                              ns_peer_ipv6_address_, true /* die_on_failure */);
    SendIPAddressesToController(ns_.peer_ipv4_address.ToString(),
                                ns_peer_ipv6_address_);
    // Start DNS redirection rule to exclude traffic with destination not equal
    // to the underlying name server.
    StartDnsRedirection("" /* ifname */, AF_INET);
    StartDnsRedirection("" /* ifname */, AF_INET6);
  }
}

shill::Client::ManagerPropertyAccessor* Proxy::shill_props() {
  if (!shill_props_) {
    shill_props_ = shill_->ManagerProperties();
    shill_props_->Watch(shill::kDNSProxyDOHProvidersProperty,
                        base::BindRepeating(&Proxy::OnDoHProvidersChanged,
                                            weak_factory_.GetWeakPtr()));
  }

  return shill_props_.get();
}

void Proxy::OnDeviceChanged(const shill::Client::Device* const device) {
  if (!device || (device_ && device_->ifname != device->ifname))
    return;

  switch (opts_.type) {
    case Type::kDefault:
      // We don't need to worry about this here since the default proxy
      // always/only tracks the default device and any update will be handled by
      // OnDefaultDeviceChanged.
      return;

    case Type::kSystem:
      if (!device_ || device_->ipconfig == device->ipconfig)
        return;

      UpdateNameServers(device->ipconfig);
      device_->ipconfig = device->ipconfig;
      return;

    case Type::kARC:
      if (opts_.ifname != device->ifname)
        return;

      if (device->state != shill::Client::Device::ConnectionState::kOnline) {
        if (device_) {
          LOG(WARNING) << *this << " is stopping because the device ["
                       << device->ifname << "] is offline";
          Stop();
        }
        return;
      }

      if (!device_) {
        device_ = std::make_unique<shill::Client::Device>();
      }

      *device_.get() = *device;
      MaybeCreateResolver();
      UpdateNameServers(device->ipconfig);

      // Process the current set of patchpanel devices and add necessary
      // redirection rules.
      for (const auto& d : patchpanel_->GetDevices()) {
        StartGuestDnsRedirection(d, AF_INET);
        StartGuestDnsRedirection(d, AF_INET6);
      }
      break;

    default:
      NOTREACHED();
  }
}

void Proxy::MaybeCreateResolver() {
  if (resolver_)
    return;

  resolver_ =
      NewResolver(kRequestTimeout, kRequestRetryDelay, kRequestMaxRetry);
  doh_config_.set_resolver(resolver_.get());

  // Listen on IPv4 and IPv6. Listening on AF_INET explicitly is not needed
  // because net.ipv6.bindv6only sysctl is defaulted to 0 and is not
  // explicitly turned on in the codebase.
  struct sockaddr_in6 addr = {0};
  addr.sin6_family = AF_INET6;
  addr.sin6_port = kDefaultPort;
  addr.sin6_addr =
      in6addr_any;  // Since we're running in the private namespace.

  if (!resolver_->ListenUDP(reinterpret_cast<struct sockaddr*>(&addr))) {
    metrics_.RecordProcessEvent(
        metrics_proc_type_, Metrics::ProcessEvent::kResolverListenUDPFailure);
    LOG(ERROR) << *this << " failed to start UDP relay loop";
    QuitWithExitCode(EX_IOERR);
    return;
  }

  if (!resolver_->ListenTCP(reinterpret_cast<struct sockaddr*>(&addr))) {
    metrics_.RecordProcessEvent(
        metrics_proc_type_, Metrics::ProcessEvent::kResolverListenTCPFailure);
    LOG(DFATAL) << *this << " failed to start TCP relay loop";
  }

  // Fetch the DoH settings.
  brillo::ErrorPtr error;
  brillo::VariantDictionary doh_providers;
  if (shill_props()->Get(shill::kDNSProxyDOHProvidersProperty, &doh_providers,
                         &error)) {
    OnDoHProvidersChanged(brillo::Any(doh_providers));
  } else {
    // Only log this metric in the system proxy to avoid replicating the data.
    if (opts_.type == Type::kSystem) {
      metrics_.RecordDnsOverHttpsMode(Metrics::DnsOverHttpsMode::kUnknown);
    }
    LOG(ERROR) << *this << " failed to obtain DoH configuration from shill: "
               << error->GetMessage();
  }
}

void Proxy::UpdateNameServers(const shill::Client::IPConfig& ipconfig) {
  std::vector<std::string> ipv4_nameservers;
  std::vector<std::string> ipv6_nameservers;

  auto maybe_add_to_ipv6_nameservers = [&](const std::string& addr) {
    struct in6_addr addr6;
    if (inet_pton(AF_INET6, addr.c_str(), &addr6.s6_addr) == 1 &&
        memcmp(&addr6, &in6addr_any, sizeof(in6_addr)) != 0) {
      ipv6_nameservers.push_back(addr);
    }
  };

  // Validate name servers.
  for (const auto& addr : ipconfig.ipv4_dns_addresses) {
    struct in_addr addr4;
    // Shill sometimes adds 0.0.0.0 for some reason - so strip any if so.
    if (inet_pton(AF_INET, addr.c_str(), &addr4) == 1 &&
        addr4.s_addr != INADDR_ANY) {
      ipv4_nameservers.push_back(addr);
      continue;
    }
    // When IPv6 nameservers are set from the UI, it will be stored inside
    // IPConfig's IPv4 DNS addresses.
    maybe_add_to_ipv6_nameservers(addr);
  }

  for (const auto& addr : ipconfig.ipv6_dns_addresses) {
    maybe_add_to_ipv6_nameservers(addr);
  }

  if (ipv4_nameservers.empty() && ipv6_nameservers.empty()) {
    LOG(WARNING) << *this << " has empty name servers";
  }

  doh_config_.set_nameservers(ipv4_nameservers, ipv6_nameservers);
  metrics_.RecordNameservers(doh_config_.ipv4_nameservers().size(),
                             doh_config_.ipv6_nameservers().size());
  LOG(INFO) << *this << " applied device DNS configuration";
}

void Proxy::OnDoHProvidersChanged(const brillo::Any& value) {
  // When VPN is enabled, DoH must be disabled on default proxy to ensure that
  // the behavior between different types of VPNs are the same.
  // When the VPN is turned off, the resolver will be re-created and the DoH
  // config will be re-populated.
  if (opts_.type == Type::kDefault && device_ &&
      device_->type == shill::Client::Device::Type::kVPN) {
    doh_config_.set_providers(brillo::VariantDictionary());
    return;
  }
  doh_config_.set_providers(value.Get<brillo::VariantDictionary>());
}

void Proxy::SetShillDNSProxyAddresses(const std::string& ipv4_addr,
                                      const std::string& ipv6_addr,
                                      bool die_on_failure,
                                      uint8_t num_retries) {
  if (opts_.type != Type::kSystem) {
    LOG(DFATAL) << *this << " " << __func__
                << " must be called from system proxy only";
    return;
  }

  if (num_retries == 0) {
    metrics_.RecordProcessEvent(
        metrics_proc_type_,
        Metrics::ProcessEvent::kShillSetProxyAddressRetryExceeded);
    LOG(ERROR) << *this << " Maximum number of retries exceeding attempt to"
               << " set dns-proxy address property on shill";

    if (die_on_failure)
      QuitWithExitCode(EX_UNAVAILABLE);

    return;
  }

  // If doesn't ever come back, there is no point in retrying here; and
  // if it does, then initialization process will eventually come back
  // into this function and succeed.
  if (!shill_ready_) {
    LOG(WARNING) << *this
                 << " No connection to shill - cannot set dns-proxy address "
                    "property IPv4 ["
                 << ipv4_addr << "], IPv6 [" << ipv6_addr << "]";
    return;
  }

  std::vector<std::string> addrs;
  if (!ipv4_addr.empty() && !doh_config_.ipv4_nameservers().empty()) {
    addrs.push_back(ipv4_addr);
  }
  if (!ipv6_addr.empty() && !doh_config_.ipv6_nameservers().empty()) {
    addrs.push_back(ipv6_addr);
  }
  if (addrs.empty()) {
    shill_->GetManagerProxy()->ClearDNSProxyAddresses(nullptr /* error */);
    LOG(INFO) << *this << " Successfully cleared dns-proxy address property";
    return;
  }

  brillo::ErrorPtr error;
  if (shill_->GetManagerProxy()->SetDNSProxyAddresses(addrs, &error)) {
    LOG(INFO) << *this << " Successfully set dns-proxy address property ["
              << base::JoinString(addrs, ",") << "]";
    return;
  }

  LOG(ERROR) << *this << " Failed to set dns-proxy address property ["
             << base::JoinString(addrs, ",")
             << "] on shill: " << error->GetMessage() << ". Retrying...";

  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&Proxy::SetShillDNSProxyAddresses,
                     weak_factory_.GetWeakPtr(), ipv4_addr, ipv6_addr,
                     die_on_failure, num_retries - 1),
      kShillPropertyAttemptDelay);
}

void Proxy::ClearShillDNSProxyAddresses() {
  SetShillDNSProxyAddresses("" /* ipv4_address */, "" /* ipv6_address */);
}

void Proxy::SendIPAddressesToController(const std::string& ipv4_addr,
                                        const std::string& ipv6_addr) {
  if (opts_.type != Type::kSystem) {
    LOG(DFATAL) << *this << " Must be called from system proxy only";
    return;
  }

  ProxyAddrMessage msg;
  msg.set_type(ProxyAddrMessage::SET_ADDRS);
  if (!ipv4_addr.empty() && !doh_config_.ipv4_nameservers().empty()) {
    msg.add_addrs(ipv4_addr);
  }
  if (!ipv6_addr.empty() && !doh_config_.ipv6_nameservers().empty()) {
    msg.add_addrs(ipv6_addr);
  }

  // Don't send empty proxy address.
  if (msg.addrs().empty()) {
    return;
  }

  SendProtoMessage(msg);
}

void Proxy::ClearIPAddressesInController() {
  ProxyAddrMessage msg;
  msg.set_type(ProxyAddrMessage::CLEAR_ADDRS);
  SendProtoMessage(msg);
}

void Proxy::SendProtoMessage(const ProxyAddrMessage& msg) {
  if (msg_dispatcher_->SendMessage(msg)) {
    return;
  }
  LOG(ERROR) << *this << " Failed to set IP addresses to controller";
  // This might be caused by the file descriptor getting invalidated. Quit the
  // process to let the controller restart the proxy. Restarting allows a new
  // clean state.
  Quit();
}

const std::vector<std::string>& Proxy::DoHConfig::ipv4_nameservers() {
  return ipv4_nameservers_;
}

const std::vector<std::string>& Proxy::DoHConfig::ipv6_nameservers() {
  return ipv6_nameservers_;
}

void Proxy::DoHConfig::set_resolver(Resolver* resolver) {
  resolver_ = resolver;
  update();
}

void Proxy::DoHConfig::set_nameservers(
    const std::vector<std::string>& ipv4_nameservers,
    const std::vector<std::string>& ipv6_nameservers) {
  ipv4_nameservers_ = ipv4_nameservers;
  ipv6_nameservers_ = ipv6_nameservers;
  update();
}

void Proxy::DoHConfig::set_providers(
    const brillo::VariantDictionary& providers) {
  secure_providers_.clear();
  auto_providers_.clear();

  if (providers.empty()) {
    if (metrics_) {
      metrics_->RecordDnsOverHttpsMode(Metrics::DnsOverHttpsMode::kOff);
    }
    LOG(INFO) << *this << " DoH: off";
    update();
    return;
  }

  for (const auto& [endpoint, value] : providers) {
    // We expect that in secure, always-on to find one (or more) endpoints with
    // no nameservers.
    const auto nameservers = value.TryGet<std::string>("");
    if (nameservers.empty()) {
      secure_providers_.insert(TrimParamTemplate(endpoint));
      continue;
    }

    // Remap nameserver -> secure endpoint so we can quickly determine if DoH
    // should be attempted when the name servers change.
    for (const auto& ns :
         base::SplitString(nameservers, ",", base::TRIM_WHITESPACE,
                           base::SPLIT_WANT_NONEMPTY)) {
      auto_providers_[ns] = TrimParamTemplate(endpoint);
    }
  }

  // If for some reason, both collections are non-empty, prefer the automatic
  // upgrade configuration.
  if (!auto_providers_.empty()) {
    secure_providers_.clear();
    if (metrics_) {
      metrics_->RecordDnsOverHttpsMode(Metrics::DnsOverHttpsMode::kAutomatic);
    }
    LOG(INFO) << *this << " DoH: automatic";
  }
  if (!secure_providers_.empty()) {
    if (metrics_) {
      metrics_->RecordDnsOverHttpsMode(Metrics::DnsOverHttpsMode::kAlwaysOn);
    }
    LOG(INFO) << *this << " DoH: always-on";
  }
  update();
}

void Proxy::DoHConfig::update() {
  if (!resolver_)
    return;

  std::vector<std::string> nameservers = ipv4_nameservers_;
  nameservers.insert(nameservers.end(), ipv6_nameservers_.begin(),
                     ipv6_nameservers_.end());
  resolver_->SetNameServers(nameservers);

  std::set<std::string> doh_providers;
  bool doh_always_on = false;
  if (!secure_providers_.empty()) {
    doh_providers = secure_providers_;
    doh_always_on = true;
  } else if (!auto_providers_.empty()) {
    for (const auto& ns : nameservers) {
      const auto it = auto_providers_.find(ns);
      if (it != auto_providers_.end()) {
        doh_providers.emplace(it->second);
      }
    }
  }

  resolver_->SetDoHProviders(
      std::vector(doh_providers.begin(), doh_providers.end()), doh_always_on);
}

void Proxy::DoHConfig::clear() {
  resolver_ = nullptr;
  secure_providers_.clear();
  auto_providers_.clear();
}

void Proxy::DoHConfig::set_metrics(Metrics* metrics) {
  metrics_ = metrics;
}

void Proxy::DoHConfig::set_logger(Proxy::Logger logger) {
  logger_ = std::move(logger);
}

void Proxy::RTNLMessageHandler(const shill::RTNLMessage& msg) {
  // Listen only for global or site-local IPv6 address changes.
  if (msg.address_status().scope != RT_SCOPE_UNIVERSE &&
      msg.address_status().scope != RT_SCOPE_SITE) {
    return;
  }

  // Listen only for the peer interface IPv6 changes.
  if (msg.interface_index() != if_nametoindex(ns_.peer_ifname.c_str())) {
    return;
  }

  switch (msg.mode()) {
    case shill::RTNLMessage::kModeAdd: {
      std::string peer_ipv6_addr;
      if (const auto tmp_addr = msg.GetIfaAddress(); tmp_addr.has_value()) {
        peer_ipv6_addr = tmp_addr->ToString();
      } else {
        LOG(ERROR) << *this << " IFA_ADDRESS in RTNL message is invalid";
        return;
      }
      if (ns_peer_ipv6_address_ == peer_ipv6_addr) {
        return;
      }
      ns_peer_ipv6_address_ = peer_ipv6_addr;
      if (opts_.type == Type::kDefault && device_) {
        StartDnsRedirection("" /* ifname */, AF_INET6,
                            doh_config_.ipv6_nameservers());
      }
      for (const auto& d : patchpanel_->GetDevices()) {
        StartGuestDnsRedirection(d, AF_INET6);
      }
      if (opts_.type == Type::kSystem && device_) {
        SetShillDNSProxyAddresses(ns_.peer_ipv4_address.ToString(),
                                  ns_peer_ipv6_address_);
        SendIPAddressesToController(ns_.peer_ipv4_address.ToString(),
                                    ns_peer_ipv6_address_);
        StartDnsRedirection("" /* ifname */, AF_INET6);
      }
      return;
    }
    case shill::RTNLMessage::kModeDelete:
      ns_peer_ipv6_address_.clear();
      if (opts_.type == Type::kDefault) {
        StopDnsRedirection("" /* ifname */, AF_INET6);
      }
      for (const auto& d : patchpanel_->GetDevices()) {
        StopGuestDnsRedirection(d, AF_INET6);
      }
      if (opts_.type == Type::kSystem && device_) {
        SetShillDNSProxyAddresses(ns_.peer_ipv4_address.ToString(), "");
        SendIPAddressesToController(ns_.peer_ipv4_address.ToString(), "");
        StopDnsRedirection("" /* ifname */, AF_INET6);
      }
      return;
    default:
      return;
  }
}

void Proxy::OnVirtualDeviceChanged(
    patchpanel::Client::VirtualDeviceEvent event,
    const patchpanel::Client::VirtualDevice& device) {
  switch (event) {
    case patchpanel::Client::VirtualDeviceEvent::kAdded:
      StartGuestDnsRedirection(device, AF_INET);
      StartGuestDnsRedirection(device, AF_INET6);
      break;
    case patchpanel::Client::VirtualDeviceEvent::kRemoved:
      StopGuestDnsRedirection(device, AF_INET);
      StopGuestDnsRedirection(device, AF_INET6);
      break;
    default:
      NOTREACHED();
  }
}

void Proxy::StartGuestDnsRedirection(
    const patchpanel::Client::VirtualDevice& device, sa_family_t sa_family) {
  if (!device_ ||
      base::Contains(lifeline_fds_, std::make_pair(device.ifname, sa_family))) {
    return;
  }

  switch (device.guest_type) {
    case patchpanel::Client::GuestType::kTerminaVm:
    case patchpanel::Client::GuestType::kParallelsVm:
      if (opts_.type == Type::kDefault) {
        StartDnsRedirection(device.ifname, sa_family);
      }
      return;
    case patchpanel::Client::GuestType::kArcContainer:
    case patchpanel::Client::GuestType::kArcVm:
      if (opts_.type == Type::kARC && opts_.ifname == device.phys_ifname) {
        StartDnsRedirection(device.ifname, sa_family);
      }
      return;
    default:
      return;
  }
}

void Proxy::StopGuestDnsRedirection(
    const patchpanel::Client::VirtualDevice& device, sa_family_t sa_family) {
  switch (device.guest_type) {
    case patchpanel::Client::GuestType::kTerminaVm:
    case patchpanel::Client::GuestType::kParallelsVm:
      if (opts_.type == Type::kDefault) {
        StopDnsRedirection(device.ifname, sa_family);
      }
      return;
    default:
      // For ARC, upon removal of the virtual device, the corresponding proxy
      // will also be removed. This will undo the created firewall rules.
      // However, if IPv6 is removed, firewall rules created need to be
      // removed.
      if (opts_.type == Type::kARC && opts_.ifname == device.phys_ifname) {
        StopDnsRedirection(device.ifname, sa_family);
      }
      return;
  }
}

void Proxy::LogName(std::ostream& stream) const {
  stream << *this;
}

}  // namespace dns_proxy
