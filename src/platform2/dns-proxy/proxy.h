// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DNS_PROXY_PROXY_H_
#define DNS_PROXY_PROXY_H_

#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <base/files/scoped_file.h>
#include <brillo/daemons/dbus_daemon.h>
#include <chromeos/patchpanel/dbus/client.h>
#include <chromeos/patchpanel/message_dispatcher.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST
#include <shill/dbus/client/client.h>
#include <shill/net/byte_string.h>
#include <shill/net/rtnl_listener.h>

#include "dns-proxy/ipc.pb.h"
#include "dns-proxy/metrics.h"
#include "dns-proxy/resolver.h"
#include "dns-proxy/session_monitor.h"

namespace dns_proxy {

// The process that runs the actual proxying code.
class Proxy : public brillo::DBusDaemon {
 public:
  enum class Type { kSystem, kDefault, kARC };

  struct Options {
    Type type;
    // Required for ARC proxies as it specifies which physical interface
    // should (always) be tracked. This field is ignored (but should be empty)
    // for the system and default network proxies.
    std::string ifname;
  };

  using Logger = base::RepeatingCallback<void(std::ostream& stream)>;

  Proxy(const Options& opts, int32_t fd);
  // For testing.
  Proxy(const Options& opts,
        std::unique_ptr<patchpanel::Client> patchpanel,
        std::unique_ptr<shill::Client> shill,
        std::unique_ptr<patchpanel::MessageDispatcher<ProxyAddrMessage>>
            msg_dispatcher);
  Proxy(const Proxy&) = delete;
  Proxy& operator=(const Proxy&) = delete;
  ~Proxy() = default;

  static const char* TypeToString(Type t);
  static std::optional<Type> StringToType(const std::string& s);
  friend std::ostream& operator<<(std::ostream& stream, const Proxy& proxy);

 protected:
  int OnInit() override;
  void OnShutdown(int*) override;

  // Added for testing.
  virtual std::unique_ptr<Resolver> NewResolver(base::TimeDelta timeout,
                                                base::TimeDelta retry_delay,
                                                int max_num_retries);

 private:
  static const uint8_t kMaxShillPropertyRetries = 10;

  // Helper for parsing and applying shill's DNSProxyDOHProviders property.
  class DoHConfig {
   public:
    DoHConfig() = default;
    DoHConfig(const DoHConfig&) = delete;
    DoHConfig& operator=(const DoHConfig&) = delete;
    ~DoHConfig() = default;

    // Get the name servers the network of the proxy is tracking.
    const std::vector<std::string>& ipv4_nameservers();
    const std::vector<std::string>& ipv6_nameservers();

    // Stores the resolver to configure whenever settings are updated.
    void set_resolver(Resolver* resolver);

    // |ipv4_nameservers| and |ipv6_nameservers| are the list of name servers
    // for the network the proxy is tracking.
    void set_nameservers(const std::vector<std::string>& ipv4_nameservers,
                         const std::vector<std::string>& ipv6_nameservers);

    // |settings| is the DoH providers property we get from shill. It keys, as
    // applicable, secure DNS provider endpoints to standard DNS name servers.
    void set_providers(const brillo::VariantDictionary& providers);

    void clear();

    void set_metrics(Metrics* metrics);
    void set_logger(Logger logger);

    friend std::ostream& operator<<(std::ostream& stream,
                                    const DoHConfig& config) {
      if (config.logger_) {
        config.logger_.Run(stream);
      }
      return stream;
    }

   private:
    void update();

    Resolver* resolver_{nullptr};
    Logger logger_;
    std::vector<std::string> ipv4_nameservers_;
    std::vector<std::string> ipv6_nameservers_;
    // If non-empty, the secure providers to use for always-on DoH.
    std::set<std::string> secure_providers_;
    // If non-empty, maps name servers to secure DNS providers, for automatic
    // update.
    std::map<std::string, std::string> auto_providers_;

    Metrics* metrics_{nullptr};
  };

  void Setup();
  void OnPatchpanelReady(bool success);
  void OnPatchpanelReset(bool reset);

  void InitShill();
  void OnShillReady(bool success);
  void OnShillReset(bool reset);

  // Triggered by the session monitor whenever the user logs in or out.
  void OnSessionStateChanged(bool login);

  void Enable();
  void Disable();

  // Stops DNS proxy from proxying DNS queries. This is run whenever the device
  // is not yet online.
  void Stop();

  // Start and stop DNS redirection rules by querying patchpanel's API. This is
  // necessary to route corresponding DNS traffic to the DNS proxy.
  // |sa_family| values will be either AF_INET or AF_INET6, for IPv4 and IPv6
  // respectively.
  // Calls from each DNS proxy types will result in a different rule:
  // - System:
  //   Rules to exclude traffic that is not using the underlying name
  //   server (EXCLUDE_DESTINATION).
  // - Default:
  //   If |ifname| is empty, rules to redirect user traffic to the proxy
  //   (USER).
  //   If |ifname| is not empty, rules to redirect guests that track default
  //   network to the proxy (DEFAULT).
  // - ARC:
  //   Rules to redirect ARC traffic to the proxy (ARC).
  void StartDnsRedirection(
      const std::string& ifname,
      sa_family_t sa_family,
      const std::vector<std::string>& nameservers = std::vector<std::string>());
  void StopDnsRedirection(const std::string& ifname, sa_family_t sa_family);

  // Triggered whenever the device attached to the default network changes.
  // |device| can be null and indicates the default service is disconnected.
  void OnDefaultDeviceChanged(const shill::Client::Device* const device);
  void OnDeviceChanged(const shill::Client::Device* const device);

  void MaybeCreateResolver();
  void UpdateNameServers(const shill::Client::IPConfig& ipconfig);

  // Update DoH providers. If proxy is the default proxy and VPN is connected,
  // DoH is disabled. Force the provider to always be empty.
  void OnDoHProvidersChanged(const brillo::Any& value);

  // Notified by patchpanel whenever a change occurs in one of its virtual
  // network devices.
  void OnVirtualDeviceChanged(patchpanel::Client::VirtualDeviceEvent event,
                              const patchpanel::Client::VirtualDevice& device);

  // Start and stop DNS redirection rules upon virtual device changed.
  void StartGuestDnsRedirection(const patchpanel::Client::VirtualDevice& device,
                                sa_family_t sa_family);
  void StopGuestDnsRedirection(const patchpanel::Client::VirtualDevice& device,
                               sa_family_t sa_family);

  // Helper func for setting the dns-proxy IPv4 and IPv6 address in shill.
  // Only valid for the system proxy.
  // Will retry on failure up to |num_retries| before possibly crashing the
  // proxy.
  void SetShillDNSProxyAddresses(
      const std::string& ipv4_addr,
      const std::string& ipv6_addr,
      bool die_on_failure = false,
      uint8_t num_retries = kMaxShillPropertyRetries);
  void ClearShillDNSProxyAddresses();

  // Helper func to send the proxy IP addresses to the controller.
  // Only valid for the system proxy.
  void SendIPAddressesToController(const std::string& ipv4_addr,
                                   const std::string& ipv6_addr);
  void ClearIPAddressesInController();
  void SendProtoMessage(const ProxyAddrMessage& msg);

  // Callback from RTNetlink listener, invoked when the lan interface IPv6
  // address is changed.
  void RTNLMessageHandler(const shill::RTNLMessage& msg);

  void LogName(std::ostream& stream) const;

  // Return the property accessor, creating it if needed.
  shill::Client::ManagerPropertyAccessor* shill_props();

  FRIEND_TEST(ProxyTest, SystemProxy_OnShutdownClearsAddressPropertyOnShill);
  FRIEND_TEST(ProxyTest, NonSystemProxy_OnShutdownDoesNotCallShill);
  FRIEND_TEST(ProxyTest,
              SystemProxy_SetShillDNSProxyAddressesWithNoRetriesCrashes);
  FRIEND_TEST(ProxyTest,
              SystemProxy_SetShillDNSProxyAddressesDoesntCrashIfDieFalse);
  FRIEND_TEST(ProxyTest, SystemProxy_SetShillDNSProxyAddresses);
  FRIEND_TEST(ProxyTest, SystemProxy_SetShillDNSProxyAddressesEmptyNameserver);
  FRIEND_TEST(ProxyTest, SystemProxy_ClearShillDNSProxyAddresses);
  FRIEND_TEST(ProxyTest, SystemProxy_SendIPAddressesToController);
  FRIEND_TEST(ProxyTest,
              SystemProxy_SendIPAddressesToControllerEmptyNameserver);
  FRIEND_TEST(ProxyTest, SystemProxy_ClearIPAddressesInController);
  FRIEND_TEST(ProxyTest, ShillInitializedWhenReady);
  FRIEND_TEST(ProxyTest, SystemProxy_ConnectedNamedspace);
  FRIEND_TEST(ProxyTest, DefaultProxy_ConnectedNamedspace);
  FRIEND_TEST(ProxyTest, ArcProxy_ConnectedNamedspace);
  FRIEND_TEST(ProxyTest, CrashOnConnectNamespaceFailure);
  FRIEND_TEST(ProxyTest, CrashOnPatchpanelNotReady);
  FRIEND_TEST(ProxyTest, ShillResetRestoresAddressProperty);
  FRIEND_TEST(ProxyTest, StateClearedIfDefaultServiceDrops);
  FRIEND_TEST(ProxyTest, ArcProxy_IgnoredIfDefaultServiceDrops);
  FRIEND_TEST(ProxyTest, StateClearedIfDefaultServiceIsNotOnline);
  FRIEND_TEST(ProxyTest, NewResolverStartsListeningOnDefaultServiceComesOnline);
  FRIEND_TEST(ProxyTest, CrashOnListenFailure);
  FRIEND_TEST(ProxyTest, NameServersUpdatedOnDefaultServiceComesOnline);
  FRIEND_TEST(ProxyTest,
              SystemProxy_ShillPropertyUpdatedOnDefaultServiceComesOnline);
  FRIEND_TEST(ProxyTest, SystemProxy_IgnoresVPN);
  FRIEND_TEST(ProxyTest, SystemProxy_GetsPhysicalDeviceOnInitialVPN);
  FRIEND_TEST(ProxyTest, DefaultProxy_UsesVPN);
  FRIEND_TEST(ProxyTest, ArcProxy_NameServersUpdatedOnDeviceChangeEvent);
  FRIEND_TEST(ProxyTest, SystemProxy_NameServersUpdatedOnDeviceChangeEvent);
  FRIEND_TEST(ProxyTest, DeviceChangeEventIgnored);
  FRIEND_TEST(ProxyTest, BasicDoHDisable);
  FRIEND_TEST(ProxyTest, BasicDoHAlwaysOn);
  FRIEND_TEST(ProxyTest, BasicDoHAutomatic);
  FRIEND_TEST(ProxyTest, RemovesDNSQueryParameterTemplate_AlwaysOn);
  FRIEND_TEST(ProxyTest, RemovesDNSQueryParameterTemplate_Automatic);
  FRIEND_TEST(ProxyTest, NewResolverConfiguredWhenSet);
  FRIEND_TEST(ProxyTest, DoHModeChangingFixedNameServers);
  FRIEND_TEST(ProxyTest, MultipleDoHProvidersForAlwaysOnMode);
  FRIEND_TEST(ProxyTest, MultipleDoHProvidersForAutomaticMode);
  FRIEND_TEST(ProxyTest, DoHBadAlwaysOnConfigSetsAutomaticMode);
  FRIEND_TEST(ProxyTest, DefaultProxy_DisableDoHProvidersOnVPN);
  FRIEND_TEST(ProxyTest, SystemProxy_SetsDnsRedirectionRule);
  FRIEND_TEST(ProxyTest, SystemProxy_SetDnsRedirectionRuleIPv6Added);
  FRIEND_TEST(ProxyTest, SystemProxy_SetDnsRedirectionRuleIPv6Deleted);
  FRIEND_TEST(ProxyTest,
              DefaultProxy_SetDnsRedirectionRuleDeviceAlreadyStarted);
  FRIEND_TEST(ProxyTest, DefaultProxy_SetDnsRedirectionRuleNewDeviceStarted);
  FRIEND_TEST(ProxyTest, DefaultProxy_NeverSetsDnsRedirectionRuleOtherGuest);
  FRIEND_TEST(ProxyTest, DefaultProxy_SetDnsRedirectionRuleWithoutIPv6);
  FRIEND_TEST(ProxyTest, DefaultProxy_SetDnsRedirectionRuleIPv6Added);
  FRIEND_TEST(ProxyTest, DefaultProxy_SetDnsRedirectionRuleIPv6Deleted);
  FRIEND_TEST(ProxyTest, DefaultProxy_SetDnsRedirectionRuleUnrelatedIPv6Added);
  FRIEND_TEST(ProxyTest, ArcProxy_SetDnsRedirectionRuleDeviceAlreadyStarted);
  FRIEND_TEST(ProxyTest, ArcProxy_SetDnsRedirectionRuleNewDeviceStarted);
  FRIEND_TEST(ProxyTest, ArcProxy_NeverSetsDnsRedirectionRuleOtherIfname);
  FRIEND_TEST(ProxyTest, ArcProxy_NeverSetsDnsRedirectionRuleOtherGuest);
  FRIEND_TEST(ProxyTest, ArcProxy_SetDnsRedirectionRuleIPv6Added);
  FRIEND_TEST(ProxyTest, ArcProxy_SetDnsRedirectionRuleIPv6Deleted);
  FRIEND_TEST(ProxyTest, ArcProxy_SetDnsRedirectionRuleUnrelatedIPv6Added);
  FRIEND_TEST(ProxyTest, UpdateNameServers);

  const Options opts_;
  std::unique_ptr<patchpanel::Client> patchpanel_;
  std::unique_ptr<shill::Client> shill_;
  std::unique_ptr<shill::Client::ManagerPropertyAccessor> shill_props_;
  std::unique_ptr<SessionMonitor> session_;

  base::ScopedFD ns_fd_;
  patchpanel::Client::ConnectedNamespace ns_;
  std::string ns_peer_ipv6_address_;

  std::unique_ptr<Resolver> resolver_;
  DoHConfig doh_config_;
  std::unique_ptr<shill::Client::Device> device_;

  bool shill_ready_{false};

  // Mapping of interface name and socket family pair to a lifeline file
  // descriptor. These file descriptors control the lifetime of the DNS
  // redirection rules created through the patchpanel's DBus API.
  // For USER DnsRedirectionRequest, the interface name will be empty as it is
  // not needed.
  std::map<std::pair<std::string, sa_family_t>, base::ScopedFD> lifeline_fds_;

  Metrics metrics_;
  const Metrics::ProcessType metrics_proc_type_;

  // Helper to send system proxy's IP addresses to be the controller. This is
  // necessary to write to /etc/resolv.conf.
  std::unique_ptr<patchpanel::MessageDispatcher<ProxyAddrMessage>>
      msg_dispatcher_;

  // Listens for RTMGRP_IPV6_IFADDR messages and invokes RTNLMessageHandler.
  std::unique_ptr<shill::RTNLListener> addr_listener_;

  base::WeakPtrFactory<Proxy> weak_factory_{this};
};

std::ostream& operator<<(std::ostream& stream, Proxy::Type type);
std::ostream& operator<<(std::ostream& stream, Proxy::Options opt);

}  // namespace dns_proxy

#endif  // DNS_PROXY_PROXY_H_
