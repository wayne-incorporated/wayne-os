// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_GUEST_IPV6_SERVICE_H_
#define PATCHPANEL_GUEST_IPV6_SERVICE_H_

#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <base/memory/weak_ptr.h>

#include "patchpanel/datapath.h"
#include "patchpanel/ipc.h"
#include "patchpanel/shill_client.h"
#include "patchpanel/subprocess_controller.h"

namespace patchpanel {

class GuestIPv6Service {
 public:
  enum class ForwardMethod {
    kMethodUnknown,
    kMethodNDProxy,
    kMethodRAServer,
    // b/187462665, b/187918638: If the physical interface is a cellular
    // modem, the network connection is expected to work as a point to point
    // link where neighbor discovery of the remote gateway is not possible.
    // Therefore injecting RA to let guests treat the host as next hop
    // router is needed if using NDProxy.
    kMethodNDProxyInjectingRA
  };

  GuestIPv6Service(SubprocessController* nd_proxy,
                   Datapath* datapath,
                   System* system);
  GuestIPv6Service(const GuestIPv6Service&) = delete;
  GuestIPv6Service& operator=(const GuestIPv6Service&) = delete;
  virtual ~GuestIPv6Service() = default;

  void Start();

  // Starts forwarding from the upstream shill Device |upstream_shill_device| to
  // the downstream interface |ifname_downlink|. |mtu| is the MTU of the
  // upstream. If |mtu| has value, then store it into |forward_record_|.
  // Otherwise, use the value which is previously stored at |forward_record_|.
  //
  // Note: the MTU value is only used when the forwarding method is RA server.
  // If there is no stored MTU value, RA server does not announce MTU value.
  void StartForwarding(const ShillClient::Device& upstream_shill_device,
                       const std::string& ifname_downlink,
                       const std::optional<int>& mtu = std::nullopt,
                       bool downlink_is_tethering = false);

  void StopForwarding(const ShillClient::Device& upstream_shill_device,
                      const std::string& ifname_downlink);

  void StopUplink(const ShillClient::Device& upstream_shill_device);

  void OnUplinkIPv6Changed(const ShillClient::Device& upstream_shill_device);

  void UpdateUplinkIPv6DNS(const ShillClient::Device& upstream_shill_device);

  // For local hotspot there is no uplink. We need to first start the RA
  // server on the tethering link with the provided prefix info.
  // StartForwarding() is still expected to be called among this link and
  // other downlinks later to propagate this private prefix to those
  // downlinks and to enable NA/NS forwarding.
  void StartLocalHotspot(const std::string& ifname_hotspot_link,
                         const std::string& prefix,
                         const std::vector<std::string>& rdnss,
                         const std::vector<std::string>& dnssl);

  void StopLocalHotspot(const std::string& ifname_hotspot_link);

  // Allow manually set a uplink to use NDProxy or RA server for test
  // purpose. This will be exposed by Manager through dbus for tast.
  void SetForwardMethod(const ShillClient::Device& upstream_shill_device,
                        ForwardMethod method);

  // Notify GuestIPv6Service that a certain (global) IPv6 address |ip| is
  // configured on a cartain downstream neighbor, connected through
  // |ifname_downlink|. GuestIPv6Service will add a /128 route to that downlink.
  void RegisterDownstreamNeighborIP(const std::string& ifname_downlink,
                                    const net_base::IPv6Address& ip);

  static net_base::IPv6CIDR IPAddressTo64BitPrefix(
      const net_base::IPv6Address& addr_str);

 protected:
  virtual void SendNDProxyControl(
      NDProxyControlMessage::NDProxyRequestType type,
      int32_t if_id_primary,
      int32_t if_id_secondary);

  virtual bool StartRAServer(const std::string& ifname,
                             const net_base::IPv6CIDR& prefix,
                             const std::vector<std::string>& rdnss,
                             const std::optional<int>& mtu);
  virtual bool StopRAServer(const std::string& ifname);

  // Callback from NDProxy telling us to add a new IPv6 route to guest or IPv6
  // address to guest-facing interface.
  void OnNDProxyMessage(const FeedbackMessage& msg);

 private:
  struct ForwardEntry {
    ForwardMethod method;
    std::set<std::string> downstream_ifnames;
    std::optional<int> mtu;
  };

  // Helper functions to find corresponding uplink interface for a downlink and
  // all downlink interfaces for an uplink.
  std::optional<std::string> DownlinkToUplink(const std::string& downlink);
  const std::set<std::string>& UplinkToDownlinks(const std::string& uplink);

  // Queries |uplink_ips_| without modifying it.
  // Return std::nullopt if |uplink_ips_| doesn't contain |ifname|.
  const std::optional<net_base::IPv6Address> GetUplinkIp(
      const std::string& ifname) const;

  // IPv6 neighbor discovery forwarder process handler. Owned by Manager.
  SubprocessController* nd_proxy_;
  // Routing and iptables controller service. Owned by Manager.
  Datapath* datapath_;
  // Owned by Manager
  System* system_;

  bool StartRadvd(const std::string& ifname);

  // The current forwarding records, keyed by the upstream interface name.
  std::map<std::string /*upstream_ifname*/, ForwardEntry> forward_record_;
  std::map<std::string, ForwardMethod> forward_method_override_;

  // We cache the if_ids of netdevices when start forwarding to ensure that the
  // same ones are used when stop forwarding. Note that it is possible that the
  // netdevice is already no longer available when we received the StopUplink()
  // call.
  std::map<std::string, int32_t> if_cache_;

  // Uplink ifname -> the IPv6 address on that uplink, read from shill.
  std::map<std::string, net_base::IPv6Address> uplink_ips_;
  // Similarly, uplink ifname -> DNS servers information from shill.
  std::map<std::string, std::vector<std::string>> uplink_dns_;

  // The IP address of neighbors discovered on each downlink. This information
  // is used to add /128 routes to those downlinks.
  std::map<std::string, std::set<net_base::IPv6Address>> downstream_neighbors_;

  base::WeakPtrFactory<GuestIPv6Service> weak_factory_{this};
};

}  // namespace patchpanel

#endif  // PATCHPANEL_GUEST_IPV6_SERVICE_H_
