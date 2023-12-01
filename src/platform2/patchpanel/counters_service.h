// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_COUNTERS_SERVICE_H_
#define PATCHPANEL_COUNTERS_SERVICE_H_

#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <patchpanel/proto_bindings/patchpanel_service.pb.h>

#include "patchpanel/datapath.h"
#include "patchpanel/iptables.h"
#include "patchpanel/routing_service.h"

namespace patchpanel {

// This class manages the iptables rules for traffic counters, and queries
// iptables to get the counters when a request comes. This class will set up
// several iptable rules to track the counters for each possible combination of
// {bytes, packets} x (Traffic source) x (shill Device) x {rx, tx} x {IPv4,
// IPv6}. These counters will never be removed after they are set up, and thus
// they represent the traffic usage from boot time.
//
// Implementation details
//
// Rules: All the rules/chains for accounting are in (INPUT, FORWARD or
// POSTROUTING) chain in the mangle table. These rules take effect after routing
// and will not change the fate of a packet. When a new interface comes up, we
// will create the following new rules/chains (using both iptables and
// ip6tables):
// - Two accounting chains:
//   - For rx packets, `rx_{ifname}` for INPUT and FORWARD chains;
//   - For tx packets, `tx_{ifname}` for POSTROUTING chain.
// - One accounting rule in each accounting chain for every source defined in
//   RoutingService plus one final accounting rule for untagged traffic.
// - Jumping rules for each accounting chain in the corresponding prebuilt
//   chain, which matches packets with this new interface.
// The above accounting rules and chains will never be removed once created, so
// we will check if one rule exists before creating it. Jumping rules are added
// and removed dynamically based on shill physical Device and shill vpn Device
// creation and removal events.
//
// Query: Two commands (iptables and ip6tables) will be executed in the mangle
// table to get all the chains and rules. And then we perform a text parsing on
// the output to get the counters.
class CountersService {
 public:
  struct CounterKey {
    std::string ifname;
    TrafficCounter::Source source;
    TrafficCounter::IpFamily ip_family;

    bool operator<(const CounterKey& rhs) const;
  };

  struct Counter {
    uint64_t rx_bytes = 0;
    uint64_t rx_packets = 0;
    uint64_t tx_bytes = 0;
    uint64_t tx_packets = 0;
  };

  explicit CountersService(Datapath* datapath);
  ~CountersService() = default;

  // Adds accounting rules and jump rules for a new physical device if this is
  // the first time this device is seen.
  void OnPhysicalDeviceAdded(const std::string& ifname);
  // Removes jump rules for a physical device.
  void OnPhysicalDeviceRemoved(const std::string& ifname);
  // Adds accounting rules and jump rules for a new VPN device.
  void OnVpnDeviceAdded(const std::string& ifname);
  // Removes jump rules for a VPN device.
  void OnVpnDeviceRemoved(const std::string& ifname);
  // Collects and returns counters from all the existing iptables rules.
  // |devices| is the set of interfaces for which counters should be returned,
  // any unknown interfaces will be ignored. If |devices| is empty, counters for
  // all known interfaces will be returned. An empty map will be returned on
  // any failure.
  std::map<CounterKey, Counter> GetCounters(
      const std::set<std::string>& devices);

 private:
  // Creates an iptables chain in the mangle table. Returns true if the chain
  // was created, or false if the chain already existed.
  bool MakeAccountingChain(const std::string& chain_name);
  bool AddAccountingRule(const std::string& chain_name, TrafficSource source);
  // Installs the required accounting chains and rules for the target
  // |chain_tag| if they did not exist already.
  void SetupAccountingRules(const std::string& chain_tag);
  // Installs jump rules in POSTROUTING to count traffic ingressing and
  // egressing |ifname| with the accounting target |chain_tag|.
  void SetupJumpRules(Iptables::Command command,
                      const std::string& ifname,
                      const std::string& chain_tag);

  Datapath* datapath_;
};

TrafficCounter::Source TrafficSourceToProto(TrafficSource source);
TrafficSource ProtoToTrafficSource(TrafficCounter::Source source);

}  // namespace patchpanel

#endif  // PATCHPANEL_COUNTERS_SERVICE_H_
