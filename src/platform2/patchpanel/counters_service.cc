// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/counters_service.h"

#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/logging.h>
#include <base/strings/strcat.h>
#include <base/strings/string_split.h>
#include <re2/re2.h>

#include "patchpanel/datapath.h"
#include "patchpanel/iptables.h"

namespace patchpanel {

namespace {

using Counter = CountersService::Counter;
using CounterKey = CountersService::CounterKey;

constexpr char kVpnChainTag[] = "vpn";
constexpr char kRxTag[] = "rx_";
constexpr char kTxTag[] = "tx_";

// The following regexs and code is written and tested for iptables v1.6.2.
// Output code of iptables can be found at:
//   https://git.netfilter.org/iptables/tree/iptables/iptables.c?h=v1.6.2

// The chain line looks like:
//   "Chain tx_eth0 (2 references)".
// This regex extracts "tx" (direction), "eth0" (ifname) from this example.
constexpr LazyRE2 kChainLine = {R"(Chain (rx|tx)_(\w+).*)"};

// The counter line for a defined source looks like (some spaces are deleted to
// make it fit in one line):
// " 5374 6172 RETURN all -- * * 0.0.0.0/0 0.0.0.0/0 mark match 0x2000/0x3f00"
// for IPv4.
// " 5374 6172 RETURN all -- * * ::/0 ::/0 mark match 0x2000/0x3f00" for IPv6.
// The final counter line for catching untagged traffic looks like:
// " 5374 6172 all -- * * 0.0.0.0/0 0.0.0.0/0" for IPv4.
// " 5374 6172 all -- * * ::/0 ::/0" for IPv6.
// The first two counters are captured for pkts and bytes. For lines with a mark
// matcher, the source is also captured.
constexpr LazyRE2 kCounterLine = {R"( *(\d+) +(\d+).*mark match (.*)/0x3f00)"};
constexpr LazyRE2 kFinalCounterLine = {
    R"( *(\d+) +(\d+).*(?:0\.0\.0\.0/0|::/0)\s*)"};

bool MatchCounterLine(const std::string& line,
                      uint64_t* pkts,
                      uint64_t* bytes,
                      TrafficSource* source) {
  Fwmark mark;
  if (RE2::FullMatch(line, *kCounterLine, pkts, bytes,
                     RE2::Hex(&mark.fwmark))) {
    *source = mark.Source();
    return true;
  }

  if (RE2::FullMatch(line, *kFinalCounterLine, pkts, bytes)) {
    *source = TrafficSource::kUnknown;
    return true;
  }

  return false;
}

// Parses the output of `iptables -L -x -v` (or `ip6tables`) and adds the parsed
// values into the corresponding counters in |counters|. An example of |output|
// can be found in the test file. This function will try to find the pattern of:
//   <one chain line for an accounting chain>
//   <one header line>
//   <one counter line for an accounting rule>
// The interface name and direction (rx or tx) will be extracted from the chain
// line, and then the values extracted from the counter line will be added into
// the counter for that interface. Note that this function will not fully
// validate if |output| is an output from iptables.
bool ParseOutput(const std::string& output,
                 const std::set<std::string>& devices,
                 const TrafficCounter::IpFamily ip_family,
                 std::map<CounterKey, Counter>* counters) {
  DCHECK(counters);
  const std::vector<std::string> lines = base::SplitString(
      output, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);

  // Finds the chain line for an accounting chain first, and then parse the
  // following line(s) to get the counters for this chain. Repeats this process
  // until we reach the end of |output|.
  for (auto it = lines.cbegin(); it != lines.cend(); it++) {
    // Finds the chain name line.
    std::string direction, ifname;
    while (it != lines.cend() &&
           !RE2::FullMatch(*it, *kChainLine, &direction, &ifname))
      it++;

    if (it == lines.cend())
      break;

    // Skips this group if this ifname is not requested.
    if (!devices.empty() && devices.find(ifname) == devices.end())
      continue;

    // Skips the chain name line and the header line.
    if (lines.cend() - it <= 2) {
      LOG(ERROR) << "Invalid iptables output for " << direction << "_"
                 << ifname;
      return false;
    }
    it += 2;

    // Checks that there are some counter rules defined.
    if (it == lines.cend() || it->empty()) {
      LOG(ERROR) << "No counter rule defined for " << direction << "_"
                 << ifname;
      return false;
    }

    // The next block of lines are the counters lines for individual sources.
    for (; it != lines.cend() && !it->empty(); it++) {
      uint64_t pkts, bytes;
      TrafficSource source;
      if (!MatchCounterLine(*it, &pkts, &bytes, &source)) {
        LOG(ERROR) << "Cannot parse counter line \"" << *it << "\" for "
                   << direction << "_" << ifname;
        return false;
      }

      if (pkts == 0 && bytes == 0)
        continue;

      CounterKey key = {};
      key.ifname = ifname;
      key.source = TrafficSourceToProto(source);
      key.ip_family = ip_family;
      auto& counter = (*counters)[key];
      if (direction == "rx") {
        counter.rx_bytes += bytes;
        counter.rx_packets += pkts;
      } else {
        counter.tx_bytes += bytes;
        counter.tx_packets += pkts;
      }
    }

    if (it == lines.cend())
      break;
  }
  return true;
}

}  // namespace

CountersService::CountersService(Datapath* datapath) : datapath_(datapath) {}

std::map<CounterKey, Counter> CountersService::GetCounters(
    const std::set<std::string>& devices) {
  std::map<CounterKey, Counter> counters;

  // Handles counters for IPv4 and IPv6 separately and returns failure if either
  // of the procession fails, since counters for only IPv4 or IPv6 are biased.
  std::string iptables_result =
      datapath_->DumpIptables(IpFamily::kIPv4, Iptables::Table::kMangle);
  if (iptables_result.empty()) {
    LOG(ERROR) << "Failed to query IPv4 counters";
    return {};
  }
  if (!ParseOutput(iptables_result, devices, TrafficCounter::IPV4, &counters)) {
    LOG(ERROR) << "Failed to parse IPv4 counters";
    return {};
  }

  std::string ip6tables_result =
      datapath_->DumpIptables(IpFamily::kIPv6, Iptables::Table::kMangle);
  if (ip6tables_result.empty()) {
    LOG(ERROR) << "Failed to query IPv6 counters";
    return {};
  }
  if (!ParseOutput(ip6tables_result, devices, TrafficCounter::IPV6,
                   &counters)) {
    LOG(ERROR) << "Failed to parse IPv6 counters";
    return {};
  }

  return counters;
}

void CountersService::OnPhysicalDeviceAdded(const std::string& ifname) {
  SetupAccountingRules(ifname);
  SetupJumpRules(Iptables::Command::kA, ifname, ifname);
}

void CountersService::OnPhysicalDeviceRemoved(const std::string& ifname) {
  SetupJumpRules(Iptables::Command::kD, ifname, ifname);
}

void CountersService::OnVpnDeviceAdded(const std::string& ifname) {
  SetupAccountingRules(kVpnChainTag);
  SetupJumpRules(Iptables::Command::kA, ifname, kVpnChainTag);
}

void CountersService::OnVpnDeviceRemoved(const std::string& ifname) {
  SetupJumpRules(Iptables::Command::kD, ifname, kVpnChainTag);
}

bool CountersService::MakeAccountingChain(const std::string& chain_name) {
  return datapath_->ModifyChain(IpFamily::kDual, Iptables::Table::kMangle,
                                Iptables::Command::kN, chain_name,
                                /*log_failures=*/false);
}

bool CountersService::AddAccountingRule(const std::string& chain_name,
                                        TrafficSource source) {
  std::vector<std::string> args = {chain_name,
                                   "-m",
                                   "mark",
                                   "--mark",
                                   Fwmark::FromSource(source).ToString() + "/" +
                                       kFwmarkAllSourcesMask.ToString(),
                                   "-j",
                                   "RETURN",
                                   "-w"};
  return datapath_->ModifyIptables(IpFamily::kDual, Iptables::Table::kMangle,
                                   Iptables::Command::kA, args);
}

void CountersService::SetupAccountingRules(const std::string& chain_tag) {
  // For a new target accounting chain, create
  //  1) an accounting chain to jump to,
  //  2) source accounting rules in the chain.
  // Note that the length of a chain name must less than 29 chars and IFNAMSIZ
  // is 16 so we can only use at most 12 chars for the prefix.
  const std::string ingress_chain = kRxTag + chain_tag;
  const std::string egress_chain = kTxTag + chain_tag;

  // Creates egress and ingress traffic chains, or stops if they already exist.
  if (!MakeAccountingChain(egress_chain) ||
      !MakeAccountingChain(ingress_chain)) {
    LOG(INFO) << "Traffic accounting chains already exist for " << chain_tag;
    return;
  }

  // Add source accounting rules.
  for (TrafficSource source : kAllSources) {
    AddAccountingRule(ingress_chain, source);
    AddAccountingRule(egress_chain, source);
  }
  // Add catch-all accounting rule for any remaining and untagged traffic.
  datapath_->ModifyIptables(IpFamily::kDual, Iptables::Table::kMangle,
                            Iptables::Command::kA, {ingress_chain, "-w"});
  datapath_->ModifyIptables(IpFamily::kDual, Iptables::Table::kMangle,
                            Iptables::Command::kA, {egress_chain, "-w"});
}

void CountersService::SetupJumpRules(Iptables::Command command,
                                     const std::string& ifname,
                                     const std::string& chain_tag) {
  // For each device create a jumping rule in mangle POSTROUTING for egress
  // traffic, and two jumping rules in mangle INPUT and FORWARD for ingress
  // traffic.
  datapath_->ModifyIptables(
      IpFamily::kDual, Iptables::Table::kMangle, command,
      {"FORWARD", "-i", ifname, "-j", kRxTag + chain_tag, "-w"});
  datapath_->ModifyIptables(
      IpFamily::kDual, Iptables::Table::kMangle, command,
      {"INPUT", "-i", ifname, "-j", kRxTag + chain_tag, "-w"});
  datapath_->ModifyIptables(
      IpFamily::kDual, Iptables::Table::kMangle, command,
      {"POSTROUTING", "-o", ifname, "-j", kTxTag + chain_tag, "-w"});
}

TrafficCounter::Source TrafficSourceToProto(TrafficSource source) {
  switch (source) {
    case TrafficSource::kChrome:
      return TrafficCounter::CHROME;
    case TrafficSource::kUser:
      return TrafficCounter::USER;
    case TrafficSource::kUpdateEngine:
      return TrafficCounter::UPDATE_ENGINE;
    case TrafficSource::kSystem:
      return TrafficCounter::SYSTEM;
    case TrafficSource::kHostVpn:
      return TrafficCounter::VPN;
    case TrafficSource::kArc:
      return TrafficCounter::ARC;
    case TrafficSource::kCrosVM:
      return TrafficCounter::CROSVM;
    case TrafficSource::kParallelsVM:
      return TrafficCounter::PARALLELS_VM;
    case TrafficSource::kTetherDownstream:
      return TrafficCounter::SYSTEM;
    case TrafficSource::kArcVpn:
      return TrafficCounter::VPN;
    case TrafficSource::kUnknown:
    default:
      return TrafficCounter::UNKNOWN;
  }
}

TrafficSource ProtoToTrafficSource(TrafficCounter::Source source) {
  switch (source) {
    case TrafficCounter::CHROME:
      return TrafficSource::kChrome;
    case TrafficCounter::USER:
      return TrafficSource::kUser;
    case TrafficCounter::UPDATE_ENGINE:
      return TrafficSource::kUpdateEngine;
    case TrafficCounter::SYSTEM:
      return TrafficSource::kSystem;
    case TrafficCounter::VPN:
      return TrafficSource::kHostVpn;
    case TrafficCounter::ARC:
      return TrafficSource::kArc;
    case TrafficCounter::CROSVM:
      return TrafficSource::kCrosVM;
    case TrafficCounter::PARALLELS_VM:
      return TrafficSource::kParallelsVM;
    default:
    case TrafficCounter::UNKNOWN:
      return TrafficSource::kUnknown;
  }
}

bool CountersService::CounterKey::operator<(const CounterKey& rhs) const {
  if (ifname < rhs.ifname) {
    return true;
  }
  if (ifname > rhs.ifname) {
    return false;
  }
  if (source < rhs.source) {
    return true;
  }
  if (source > rhs.source) {
    return false;
  }
  return ip_family < rhs.ip_family;
}

}  // namespace patchpanel
