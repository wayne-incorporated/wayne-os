// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/routing_service.h"

#include <iostream>
#include <map>

#include <base/logging.h>

namespace patchpanel {

RoutingService::RoutingService() {}

int RoutingService::GetSockopt(
    int sockfd, int level, int optname, void* optval, socklen_t* optlen) {
  return getsockopt(sockfd, level, optname, optval, optlen);
}

int RoutingService::SetSockopt(
    int sockfd, int level, int optname, const void* optval, socklen_t optlen) {
  return setsockopt(sockfd, level, optname, optval, optlen);
}

bool RoutingService::SetFwmark(int sockfd, Fwmark mark, Fwmark mask) {
  uint32_t fwmark_value = 0;
  socklen_t fwmark_len = sizeof(fwmark_value);
  if (GetSockopt(sockfd, SOL_SOCKET, SO_MARK, &fwmark_value, &fwmark_len) < 0) {
    PLOG(ERROR) << "SetFwmark mark=" << mark.ToString()
                << " mask=" << mask.ToString()
                << " getsockopt SOL_SOCKET SO_MARK failed";
    return false;
  }

  fwmark_value = (mark & mask).Value() | (fwmark_value & ~mask.Value());

  fwmark_len = sizeof(fwmark_value);
  if (SetSockopt(sockfd, SOL_SOCKET, SO_MARK, &fwmark_value, fwmark_len) < 0) {
    PLOG(ERROR) << "SetFwmark mark=" << mark.ToString()
                << " mask=" << mask.ToString()
                << " setsockopt SOL_SOCKET SO_MARK failed";
    return false;
  }

  return true;
}

bool RoutingService::SetVpnFwmark(
    int sockfd, patchpanel::SetVpnIntentRequest::VpnRoutingPolicy policy) {
  Fwmark mark = {};
  switch (policy) {
    case patchpanel::SetVpnIntentRequest::DEFAULT_ROUTING:
      break;
    case patchpanel::SetVpnIntentRequest::ROUTE_ON_VPN:
      mark = kFwmarkRouteOnVpn;
      break;
    case patchpanel::SetVpnIntentRequest::BYPASS_VPN:
      mark = kFwmarkBypassVpn;
      break;
    default:
      LOG(ERROR) << "Incorrect SetVpnIntent policy value " << policy;
      return false;
  }
  LOG(INFO) << "SetFwmark mark=" << mark.ToString()
            << " mask=" << kFwmarkVpnMask.ToString()
            << " getsockopt SOL_SOCKET SO_MARK";
  return SetFwmark(sockfd, mark, kFwmarkVpnMask);
}

const std::string& TrafficSourceName(TrafficSource source) {
  static std::map<TrafficSource, std::string> kTrafficSourceNames = {
      {kChrome, "CHROME"},
      {kUser, "USER"},
      {kUpdateEngine, "UPDATE_ENGINE"},
      {kSystem, "SYSTEM"},
      {kHostVpn, "HOST_VPN"},
      {kArc, "ARC"},
      {kCrosVM, "CROSVM"},
      {kParallelsVM, "PARALLELS_VM"},
      {kTetherDownstream, "TETHER_DOWNSTREAM"},
      {kArcVpn, "ARC_VPN"},
      {kUnknown, "UNKNOWN"},
  };
  const auto& it = kTrafficSourceNames.find(source);
  if (it == kTrafficSourceNames.end()) {
    return kTrafficSourceNames.find(kUnknown)->second;
  }
  return it->second;
}

std::ostream& operator<<(std::ostream& stream, const LocalSourceSpecs& source) {
  return stream << "{source: " << TrafficSourceName(source.source_type)
                << ", uid: " << (source.uid_name ? source.uid_name : "")
                << ", classid: " << source.classid
                << ", is_on_vpn: " << (source.is_on_vpn ? "true" : "false")
                << "}";
}

}  // namespace patchpanel
