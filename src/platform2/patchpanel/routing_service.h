// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_ROUTING_SERVICE_H_
#define PATCHPANEL_ROUTING_SERVICE_H_

#include <arpa/inet.h>
#include <limits.h>
#include <stdint.h>
#include <sys/socket.h>

#include <array>
#include <optional>
#include <ostream>
#include <string>

#include <base/strings/stringprintf.h>

#include <patchpanel/proto_bindings/patchpanel_service.pb.h>

namespace patchpanel {

// Constant used for establishing a stable mapping between routing table ids
// and interface indexes. An interface with ifindex 2 will be assigned the
// routing table with id 1002 by the routing layer. This stable mapping is used
// for configuring ip rules, iptables fwmark mangle rules, and the
// accept_ra_rt_table sysctl for all physical interfaces.
// TODO(b/161507671) Consolidate with shill::kInterfaceTableIdIncrement
// in platform2/shill/routing_table.cc once routing and ip rule configuration
// is migrated to patchpanel.
constexpr const int kInterfaceTableIdIncrement = 1000;

// The list of all sources of traffic that need to be distinguished
// for routing or traffic accounting. Currently 6 bits are used for encoding
// the TrafficSource enum in a fwmark. The enum is split into two groups:local
// sources and forwarded sources. The enum values of forwarded sources are
// offset by 0x20 so that their most significant bit is always set and can be
// easily matched separately from local sources.
enum TrafficSource {
  kUnknown = 0,

  // Local sources:
  // Traffic corresponding to uid "chronos".
  kChrome = 1,
  // Other uids classified as "user" for traffic purposes: debugd, cups,
  // tlsdate, pluginvm (Parallels), etc.
  kUser = 2,
  // Traffic from Update engine.
  kUpdateEngine = 3,
  // Other system traffic.
  kSystem = 4,
  // Traffic emitted on an underlying physical network by the built-in OpenVPN
  // and L2TP clients, or Chrome 3rd party VPN Apps. This traffic constitutes
  // the VPN tunnel.
  kHostVpn = 5,

  // Forwarded sources:
  // ARC++ and ARCVM.
  kArc = 0x20,
  // Crostini VMs and lxc containers.
  kCrosVM = 0x21,
  // Parallels VMs.
  kParallelsVM = 0x22,
  // A tethered downstream network. Currently reserved for future use.
  kTetherDownstream = 0x23,
  // Traffic emitted by Android VPNs for their tunnelled connections.
  kArcVpn = 0x24,
};

const std::string& TrafficSourceName(TrafficSource source);

// A representation of how fwmark bits are split and used for tagging and
// routing traffic. The 32 bits of the fwmark are currently organized as such:
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |        routing table id       |VPN|source enum|   reserved  |*|
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// routing table id (16bits): the routing table id of a physical device managed
//                            by shill or of a virtual private network.
// VPN (2bits): policy bits controlled by host application to force VPN routing
//              or bypass VPN routing.
// source enum(6bits): policy bits controlled by patchpanel for grouping
//                     originated traffic by domain.
// reserved(7bits): no usage at the moment.
// legacy SNAT(1bit): legacy bit used for setting up SNAT for ARC, Crostini, and
//                    Parallels VMs with iptables MASQUERADE.
//
// Note that bitfields are not a portable way to define a
// stable Fwmark. Also note that the in-memory representation of values of
// this union changes depending on endianness, so care must be taken when
// serializing or deserializing Fwmark values, or when aliasing with raw bytes
// through pointers. In practice client code should not rely on a specific
// memory representation and should instead use ToString() and Value().
union Fwmark {
  struct {
    // The LSB is currently only used for applying IPv4 SNAT to egress traffic
    // from ARC and other VMs; indicated by a value of 1.
    uint8_t legacy;
    // The 3rd byte is used to store the intent and policy to be applied to the
    // traffic. The first 2 bits are used for host processes to select a VPN
    // routing intent via patchpanel SetVpnIntent API. The next 6 bits of are
    // used for tagging the traffic with a source.
    uint8_t policy;
    // The 2 upper bytes corresponds to the routing table id associated with
    // a shill device or a VPN.
    uint16_t rt_table_id;
  };
  // The raw memory representation of this fwmark as a uint32_t.
  uint32_t fwmark;

  // Returns a String representation of this Fwmark. This should
  std::string ToString() const {
    return base::StringPrintf("0x%04x%02x%02x", rt_table_id, policy, legacy);
  }

  // Returns the logical uint32_t value of this Fwmark.
  uint32_t Value() const {
    return static_cast<uint32_t>(rt_table_id) << 16 |
           static_cast<uint32_t>(policy) << 8 | static_cast<uint32_t>(legacy);
  }

  constexpr TrafficSource Source() {
    return static_cast<TrafficSource>(policy & 0x3f);
  }

  constexpr bool operator==(Fwmark that) const { return fwmark == that.fwmark; }

  constexpr Fwmark operator|(Fwmark that) const {
    return {.fwmark = fwmark | that.fwmark};
  }

  constexpr Fwmark operator&(Fwmark that) const {
    return {.fwmark = fwmark & that.fwmark};
  }

  constexpr Fwmark operator~() const { return {.fwmark = ~fwmark}; }

  static Fwmark FromSource(TrafficSource source) {
    return {
        .policy = static_cast<uint8_t>(source), .legacy = 0, .rt_table_id = 0};
  }

  static std::optional<Fwmark> FromIfIndex(int ifindex) {
    int table_id = ifindex + kInterfaceTableIdIncrement;
    if (ifindex < 0 || table_id > INT16_MAX) {
      return std::nullopt;
    }
    return {{.policy = 0,
             .legacy = 0,
             .rt_table_id = static_cast<uint16_t>(table_id)}};
  }
};

// Specifies how the local traffic originating from a given source should be
// tagged in mangle OUTPUT. A source is either identified by a uid or by a
// cgroup classid identifier.
struct LocalSourceSpecs {
  TrafficSource source_type;
  const char* uid_name;
  uint32_t classid;
  bool is_on_vpn;
};

std::ostream& operator<<(std::ostream& stream, const LocalSourceSpecs& source);

// This block defines the names of uids whose traffic is always routed through a
// VPN connection. Chrome and nacl applications
constexpr char kUidChronos[] = "chronos";
// Crosh terminal and feedback reports
constexpr char kUidDebugd[] = "debugd";
// Printing
constexpr char kUidCups[] = "cups";
// Printer and print queues configuration utility used for cups
constexpr char kUidLpadmin[] = "lpadmin";
// Chrome OS Kerberos daemon
constexpr char kUidKerberosd[] = "kerberosd";
// Kerberos third party untrusted code
constexpr char kUidKerberosdExec[] = "kerberosd-exec";
// While tlsdate is not user traffic, time sync should be attempted over
// VPN. It is OK to send tlsdate traffic over VPN because it will also try
// to sync time immediately after boot on the sign-in screen when no VPN can
// be active.
constexpr char kUidTlsdate[] = "tlsdate";
// Parallels VM problem report utility (b/160916677)
constexpr char kUidPluginvm[] = "pluginvm";
// smbfs SMB filesystem daemon
constexpr char kUidFuseSmbfs[] = "fuse-smbfs";

// The list of all local sources to tag in mangle OUTPUT with the VPN intent
// bit, or with a source tag, or with both. This arrays specifies: 1) the source
// type, 2) the uid name of the source or empty cstring if none is defined (the
// cstring must be defined and cannot be null), 3) the cgroup classid of the
// source (or 0 if none is defined), and 4) if the traffic originated from that
// source should be routed through VPN connections by default or not.
constexpr std::array<LocalSourceSpecs, 10> kLocalSourceTypes{{
    {TrafficSource::kChrome, kUidChronos, 0, true},
    {TrafficSource::kUser, kUidDebugd, 0, true},
    {TrafficSource::kUser, kUidCups, 0, true},
    {TrafficSource::kUser, kUidLpadmin, 0, true},
    {TrafficSource::kSystem, kUidKerberosd, 0, true},
    {TrafficSource::kSystem, kUidKerberosdExec, 0, true},
    {TrafficSource::kSystem, kUidTlsdate, 0, true},
    {TrafficSource::kUser, kUidPluginvm, 0, true},
    {TrafficSource::kSystem, kUidFuseSmbfs, 0, true},
    // The classid value for update engine must stay in sync with
    // src/aosp/system/update_engine/init/update-engine.conf.
    {TrafficSource::kUpdateEngine, "", 0x10001, false},
}};

// All local sources
constexpr std::array<TrafficSource, 5> kLocalSources{
    {kChrome, kUser, kUpdateEngine, kSystem, kHostVpn}};

// All forwarded sources
constexpr std::array<TrafficSource, 5> kForwardedSources{
    {kArc, kCrosVM, kParallelsVM, kTetherDownstream, kArcVpn}};

// All sources
constexpr std::array<TrafficSource, 10> kAllSources{
    {kChrome, kUser, kUpdateEngine, kSystem, kHostVpn, kArc, kCrosVM,
     kParallelsVM, kTetherDownstream, kArcVpn}};

// iptables type keywords for neighbor discovery packets
constexpr std::array<char[32], 4> kNeighborDiscoveryTypes{
    {"router-solicitation", "router-advertisement", "neighbour-solicitation",
     "neighbour-advertisement"}};

// Constant fwmark value for tagging traffic with the "route-on-vpn" intent.
constexpr const Fwmark kFwmarkRouteOnVpn = {.policy = 0x80};
// Constant fwmark value for tagging traffic with the "bypass-vpn" intent.
constexpr const Fwmark kFwmarkBypassVpn = {.policy = 0x40};
// constexpr const Fwmark kFwmarkVpnMask = kFwmarkRouteOnVpn | kFwmarkBypassVpn;
constexpr const Fwmark kFwmarkVpnMask = {.policy = 0xc0};
// A mask for matching fwmarks on the routing table id.
constexpr const Fwmark kFwmarkRoutingMask = {.rt_table_id = 0xffff};
// A mask for matching fwmarks on the source.
constexpr const Fwmark kFwmarkAllSourcesMask = {.policy = 0x3f};
// A mast for matching fwmarks of forwarded sources.
constexpr const Fwmark kFwmarkForwardedSourcesMask = {.policy = 0x20};
// A mask for matching fwmarks on the policy byte.
constexpr const Fwmark kFwmarkPolicyMask = {.policy = 0xff};
// Both the mask and fwmark values for legacy SNAT rules used for ARC and other
// containers.
constexpr const Fwmark kFwmarkLegacySNAT = {.legacy = 0x1};

// Service implementing routing features of patchpanel.
// TODO(hugobenichi) Explain how this coordinates with shill's RoutingTable.
class RoutingService {
 public:
  RoutingService();
  RoutingService(const RoutingService&) = delete;
  RoutingService& operator=(const RoutingService&) = delete;
  virtual ~RoutingService() = default;

  // Sets the VPN bits of the fwmark for the given socket according to the
  // given policy. Preserves any other bits of the fwmark already set.
  bool SetVpnFwmark(int sockfd,
                    patchpanel::SetVpnIntentRequest::VpnRoutingPolicy policy);

  // Sets the fwmark on the given socket with the given mask.
  // Preserves any other bits of the fwmark already set.
  bool SetFwmark(int sockfd, Fwmark mark, Fwmark mask);

 protected:
  // Can be overridden in tests.
  virtual int GetSockopt(
      int sockfd, int level, int optname, void* optval, socklen_t* optlen);
  virtual int SetSockopt(
      int sockfd, int level, int optname, const void* optval, socklen_t optlen);
};

}  // namespace patchpanel

#endif  // PATCHPANEL_ROUTING_SERVICE_H_
