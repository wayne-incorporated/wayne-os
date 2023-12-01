// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_METRICS_H_
#define SHILL_METRICS_H_

#include <cstdint>
#include <list>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/strings/string_piece_forward.h>
#include <chromeos/dbus/shill/dbus-constants.h>
#include <chromeos/patchpanel/dbus/client.h>
#include <metrics/metrics_library.h>
#include <metrics/timer.h>

#include "shill/cellular/apn_list.h"
#include "shill/default_service_observer.h"
#include "shill/error.h"
#include "shill/net/ieee80211.h"
#include "shill/portal_detector.h"
#include "shill/refptr_types.h"
#include "shill/service.h"
#include "shill/vpn/vpn_provider.h"
#include "shill/wifi/wifi_security.h"

namespace shill {

class WiFiEndPoint;

static constexpr size_t kMaxMetricNameLen = 256;

// Represents a UMA metric name that can be defined by technology for a
// metric represented with EnumMetric or HistogramMetric, following the
// pattern "$kMetricPrefix.$TECH.$name" or "$kMetricPrefix.$name.$TECH"
// depending on the value of |location|.
// Note: This must be fully defined outside of the Metrics class to allow
// default member initialization for |location| within the class, e.g.
// MetricsNameByTechnology{"name"}.
struct MetricsNameByTechnology {
  enum class Location { kBeforeName, kAfterName };
  const char* name;
  Location location = Location::kBeforeName;
  // Necessary for testing.
  bool operator==(const MetricsNameByTechnology& that) const {
    return strncmp(name, that.name, kMaxMetricNameLen) == 0;
  }
};

class Metrics : public DefaultServiceObserver {
 public:
  using NameByTechnology = MetricsNameByTechnology;
  using TechnologyLocation = MetricsNameByTechnology::Location;

  // Helper type for describing a UMA enum metrics.
  // The template parameter is used for deriving the name of the metric. See
  // FixedName and NameByTechnology.
  template <typename N>
  struct EnumMetric {
    N n;
    int max;
    // Necessary for testing.
    bool operator==(const EnumMetric<N>& that) const {
      return n == that.n && max == that.max;
    }
  };

  // Helper type for describing a UMA histogram metrics.
  // The template parameter is used for deriving the name of the metric. See
  // FixedName and NameByTechnology.
  template <typename N>
  struct HistogramMetric {
    N n;
    int min;
    int max;
    int num_buckets;
    // Necessary for testing.
    bool operator==(const HistogramMetric<N>& that) const {
      return n == that.n && min == that.min && max == that.max &&
             num_buckets == that.num_buckets;
    }
  };

  // Represents a fixed UMA metric name for a metric represented with EnumMetric
  // or HistogramMetric.
  struct FixedName {
    const char* name;
    // Necessary for testing.
    bool operator==(const FixedName& that) const {
      return strncmp(name, that.name, kMaxMetricNameLen) == 0;
    }
  };

  // Represents a UMA metric name by APN type.
  struct NameByApnType {
    const char* name;
    // Necessary for testing.
    bool operator==(const NameByApnType& that) const {
      return strncmp(name, that.name, kMaxMetricNameLen) == 0;
    }
  };

  // Represents a UMA metric name by VPN type.
  struct NameByVPNType {
    const char* name;
    // Necessary for testing.
    bool operator==(const NameByVPNType& that) const {
      return strncmp(name, that.name, kMaxMetricNameLen) == 0;
    }
  };

  // Represents a UMA metric name with a fixed prefix. Callers provide the
  // suffix for every call sites. This is convenient for group of metrics
  // like "Network.Shill.WiFi.RememberedSystemNetworkCount.*" that share a
  // common prefix.
  struct PrefixName {
    const char* prefix;
    // Necessary for testing.
    bool operator==(const PrefixName& that) const {
      return strncmp(prefix, that.prefix, kMaxMetricNameLen) == 0;
    }
  };

  enum WiFiChannel {
    kWiFiChannelUndef = 0,
    kWiFiChannel2412 = 1,
    kWiFiChannelMin24 = kWiFiChannel2412,
    kWiFiChannel2417 = 2,
    kWiFiChannel2422 = 3,
    kWiFiChannel2427 = 4,
    kWiFiChannel2432 = 5,
    kWiFiChannel2437 = 6,
    kWiFiChannel2442 = 7,
    kWiFiChannel2447 = 8,
    kWiFiChannel2452 = 9,
    kWiFiChannel2457 = 10,
    kWiFiChannel2462 = 11,
    kWiFiChannel2467 = 12,
    kWiFiChannel2472 = 13,
    kWiFiChannel2484 = 14,
    kWiFiChannelMax24 = kWiFiChannel2484,

    kWiFiChannel5180 = 15,
    kWiFiChannelMin5 = kWiFiChannel5180,
    kWiFiChannel5200 = 16,
    kWiFiChannel5220 = 17,
    kWiFiChannel5240 = 18,
    kWiFiChannel5260 = 19,
    kWiFiChannel5280 = 20,
    kWiFiChannel5300 = 21,
    kWiFiChannel5320 = 22,

    kWiFiChannel5500 = 23,
    kWiFiChannel5520 = 24,
    kWiFiChannel5540 = 25,
    kWiFiChannel5560 = 26,
    kWiFiChannel5580 = 27,
    kWiFiChannel5600 = 28,
    kWiFiChannel5620 = 29,
    kWiFiChannel5640 = 30,
    kWiFiChannel5660 = 31,
    kWiFiChannel5680 = 32,
    kWiFiChannel5700 = 33,

    kWiFiChannel5745 = 34,
    kWiFiChannel5765 = 35,
    kWiFiChannel5785 = 36,
    kWiFiChannel5805 = 37,
    kWiFiChannel5825 = 38,

    kWiFiChannel5170 = 39,
    kWiFiChannel5190 = 40,
    kWiFiChannel5210 = 41,
    kWiFiChannel5230 = 42,
    kWiFiChannelMax5 = kWiFiChannel5230,

    kWiFiChannel5955 = 43,
    kWiFiChannelMin6 = kWiFiChannel5955,
    kWiFiChannel5975 = 44,
    kWiFiChannel5995 = 45,
    kWiFiChannel6015 = 46,
    kWiFiChannel6035 = 47,
    kWiFiChannel6055 = 48,
    kWiFiChannel6075 = 49,
    kWiFiChannel6095 = 50,
    kWiFiChannel6115 = 51,
    kWiFiChannel6135 = 52,
    kWiFiChannel6155 = 53,
    kWiFiChannel6175 = 54,
    kWiFiChannel6195 = 55,
    kWiFiChannel6215 = 56,
    kWiFiChannel6235 = 57,
    kWiFiChannel6255 = 58,
    kWiFiChannel6275 = 59,
    kWiFiChannel6295 = 60,
    kWiFiChannel6315 = 61,
    kWiFiChannel6335 = 62,
    kWiFiChannel6355 = 63,
    kWiFiChannel6375 = 64,
    kWiFiChannel6395 = 65,
    kWiFiChannel6415 = 66,
    kWiFiChannel6435 = 67,
    kWiFiChannel6455 = 68,
    kWiFiChannel6475 = 69,
    kWiFiChannel6495 = 70,
    kWiFiChannel6515 = 71,
    kWiFiChannel6535 = 72,
    kWiFiChannel6555 = 73,
    kWiFiChannel6575 = 74,
    kWiFiChannel6595 = 75,
    kWiFiChannel6615 = 76,
    kWiFiChannel6635 = 77,
    kWiFiChannel6655 = 78,
    kWiFiChannel6675 = 79,
    kWiFiChannel6695 = 80,
    kWiFiChannel6715 = 81,
    kWiFiChannel6735 = 82,
    kWiFiChannel6755 = 83,
    kWiFiChannel6775 = 84,
    kWiFiChannel6795 = 85,
    kWiFiChannel6815 = 86,
    kWiFiChannel6835 = 87,
    kWiFiChannel6855 = 88,
    kWiFiChannel6875 = 89,
    kWiFiChannel6895 = 90,
    kWiFiChannel6915 = 91,
    kWiFiChannel6935 = 92,
    kWiFiChannel6955 = 93,
    kWiFiChannel6975 = 94,
    kWiFiChannel6995 = 95,
    kWiFiChannel7015 = 96,
    kWiFiChannel7035 = 97,
    kWiFiChannel7055 = 98,
    kWiFiChannel7075 = 99,
    kWiFiChannel7095 = 100,
    kWiFiChannel7115 = 101,
    kWiFiChannelMax6 = kWiFiChannel7115,

    /* NB: ignore old 11b bands 2312..2372 and 2512..2532 */
    /* NB: ignore regulated bands 4920..4980 and 5020..5160 */
    kWiFiChannelMax
  };

  enum WiFiFrequencyRange {
    kWiFiFrequencyRangeUndef = 0,
    kWiFiFrequencyRange24 = 1,
    kWiFiFrequencyRange5 = 2,
    kWiFiFrequencyRange6 = 3,

    kWiFiFrequencyRangeMax
  };

  enum WiFiNetworkPhyMode {
    kWiFiNetworkPhyModeUndef = 0,    // Unknown/undefined
    kWiFiNetworkPhyMode11a = 1,      // 802.11a
    kWiFiNetworkPhyMode11b = 2,      // 802.11b
    kWiFiNetworkPhyMode11g = 3,      // 802.11g
    kWiFiNetworkPhyMode11n = 4,      // 802.11n
    kWiFiNetworkPhyModeHalf = 5,     // PSB Half-width
    kWiFiNetworkPhyModeQuarter = 6,  // PSB Quarter-width
    kWiFiNetworkPhyMode11ac = 7,     // 802.11ac
    kWiFiNetworkPhyMode11ax = 8,     // 802.11ax

    kWiFiNetworkPhyModeMax
  };

  enum EapOuterProtocol {
    kEapOuterProtocolUnknown = 0,
    kEapOuterProtocolLeap = 1,
    kEapOuterProtocolPeap = 2,
    kEapOuterProtocolTls = 3,
    kEapOuterProtocolTtls = 4,

    kEapOuterProtocolMax
  };
  static constexpr EnumMetric<NameByTechnology> kMetricNetworkEapOuterProtocol =
      {
          .n = NameByTechnology{"EapOuterProtocol"},
          .max = kEapOuterProtocolMax,
      };

  enum EapInnerProtocol {
    kEapInnerProtocolUnknown = 0,
    kEapInnerProtocolNone = 1,
    kEapInnerProtocolPeapMd5 = 2,
    kEapInnerProtocolPeapMschapv2 = 3,
    kEapInnerProtocolTtlsEapMd5 = 4,
    kEapInnerProtocolTtlsEapMschapv2 = 5,
    kEapInnerProtocolTtlsMschapv2 = 6,
    kEapInnerProtocolTtlsMschap = 7,
    kEapInnerProtocolTtlsPap = 8,
    kEapInnerProtocolTtlsChap = 9,

    kEapInnerProtocolMax
  };
  static constexpr EnumMetric<NameByTechnology> kMetricNetworkEapInnerProtocol =
      {
          .n = NameByTechnology{"EapInnerProtocol"},
          .max = kEapInnerProtocolMax,
      };

  enum WirelessSecurity {
    kWirelessSecurityUnknown = 0,
    kWirelessSecurityNone = 1,
    kWirelessSecurityWep = 2,
    kWirelessSecurityWpa = 3,
    // Value "802.11i/RSN" (4) is not used anymore.
    kWirelessSecurity8021x = 5,
    kWirelessSecurityPsk = 6,
    kWirelessSecurityWpa3 = 7,
    kWirelessSecurityWpaWpa2 = 8,
    kWirelessSecurityWpa2 = 9,
    kWirelessSecurityWpa2Wpa3 = 10,
    kWirelessSecurityWpaEnterprise = 11,
    kWirelessSecurityWpaWpa2Enterprise = 12,
    kWirelessSecurityWpa2Enterprise = 13,
    kWirelessSecurityWpa2Wpa3Enterprise = 14,
    kWirelessSecurityWpa3Enterprise = 15,
    kWirelessSecurityWpaAll = 16,
    kWirelessSecurityWpaAllEnterprise = 17,
    kWirelessSecurityWepEnterprise = 18,

    kWirelessSecurityMax
  };

  enum WirelessSecurityChange {
    kWirelessSecurityChangeWpa3ToWpa23 = 0,
    kWirelessSecurityChangeWpa3ToWpa123 = 1,
    kWirelessSecurityChangeWpa23ToWpa123 = 2,
    kWirelessSecurityChangeWpa2ToWpa12 = 3,
    kWirelessSecurityChangeEAPWpa3ToWpa23 = 4,
    kWirelessSecurityChangeEAPWpa3ToWpa123 = 5,
    kWirelessSecurityChangeEAPWpa23ToWpa123 = 6,
    kWirelessSecurityChangeEAPWpa2ToWpa12 = 7,
    kWirelessSecurityChangeWpa12ToWpa123 = 8,
    kWirelessSecurityChangeEAPWpa12ToWpa123 = 9,

    kWirelessSecurityChangeMax
  };

  // The result of the portal detection. TODO(b/236387876): Deprecate.
  enum PortalResult {
    kPortalResultSuccess = 0,
    kPortalResultDNSFailure = 1,
    kPortalResultDNSTimeout = 2,
    kPortalResultConnectionFailure = 3,
    kPortalResultConnectionTimeout = 4,
    kPortalResultHTTPFailure = 5,
    kPortalResultHTTPTimeout = 6,
    kPortalResultContentFailure = 7,
    kPortalResultContentTimeout = 8,
    kPortalResultUnknown = 9,
    kPortalResultContentRedirect = 10,

    kPortalResultMax
  };
  static constexpr EnumMetric<NameByTechnology> kMetricPortalResult = {
      .n = NameByTechnology{"PortalResult"},
      .max = kPortalResultMax,
  };

  // Updated portal detector results. See b/236387876 for details.
  enum PortalDetectorResult {
    kPortalDetectorResultUnknown = 0,
    kPortalDetectorResultConnectionFailure = 1,
    kPortalDetectorResultDNSFailure = 2,
    kPortalDetectorResultDNSTimeout = 3,
    kPortalDetectorResultHTTPFailure = 4,
    kPortalDetectorResultHTTPTimeout = 5,
    kPortalDetectorResultContentFailure = 6,
    kPortalDetectorResultContentTimeout = 7,
    kPortalDetectorResultRedirectFound = 8,
    kPortalDetectorResultRedirectNoUrl = 9,
    kPortalDetectorResultHTTPSFailure = 10,
    kPortalDetectorResultNoConnectivity = 11,
    kPortalDetectorResultOnline = 12,
    kPortalDetectorResultMax = 13,
  };
  static constexpr EnumMetric<NameByTechnology> kPortalDetectorInitialResult = {
      .n = NameByTechnology{"PortalDetector.InitialResult",
                            TechnologyLocation::kAfterName},
      .max = kPortalDetectorResultMax,
  };
  static constexpr EnumMetric<NameByTechnology> kPortalDetectorRetryResult = {
      .n = NameByTechnology{"PortalDetector.RepeatResult",
                            TechnologyLocation::kAfterName},
      .max = kPortalDetectorResultMax,
  };

  // patchpanel::NeighborLinkMonitor statistics.
  enum NeighborLinkMonitorFailure {
    kNeighborLinkMonitorFailureUnknown = 0,
    kNeighborIPv4GatewayFailure = 1,
    kNeighborIPv4DNSServerFailure = 2,
    kNeighborIPv4GatewayAndDNSServerFailure = 3,
    kNeighborIPv6GatewayFailure = 4,
    kNeighborIPv6DNSServerFailure = 5,
    kNeighborIPv6GatewayAndDNSServerFailure = 6,

    kNeighborLinkMonitorFailureMax
  };
  static constexpr EnumMetric<NameByTechnology>
      kMetricNeighborLinkMonitorFailure = {
          .n = NameByTechnology{"NeighborLinkMonitorFailure"},
          .max = kNeighborLinkMonitorFailureMax,
      };

  enum WiFiApChannelSwitch {
    kWiFiApChannelSwitchUndef = 0,
    kWiFiApChannelSwitch24To24 = 1,
    kWiFiApChannelSwitch24To5 = 2,
    kWiFiApChannelSwitch5To24 = 3,
    kWiFiApChannelSwitch5To5 = 4,

    kWiFiApChannelSwitchMax
  };
  static constexpr EnumMetric<FixedName> kMetricApChannelSwitch = {
      .n = FixedName{"Network.Shill.WiFi.ApChannelSwitch"},
      .max = kWiFiApChannelSwitchMax,
  };

  // AP 802.11r support statistics.
  enum WiFiAp80211rSupport {
    kWiFiAp80211rNone = 0,
    kWiFiAp80211rOTA = 1,
    kWiFiAp80211rOTDS = 2,

    kWiFiAp80211rMax
  };
  static constexpr EnumMetric<FixedName> kMetricAp80211rSupport = {
      .n = FixedName{"Network.Shill.WiFi.Ap80211rSupport"},
      .max = kWiFiAp80211rMax,
  };

  // AP stream classification support metric.
  enum WiFiApSCSupport {
    kWiFiApSCUnsupported = 0,
    kWiFiApSCS = 1,
    kWiFiApMSCS = 2,
    kWiFiApSCBoth = 3,

    kWiFiApSCMax
  };
  static constexpr EnumMetric<FixedName> kMetricApSCSupport = {
      .n = FixedName{"Network.Shill.WiFi.ApSCSupport"},
      .max = kWiFiApSCMax,
  };

  // Alternate EDCA support metric.
  static constexpr char kMetricApAlternateEDCASupport[] =
      "Network.Shill.WiFi.ApAlternateEDCASupport";

  enum WiFiRoamComplete {
    kWiFiRoamSuccess = 0,
    kWiFiRoamFailure = 1,

    kWiFiRoamCompleteMax
  };

  enum WiFiCQMReason {
    kWiFiCQMPacketLoss = 0,
    kWiFiCQMBeaconLoss = 1,

    kWiFiCQMMax
  };

  enum WiFiReasonType {
    kReasonCodeTypeByAp,
    kReasonCodeTypeByClient,
    kReasonCodeTypeByUser,
    kReasonCodeTypeConsideredDead,
    kReasonCodeTypeMax
  };
  static constexpr EnumMetric<FixedName> kMetricLinkClientDisconnectType = {
      .n = FixedName{"Network.Shill.WiFi.ClientDisconnectType"},
      .max = kReasonCodeTypeMax,
  };
  static constexpr EnumMetric<FixedName> kMetricLinkApDisconnectType = {
      .n = FixedName{"Network.Shill.WiFi.ApDisconnectType"},
      .max = kReasonCodeTypeMax,
  };

  enum WiFiDisconnectByWhom { kDisconnectedByAp, kDisconnectedNotByAp };

  enum WiFiScanResult {
    kScanResultProgressiveConnected,
    kScanResultProgressiveErrorAndFullFoundNothing,
    kScanResultProgressiveErrorButFullConnected,
    kScanResultProgressiveAndFullFoundNothing,
    kScanResultProgressiveAndFullConnected,
    kScanResultFullScanFoundNothing,
    kScanResultFullScanConnected,
    kScanResultInternalError,
    kScanResultMax
  };
  static constexpr EnumMetric<FixedName> kMetricScanResult = {
      .n = FixedName{"Network.Shill.WiFi.ScanResult"},
      .max = kScanResultMax,
  };

  enum Cellular3GPPRegistrationDelayedDrop {
    kCellular3GPPRegistrationDelayedDropPosted = 0,
    kCellular3GPPRegistrationDelayedDropCanceled = 1,
    kCellular3GPPRegistrationDelayedDropMax
  };
  static constexpr EnumMetric<FixedName>
      kMetricCellular3GPPRegistrationDelayedDrop = {
          .n = FixedName{"Network.Shill.Cellular.3GPPRegistrationDelayedDrop"},
          .max = kCellular3GPPRegistrationDelayedDropMax,
      };

  enum CellularApnSource {
    kCellularApnSourceMoDb = 0,
    kCellularApnSourceUi = 1,
    kCellularApnSourceModem = 2,
    kCellularApnSourceFallback = 3,
    kCellularApnSourceMax
  };

  enum CellularDropTechnology {
    kCellularDropTechnology1Xrtt = 0,
    kCellularDropTechnologyEdge = 1,
    kCellularDropTechnologyEvdo = 2,
    kCellularDropTechnologyGprs = 3,
    kCellularDropTechnologyGsm = 4,
    kCellularDropTechnologyHspa = 5,
    kCellularDropTechnologyHspaPlus = 6,
    kCellularDropTechnologyLte = 7,
    kCellularDropTechnologyUmts = 8,
    kCellularDropTechnologyUnknown = 9,
    kCellularDropTechnology5gNr = 10,
    kCellularDropTechnologyMax
  };
  static constexpr EnumMetric<FixedName> kMetricCellularDrop = {
      .n = FixedName{"Network.Shill.Cellular.Drop"},
      .max = kCellularDropTechnologyMax,
  };

  // These metrics enum values should not be renumbered or overwritten.
  enum CellularEntitlementCheck {
    kCellularEntitlementCheckAllowed = 0,
    kCellularEntitlementCheckInProgress = 1,
    kCellularEntitlementCheckFailedToBuildPayload = 2,
    kCellularEntitlementCheckFailedToParseIp = 3,
    kCellularEntitlementCheckUnexpectedRequestId = 4,
    kCellularEntitlementCheckUserNotAllowedToTether = 5,
    kCellularEntitlementCheckHttpSyntaxErrorOnServer = 6,
    kCellularEntitlementCheckUnrecognizedUser = 7,
    kCellularEntitlementCheckInternalErrorOnServer = 8,
    kCellularEntitlementCheckUnrecognizedErrorCode = 9,
    kCellularEntitlementCheckUnrecognizedHttpStatusCode = 10,
    kCellularEntitlementCheckHttpRequestError = 11,
    kCellularEntitlementCheckIllegalInProgress = 12,
    kCellularEntitlementCheckNotAllowedByModb = 13,
    kCellularEntitlementCheckUnknownCarrier = 14,
    kCellularEntitlementCheckNoIp = 15,
    kCellularEntitlementCheckNoCellularDevice = 16,
    kCellularEntitlementCheckMax
  };
  static constexpr EnumMetric<FixedName> kMetricCellularEntitlementCheck = {
      .n = FixedName{"Network.Shill.Cellular.EntitlementCheck"},
      .max = kCellularEntitlementCheckMax,
  };

  // These values are persisted to logs for
  // Network.Shill.Cellular.ConnectResult. CellularConnectResult entries should
  // not be renumbered and numeric values should never be reused.
  enum class CellularConnectResult {
    kCellularConnectResultSuccess = 0,
    kCellularConnectResultUnknown = 1,
    kCellularConnectResultWrongState = 2,
    kCellularConnectResultOperationFailed = 3,
    kCellularConnectResultAlreadyConnected = 4,
    kCellularConnectResultNotRegistered = 5,
    kCellularConnectResultNotOnHomeNetwork = 6,
    kCellularConnectResultIncorrectPin = 7,
    kCellularConnectResultPinRequired = 8,
    kCellularConnectResultPinBlocked = 9,
    kCellularConnectResultInvalidApn = 10,
    kCellularConnectResultInternalError = 11,
    kCellularConnectResultMax
  };

  static constexpr EnumMetric<NameByApnType> kMetricCellularConnectResult = {
      .n = NameByApnType{"ConnectResult"},
      .max = static_cast<int>(CellularConnectResult::kCellularConnectResultMax),
  };

  enum CellularRoamingState {
    kCellularRoamingStateUnknown = 0,
    kCellularRoamingStateHome = 1,
    kCellularRoamingStateRoaming = 2,
    kCellularRoamingStateMax
  };
  // The |CellularApnType| values represent a bit mask, so each following value
  // has to be the next multiple of 2- i.e., 1, 2, 4, 8, ...
  enum class CellularApnType {
    kCellularApnTypeDefault = 1,
    kCellularApnTypeIA = 2,
    kCellularApnTypeDun = 4,
  };

  // Connection diagnostics issue produced by ConnectionDiagnostics.
  enum ConnectionDiagnosticsIssue {
    kConnectionDiagnosticsIssueIPCollision = 0,
    kConnectionDiagnosticsIssueRouting = 1,
    kConnectionDiagnosticsIssueHTTP = 2,
    kConnectionDiagnosticsIssueDNSServerMisconfig = 3,
    kConnectionDiagnosticsIssueDNSServerNoResponse = 4,
    kConnectionDiagnosticsIssueNoDNSServersConfigured = 5,
    kConnectionDiagnosticsIssueDNSServersInvalid = 6,
    kConnectionDiagnosticsIssueNone = 7,
    // Not logged anymore
    kConnectionDiagnosticsIssueCaptivePortal = 8,
    kConnectionDiagnosticsIssueGatewayUpstream = 9,
    kConnectionDiagnosticsIssueGatewayNotResponding = 10,
    kConnectionDiagnosticsIssueServerNotResponding = 11,
    kConnectionDiagnosticsIssueGatewayArpFailed = 12,
    kConnectionDiagnosticsIssueServerArpFailed = 13,
    kConnectionDiagnosticsIssueInternalError = 14,
    kConnectionDiagnosticsIssueGatewayNoNeighborEntry = 15,
    kConnectionDiagnosticsIssueServerNoNeighborEntry = 16,
    kConnectionDiagnosticsIssueGatewayNeighborEntryNotConnected = 17,
    kConnectionDiagnosticsIssueServerNeighborEntryNotConnected = 18,
    kConnectionDiagnosticsIssuePlaceholder1 = 19,
    kConnectionDiagnosticsIssuePlaceholder2 = 20,
    kConnectionDiagnosticsIssuePlaceholder3 = 21,
    kConnectionDiagnosticsIssuePlaceholder4 = 22,
    kConnectionDiagnosticsIssueMax
  };
  static constexpr EnumMetric<FixedName> kMetricConnectionDiagnosticsIssue = {
      .n = FixedName{"Network.Shill.ConnectionDiagnosticsIssue"},
      .max = kConnectionDiagnosticsIssueMax,
  };

  enum VpnDriver {
    kVpnDriverOpenVpn = 0,
    kVpnDriverL2tpIpsec = 1,
    kVpnDriverThirdParty = 2,
    kVpnDriverArc = 3,
    // 4 is occupied by PPTP in chrome.
    kVpnDriverWireGuard = 5,
    kVpnDriverIKEv2 = 6,
    kVpnDriverMax
  };
  static constexpr EnumMetric<FixedName> kMetricVpnDriver = {
      .n = FixedName{"Network.Shill.Vpn.Driver"},
      .max = kVpnDriverMax,
  };

  enum EthernetDriver {
    kEthernetDriverUnknown = 0,
    kEthernetDriverAlx = 1,
    kEthernetDriverAqc111 = 2,
    kEthernetDriverAsix = 3,
    kEthernetDriverAtlantic = 4,
    kEthernetDriverAx88179_178a = 5,
    kEthernetDriverCdcEem = 6,
    kEthernetDriverCdcEther = 7,
    kEthernetDriverCdcMbim = 8,
    kEthernetDriverCdcNcm = 9,
    kEthernetDriverDm9601 = 10,
    kEthernetDriverE100 = 11,
    kEthernetDriverE1000 = 12,
    kEthernetDriverE1000e = 13,
    kEthernetDriverIgb = 14,
    kEthernetDriverIgbvf = 15,
    kEthernetDriverIgc = 16,
    kEthernetDriverIpheth = 17,
    kEthernetDriverJme = 18,
    kEthernetDriverMcs7830 = 19,
    kEthernetDriverPegasus = 20,
    kEthernetDriverR8152 = 21,
    kEthernetDriverR8169 = 22,
    kEthernetDriverRtl8150 = 23,
    kEthernetDriverSmsc75xx = 24,
    kEthernetDriverSmsc95xx = 25,
    kEthernetDriverTg3 = 26,
    kEthernetDriverError = 27,
    kEthernetDriverMax
  };
  static constexpr EnumMetric<FixedName> kMetricEthernetDriver = {
      .n = FixedName{"Network.Shill.Ethernet.Driver"},
      .max = kEthernetDriverMax,
  };

  // Remote authentication statistics for VPN connections.
  enum VpnRemoteAuthenticationType {
    kVpnRemoteAuthenticationTypeOpenVpnDefault = 0,
    kVpnRemoteAuthenticationTypeOpenVpnCertificate = 1,
    kVpnRemoteAuthenticationTypeL2tpIpsecDefault = 2,
    kVpnRemoteAuthenticationTypeL2tpIpsecCertificate = 3,
    kVpnRemoteAuthenticationTypeL2tpIpsecPsk = 4,
    kVpnRemoteAuthenticationTypeMax
  };
  static constexpr EnumMetric<FixedName> kMetricVpnRemoteAuthenticationType = {
      .n = FixedName{"Network.Shill.Vpn.RemoteAuthenticationType"},
      .max = kVpnRemoteAuthenticationTypeMax,
  };

  // User authentication type statistics for VPN connections.
  enum VpnUserAuthenticationType {
    kVpnUserAuthenticationTypeOpenVpnNone = 0,
    kVpnUserAuthenticationTypeOpenVpnCertificate = 1,
    kVpnUserAuthenticationTypeOpenVpnUsernamePassword = 2,
    kVpnUserAuthenticationTypeOpenVpnUsernamePasswordOtp = 3,
    kVpnUserAuthenticationTypeOpenVpnUsernameToken = 7,
    kVpnUserAuthenticationTypeL2tpIpsecNone = 4,
    kVpnUserAuthenticationTypeL2tpIpsecCertificate = 5,
    kVpnUserAuthenticationTypeL2tpIpsecUsernamePassword = 6,
    kVpnUserAuthenticationTypeMax
  };
  static constexpr EnumMetric<FixedName> kMetricVpnUserAuthenticationType = {
      .n = FixedName{"Network.Shill.Vpn.UserAuthenticationType"},
      .max = kVpnUserAuthenticationTypeMax,
  };

  // IKEv2 IPsec authentication statistics.
  enum VpnIpsecAuthenticationType {
    kVpnIpsecAuthenticationTypeUnknown = 0,
    kVpnIpsecAuthenticationTypePsk = 1,
    kVpnIpsecAuthenticationTypeEap = 2,
    kVpnIpsecAuthenticationTypeCertificate = 3,
    kVpnIpsecAuthenticationTypeMax
  };
  static constexpr EnumMetric<FixedName> kMetricVpnIkev2AuthenticationType = {
      .n = FixedName{"Network.Shill.Vpn.Ikev2.AuthenticationType"},
      .max = kVpnIpsecAuthenticationTypeMax,
  };

  // L2TP/IPsec group usage statistics.
  enum VpnL2tpIpsecTunnelGroupUsage {
    kVpnL2tpIpsecTunnelGroupUsageNo = 0,
    kVpnL2tpIpsecTunnelGroupUsageYes = 1,
    kVpnL2tpIpsecTunnelGroupUsageMax
  };
  static constexpr EnumMetric<FixedName> kMetricVpnL2tpIpsecTunnelGroupUsage = {
      .n = FixedName{"Network.Shill.Vpn.L2tpIpsecTunnelGroupUsage"},
      .max = kVpnL2tpIpsecTunnelGroupUsageMax,
  };

  enum IPType {
    kIPTypeUnknown = 0,
    kIPTypeIPv4Only = 1,
    kIPTypeIPv6Only = 2,
    kIPTypeDualStack = 3,
    kIPTypeMax
  };
  static constexpr EnumMetric<NameByTechnology> kMetricIPType = {
      .n = NameByTechnology{"IPType"},
      .max = kIPTypeMax,
  };
  // IPType for VPN is a separate metric because:
  // 1) IP provisioning for VPN always happens before VPN is connected, while
  //    it's not the case for other technologies, and thus the reporting timings
  //    are different;
  // 2) We need per-VPN-type metrics for VPN.
  static constexpr EnumMetric<NameByVPNType> kMetricVpnIPType = {
      .n = NameByVPNType{"IPType"},
      .max = kIPTypeMax,
  };

  // This enum contains the encryption algorithms we are using for IPsec now,
  // but not the complete list of algorithms which are supported by strongswan.
  // It is the same for the following enums for integrity algorithms and DH
  // groups.
  enum VpnIpsecEncryptionAlgorithm {
    kVpnIpsecEncryptionAlgorithmUnknown = 0,

    kVpnIpsecEncryptionAlgorithm_AES_CBC_128 = 1,
    kVpnIpsecEncryptionAlgorithm_AES_CBC_192 = 2,
    kVpnIpsecEncryptionAlgorithm_AES_CBC_256 = 3,
    kVpnIpsecEncryptionAlgorithm_CAMELLIA_CBC_128 = 4,
    kVpnIpsecEncryptionAlgorithm_CAMELLIA_CBC_192 = 5,
    kVpnIpsecEncryptionAlgorithm_CAMELLIA_CBC_256 = 6,
    kVpnIpsecEncryptionAlgorithm_3DES_CBC = 7,
    kVpnIpsecEncryptionAlgorithm_AES_GCM_16_128 = 8,
    kVpnIpsecEncryptionAlgorithm_AES_GCM_16_192 = 9,
    kVpnIpsecEncryptionAlgorithm_AES_GCM_16_256 = 10,
    kVpnIpsecEncryptionAlgorithm_AES_GCM_12_128 = 11,
    kVpnIpsecEncryptionAlgorithm_AES_GCM_12_192 = 12,
    kVpnIpsecEncryptionAlgorithm_AES_GCM_12_256 = 13,
    kVpnIpsecEncryptionAlgorithm_AES_GCM_8_128 = 14,
    kVpnIpsecEncryptionAlgorithm_AES_GCM_8_192 = 15,
    kVpnIpsecEncryptionAlgorithm_AES_GCM_8_256 = 16,

    kVpnIpsecEncryptionAlgorithmMax,
  };
  static constexpr EnumMetric<NameByVPNType> kMetricVpnIkeEncryptionAlgorithm =
      {
          .n = NameByVPNType{"IkeEncryptionAlgorithm"},
          .max = kVpnIpsecEncryptionAlgorithmMax,
      };
  static constexpr EnumMetric<NameByVPNType> kMetricVpnEspEncryptionAlgorithm =
      {
          .n = NameByVPNType{"EspEncryptionAlgorithm"},
          .max = kVpnIpsecEncryptionAlgorithmMax,
      };

  enum VpnIpsecIntegrityAlgorithm {
    kVpnIpsecIntegrityAlgorithmUnknown = 0,

    kVpnIpsecIntegrityAlgorithm_HMAC_SHA2_256_128 = 1,
    kVpnIpsecIntegrityAlgorithm_HMAC_SHA2_384_192 = 2,
    kVpnIpsecIntegrityAlgorithm_HMAC_SHA2_512_256 = 3,
    kVpnIpsecIntegrityAlgorithm_HMAC_SHA1_96 = 4,
    kVpnIpsecIntegrityAlgorithm_AES_XCBC_96 = 5,
    kVpnIpsecIntegrityAlgorithm_AES_CMAC_96 = 6,

    kVpnIpsecIntegrityAlgorithmMax,
  };
  static constexpr EnumMetric<NameByVPNType> kMetricVpnIkeIntegrityAlgorithm = {
      .n = NameByVPNType{"IkeIntegrityAlgorithm"},
      .max = kVpnIpsecIntegrityAlgorithmMax,
  };
  static constexpr EnumMetric<NameByVPNType> kMetricVpnEspIntegrityAlgorithm = {
      .n = NameByVPNType{"EspIntegrityAlgorithm"},
      .max = kVpnIpsecIntegrityAlgorithmMax,
  };

  enum VpnIpsecDHGroup {
    kVpnIpsecDHGroupUnknown = 0,

    kVpnIpsecDHGroup_ECP_256 = 1,
    kVpnIpsecDHGroup_ECP_384 = 2,
    kVpnIpsecDHGroup_ECP_521 = 3,
    kVpnIpsecDHGroup_ECP_256_BP = 4,
    kVpnIpsecDHGroup_ECP_384_BP = 5,
    kVpnIpsecDHGroup_ECP_512_BP = 6,
    kVpnIpsecDHGroup_CURVE_25519 = 7,
    kVpnIpsecDHGroup_CURVE_448 = 8,
    kVpnIpsecDHGroup_MODP_1024 = 9,
    kVpnIpsecDHGroup_MODP_1536 = 10,
    kVpnIpsecDHGroup_MODP_2048 = 11,
    kVpnIpsecDHGroup_MODP_3072 = 12,
    kVpnIpsecDHGroup_MODP_4096 = 13,
    kVpnIpsecDHGroup_MODP_6144 = 14,
    kVpnIpsecDHGroup_MODP_8192 = 15,

    kVpnIpsecDHGroupMax,
  };
  static constexpr EnumMetric<NameByVPNType> kMetricVpnIkeDHGroup = {
      .n = NameByVPNType{"IkeDHGroup"},
      .max = kVpnIpsecDHGroupMax,
  };

  // OpenVPN cipher algorithm used after negotiating with server.
  enum VpnOpenVPNCipher {
    kVpnOpenVPNCipherUnknown = 0,
    kVpnOpenVPNCipher_BF_CBC = 1,
    kVpnOpenVPNCipher_AES_256_GCM = 2,
    kVpnOpenVPNCipher_AES_128_GCM = 3,
    kVpnOpenVPNCipherMax
  };
  static constexpr EnumMetric<FixedName> kMetricVpnOpenVPNCipher = {
      .n = FixedName{"Network.Shill.Vpn.OpenVPNCipher"},
      .max = kVpnOpenVPNCipherMax,
  };

  // Key pair source (e.g., user input) used in a WireGuard Connection.
  enum VpnWireGuardKeyPairSource {
    kVpnWireguardKeyPairSourceUnknown = 0,
    kVpnWireGuardKeyPairSourceUserInput = 1,
    kVpnWireGuardKeyPairSourceSoftwareGenerated = 2,
    kVpnWireGuardKeyPairSourceMax
  };
  static constexpr EnumMetric<FixedName> kMetricVpnWireGuardKeyPairSource = {
      .n = FixedName{"Network.Shill.Vpn.WireGuardKeyPairSource"},
      .max = kVpnWireGuardKeyPairSourceMax,
  };

  // Allowed IPs type used in a WireGuard connection.
  enum VpnWireGuardAllowedIPsType {
    kVpnWireGuardAllowedIPsTypeHasDefaultRoute = 0,
    kVpnWireGuardAllowedIPsTypeNoDefaultRoute = 1,
    kVpnWireGuardAllowedIPsTypeMax
  };
  static constexpr EnumMetric<FixedName> kMetricVpnWireGuardAllowedIPsType = {
      .n = FixedName{"Network.Shill.Vpn.WireGuardAllowedIPsType"},
      .max = kVpnWireGuardAllowedIPsTypeMax,
  };

  // Result of a connection initiated by Service::UserInitiatedConnect.
  enum UserInitiatedConnectionResult {
    kUserInitiatedConnectionResultSuccess = 0,
    kUserInitiatedConnectionResultFailure = 1,
    kUserInitiatedConnectionResultAborted = 2,
    kUserInitiatedConnectionResultMax
  };
  static constexpr EnumMetric<FixedName>
      kMetricWifiUserInitiatedConnectionResult = {
          .n = FixedName{"Network.Shill.WiFi.UserInitiatedConnectionResult"},
          .max = kUserInitiatedConnectionResultMax,
      };

  // Reason when a connection initiated by Service::UserInitiatedConnect fails.
  enum UserInitiatedConnectionFailureReason {
    kUserInitiatedConnectionFailureReasonBadPassphrase = 1,
    kUserInitiatedConnectionFailureReasonBadWEPKey = 2,
    kUserInitiatedConnectionFailureReasonConnect = 3,
    kUserInitiatedConnectionFailureReasonDHCP = 4,
    kUserInitiatedConnectionFailureReasonDNSLookup = 5,
    kUserInitiatedConnectionFailureReasonEAPAuthentication = 6,
    kUserInitiatedConnectionFailureReasonEAPLocalTLS = 7,
    kUserInitiatedConnectionFailureReasonEAPRemoteTLS = 8,
    kUserInitiatedConnectionFailureReasonOutOfRange = 9,
    kUserInitiatedConnectionFailureReasonPinMissing = 10,
    kUserInitiatedConnectionFailureReasonUnknown = 11,
    kUserInitiatedConnectionFailureReasonNone = 12,
    kUserInitiatedConnectionFailureReasonNotAssociated = 13,
    kUserInitiatedConnectionFailureReasonNotAuthenticated = 14,
    kUserInitiatedConnectionFailureReasonTooManySTAs = 15,
    kUserInitiatedConnectionFailureReasonMax
  };
  static constexpr EnumMetric<FixedName>
      kMetricWifiUserInitiatedConnectionFailureReason = {
          .n =
              FixedName{
                  "Network.Shill.WiFi.UserInitiatedConnectionFailureReason"},
          .max = kUserInitiatedConnectionFailureReasonMax,
      };

  // Device presence.
  enum DevicePresenceStatus {
    kDevicePresenceStatusNo = 0,
    kDevicePresenceStatusYes = 1,
    kDevicePresenceStatusMax
  };
  static constexpr EnumMetric<NameByTechnology> kMetricDevicePresenceStatus = {
      .n = NameByTechnology{"DevicePresenceStatus"},
      .max = kDevicePresenceStatusMax,
  };

  enum DeviceTechnologyType {
    kDeviceTechnologyTypeUnknown = 0,
    kDeviceTechnologyTypeEthernet = 1,
    kDeviceTechnologyTypeWifi = 2,
    // deprecated: kDeviceTechnologyTypeWimax = 3,
    kDeviceTechnologyTypeCellular = 4,
    kDeviceTechnologyTypeMax
  };

  // These correspond to entries in Chrome's tools/metrics/histograms/enums.xml.
  // Please do not remove entries (append 'Deprecated' instead), and update the
  // enums.xml file when entries are added.
  enum NetworkServiceError {
    kNetworkServiceErrorNone = 0,
    kNetworkServiceErrorAAA = 1,
    kNetworkServiceErrorActivation = 2,
    kNetworkServiceErrorBadPassphrase = 3,
    kNetworkServiceErrorBadWEPKey = 4,
    kNetworkServiceErrorConnect = 5,
    kNetworkServiceErrorDHCP = 6,
    kNetworkServiceErrorDNSLookup = 7,
    kNetworkServiceErrorEAPAuthentication = 8,
    kNetworkServiceErrorEAPLocalTLS = 9,
    kNetworkServiceErrorEAPRemoteTLS = 10,
    kNetworkServiceErrorHTTPGet = 11,
    kNetworkServiceErrorIPsecCertAuth = 12,
    kNetworkServiceErrorIPsecPSKAuth = 13,
    kNetworkServiceErrorInternal = 14,
    kNetworkServiceErrorNeedEVDO = 15,
    kNetworkServiceErrorNeedHomeNetwork = 16,
    kNetworkServiceErrorOTASP = 17,
    kNetworkServiceErrorOutOfRange = 18,
    kNetworkServiceErrorPPPAuth = 19,
    kNetworkServiceErrorPinMissing = 20,
    kNetworkServiceErrorUnknown = 21,
    kNetworkServiceErrorNotAssociated = 22,
    kNetworkServiceErrorNotAuthenticated = 23,
    kNetworkServiceErrorTooManySTAs = 24,
    kNetworkServiceErrorDisconnect = 25,
    kNetworkServiceErrorSimLocked = 26,
    kNetworkServiceErrorNotRegistered = 27,
    kNetworkServiceErrorInvalidAPN = 28,
    kNetworkServiceErrorMax
  };
  static constexpr EnumMetric<NameByTechnology> kMetricNetworkServiceError = {
      .n = NameByTechnology{"ServiceErrors"},
      .max = kNetworkServiceErrorMax,
  };
  static constexpr EnumMetric<FixedName> kMetricVpnIkev2EndReason = {
      .n = FixedName{"Network.Shill.Vpn.Ikev2.EndReason"},
      .max = kNetworkServiceErrorMax,
  };
  // Temporary metrics for comparing the robustness of the two L2TP/IPsec
  // drivers (b/204261554).
  static constexpr EnumMetric<FixedName> kMetricVpnL2tpIpsecSwanctlEndReason = {
      .n = FixedName{"Network.Shill.Vpn.L2tpIpsec.SwanctlEndReason"},
      .max = kNetworkServiceErrorMax,
  };
  static constexpr EnumMetric<FixedName> kMetricVpnL2tpIpsecStrokeEndReason = {
      .n = FixedName{"Network.Shill.Vpn.L2tpIpsec.StrokeEndReason"},
      .max = kNetworkServiceErrorMax,
  };
  static constexpr EnumMetric<FixedName> kMetricPasspointConnectionResult = {
      .n = FixedName{"Network.Shill.WiFi.Passpoint.ConnectionResult"},
      .max = kNetworkServiceErrorMax,
  };

  // Corresponds to RegulatoryDomain enum values in
  // /chromium/src/tools/metrics/histograms/enums.xml.
  // kRegDom00, kRegDom99, kRegDom98 and kRegDom97 are special alpha2 codes
  enum RegulatoryDomain {
    kRegDom00 = 1,
    kCountryCodeInvalid = 678,
    kRegDom99 = 679,
    kRegDom98 = 680,
    kRegDom97 = 681,
    kRegDomMaxValue
  };

  // Hotspot 2.0 version number metric.
  enum HS20Support {
    kHS20Unsupported = 0,
    kHS20VersionInvalid = 1,
    kHS20Version1 = 2,
    kHS20Version2 = 3,
    kHS20Version3 = 4,
    kHS20SupportMax
  };
  static constexpr EnumMetric<FixedName> kMetricHS20Support = {
      .n = FixedName{"Network.Shill.WiFi.HS20Support"},
      .max = kHS20SupportMax,
  };

  // Is the WiFi adapter detected on the system in the allowlist of adapters
  // that can be reported through structured metrics or not?
  enum WiFiAdapterInAllowlist {
    kNotInAllowlist = 0,
    kInAVL = 1,
    kInAllowlist = 2,
    kAllowlistMax
  };
  static constexpr EnumMetric<FixedName> kMetricAdapterInfoAllowlisted = {
      .n = FixedName{"Network.Shill.WiFi.AdapterAllowlisted"},
      .max = kAllowlistMax,
  };

  static constexpr int kTimerHistogramNumBuckets = 50;
  static constexpr int kTimerHistogramNumBucketsLarge = 150;

  static constexpr HistogramMetric<NameByTechnology> kMetricTimeOnlineSeconds =
      {
          .n = NameByTechnology{"TimeOnline"},
          .min = 1,
          .max = 8 * 60 * 60,  // 8 hours
          .num_buckets = kTimerHistogramNumBuckets,
      };

  static constexpr HistogramMetric<FixedName> kMetricTimeToDropSeconds = {
      .n = FixedName{"Network.Shill.TimeToDrop"},
      .min = 1,
      .max = 8 * 60 * 60,  // 8 hours
      .num_buckets = kTimerHistogramNumBuckets,
  };

  // Our disconnect enumeration values are 0 (System Disconnect) and
  // 1 (User Disconnect), see histograms.xml, but Chrome needs a minimum
  // enum value of 1 and the minimum number of buckets needs to be 3 (see
  // histogram.h).  Instead of remapping System Disconnect to 1 and
  // User Disconnect to 2, we can just leave the enumerated values as-is
  // because Chrome implicitly creates a [0-1) bucket for us.  Using Min=1,
  // Max=2 and NumBuckets=3 gives us the following three buckets:
  // [0-1), [1-2), [2-INT_MAX).  We end up with an extra bucket [2-INT_MAX)
  // that we can safely ignore.
  static constexpr HistogramMetric<FixedName> kMetricWiFiDisconnect = {
      // "Wifi" is used instead of "WiFi" because the name of this metric used
      // to be derived from the display name of Technology::kWiFi.
      .n = FixedName{"Network.Shill.Wifi.Disconnect"},
      .min = 1,
      .max = 2,
      .num_buckets = 3,
  };

  static constexpr HistogramMetric<FixedName> kMetricWiFiSignalAtDisconnect = {
      // "Wifi" is used instead of "WiFi" because the name of this metric used
      // to be derived from the display name of Technology::kWiFi.
      .n = FixedName{"Network.Shill.Wifi.SignalAtDisconnect"},
      .min = 1,
      .max = 200,
      .num_buckets = 40,
  };

  static constexpr char kMetricNetworkChannelSuffix[] = "Channel";
  static constexpr int kMetricNetworkChannelMax = kWiFiChannelMax;
  static constexpr char kMetricNetworkPhyModeSuffix[] = "PhyMode";
  static constexpr int kMetricNetworkPhyModeMax = kWiFiNetworkPhyModeMax;
  static constexpr char kMetricNetworkSecuritySuffix[] = "Security";
  static constexpr int kMetricNetworkSecurityMax = kWirelessSecurityMax;
  static constexpr char kMetricWirelessSecurityChange[] =
      "Network.Shill.Wifi.SecurityChange";
  static constexpr char kMetricNetworkSignalStrengthSuffix[] = "SignalStrength";
  static constexpr int kMetricNetworkSignalStrengthMin = 1;
  static constexpr int kMetricNetworkSignalStrengthMax = 200;
  static constexpr int kMetricNetworkSignalStrengthNumBuckets = 40;

  // Metric recorded during provisioning of Passpoint credentials with the
  // Manager AddPasspointCredentials() DBus API. Indicates it the call was
  // successful, if an error happened, or if the credentials were invalid.
  enum PasspointProvisioningResult {
    kPasspointProvisioningSuccess = 0,
    kPasspointProvisioningNoOrInvalidFqdn = 1,
    kPasspointProvisioningNoOrInvalidRealm = 2,
    kPasspointProvisioningInvalidEapMethod = 3,
    kPasspointProvisioningInvalidEapProperties = 4,
    kPasspointProvisioningInvalidOrganizationIdentifier = 5,
    kPasspointProvisioningInvalidExpirationTime = 6,
    kPasspointProvisioningShillProfileError = 7,

    kPasspointProvisioningMax,
  };
  static constexpr EnumMetric<FixedName> kMetricPasspointProvisioningResult = {
      .n = FixedName{"Network.Shill.WiFi.Passpoint.ProvisioningResult"},
      .max = kPasspointProvisioningMax,
  };

  // Metric recorded when removing Passpoint credentaisl with the
  // Manager RemovePasspointCredentials() DBus API.
  enum PasspointRemovalResult {
    kPasspointRemovalSuccess = 0,
    kPasspointRemovalNotFound = 1,
    kPasspointRemovalNoActiveUserProfile = 2,
    kPasspointRemovalFailure = 3,

    kPasspointRemovalMax,
  };
  static constexpr EnumMetric<FixedName> kMetricPasspointRemovalResult = {
      .n = FixedName{"Network.Shill.WiFi.Passpoint.RemovalResult"},
      .max = kPasspointRemovalMax,
  };

  // Metric indicating the provisioning origin of Passpoint credentials.
  // This metric is recorded once for any successful Passpoint provisioning
  // event.
  enum PasspointOrigin {
    // Unknown or unspecified origin.
    kPasspointOriginOther = 0,
    // Credentials came from an Android App.
    kPasspointOriginAndroid = 1,
    // Credentials came from a Policy.
    kPasspointOriginPolicy = 2,
    // Credentials came from a cellular carrier profile.
    kPasspointOriginCarrier = 3,

    kPasspointOriginMax,
  };
  static constexpr EnumMetric<FixedName> kMetricPasspointOrigin = {
      .n = FixedName{"Network.Shill.WiFi.Passpoint.Origin"},
      .max = kPasspointOriginMax,
  };

  // Metric indicating the EAP method used for a Passpoint credential
  // object. This metric is recorded once for any successful Passpoint
  // provisioning event.
  // TODO(b/207730857) Update this enum once EAP-SIM support for Passpoint
  // is available.
  enum PasspointSecurity {
    kPasspointSecurityUnknown = 0,
    kPasspointSecurityTLS = 1,
    kPasspointSecurityTTLSUnknown = 2,
    kPasspointSecurityTTLSPAP = 3,
    kPasspointSecurityTTLSMSCHAP = 4,
    kPasspointSecurityTTLSMSCHAPV2 = 5,

    kPasspointSecurityMax,
  };
  static constexpr EnumMetric<FixedName> kMetricPasspointSecurity = {
      .n = FixedName{"Network.Shill.WiFi.Passpoint.Security"},
      .max = kPasspointSecurityMax,
  };

  // Metric indicating if a Passpoint profile indicates all WiFi
  // connections established with its credentials should be considered metered
  // or not. This metric is recorded once for any successful Passpoint
  // provisioning event.
  enum PasspointMeteredness {
    // Services matching this Passpoint credentials should be considered
    // non-metered.
    kPasspointNotMetered = 0,
    // Services matching this Passpoint credentials should be considered
    // metered.
    kPasspointMetered = 1,

    kPasspointMeteredMax,
  };
  static constexpr EnumMetric<FixedName> kMetricPasspointMeteredness = {
      .n = FixedName{"Network.Shill.WiFi.Passpoint.Meteredness"},
      .max = kPasspointMeteredMax,
  };

  // Metric indicating the outcome of a Passpoint credentials match event.
  // Passpoint match events are generated by the supplicant during an
  // Interworking Select operation and processed by shill for updating the
  // associated WiFi Services as connectable using the Passpoint credentials.
  enum PasspointMatch {
    kPasspointNoMatch = 0,
    // The Service associated with the matching AP was not found.
    kPasspointMatchServiceNotFound = 1,
    // The AP had already matched with higher priority Passpoint credentials.
    kPasspointMatchPriorPasspointMatch = 2,
    // The service associated with the AP that matched has non-Passpoint
    // credentials of highier priority (PSK, non-Passpoint EAP).
    kPasspointMatchPriorCredentials = 3,
    // The AP had a prior Passpoint credentials match with a priority
    // lower than "Home". The associated Service will use the new Passpoint
    // credentials for future connections.
    kPasspointMatchUpgradeToHomeMatch = 4,
    // The AP had a prior Passpoint credentials match with priority
    // lower than "Roaming". The associated Service will use the new Passpoint
    // credentials for future connections.
    kPasspointMatchUpgradeToRoamingMatch = 5,
    // The AP matched for the first time with Home priority.
    kPasspointMatchNewHomeMatch = 6,
    // The AP matched for the first time with Roaming priority.
    kPasspointMatchNewRoamingMatch = 7,
    // The AP matched for the first time with unknown priority.
    kPasspointMatchNewUnknownMatch = 8,

    kPasspointMatchMax,
  };
  static constexpr EnumMetric<FixedName> kMetricPasspointMatch = {
      .n = FixedName{"Network.Shill.WiFi.Passpoint.Match"},
      .max = kPasspointMatchMax,
  };

  // Sparse histogram metric recording the number of "Home" service provider
  // FQDNs specified in a Passpoint profile. This metric is recorded once for
  // any successful Passpoint provisioning event.
  static constexpr char kMetricPasspointDomains[] =
      "Network.Shill.WiFi.Passpoint.Domains";

  // Sparse histogram metric recording the number of "Home" Organization
  // Identifiers specified in a Passpoint profile. This metric is recorded once
  // for any successful Passpoint provisioning event.
  static constexpr char kMetricPasspointHomeOis[] =
      "Network.Shill.WiFi.Passpoint.HomeOis";

  // Sparse histogram metric recording the number of required "Home"
  // Organization Identifiers specified in a Passpoint profile. This metric is
  // recorded once for any successful Passpoint provisioning event.
  static constexpr char kMetricPasspointRequiredHomeOis[] =
      "Network.Shill.WiFi.Passpoint.RequiredHomeOis";

  // Sparse histogram metric recording the number of "Roaming" Organization
  // Identifiers specified in a Passpoint profile. This metric is recorded once
  // for any successful Passpoint provisioning event.
  static constexpr char kMetricPasspointRoamingOis[] =
      "Network.Shill.WiFi.Passpoint.RoamingOis";

  // Sparse histogram metric recording the number of Passpoint credentials
  // matches found in a single Interworking select operation conducted by the
  // supplicant.
  static constexpr char kMetricPasspointInterworkingMatches[] =
      "Network.Shill.WiFi.Passpoint.InterworkingMatches";

  // Metric recording as an histogram the duration of an Interworking select
  // operation in milliseconds.
  static constexpr HistogramMetric<FixedName>
      kMetricPasspointInterworkingDurationMillis = {
          .n =
              FixedName{
                  "Network.Shill.WiFi.Passpoint.InterworkingDurationMillis"},
          .min = 1,
          .max = 20000,  // 20 seconds
          .num_buckets = kTimerHistogramNumBuckets,
      };

  // Sparse histogram metric recording the number of Passpoint credentials
  // saved for a user profile. This metric is recorded once every time the
  // WifiProvider loads a user profile.
  static constexpr char kMetricPasspointSavedCredentials[] =
      "Network.Shill.WiFi.Passpoint.SavedCredentials";

  static constexpr int kMetricRememberedWiFiNetworkCountMax = 1024;
  static constexpr int kMetricRememberedWiFiNetworkCountMin = 1;
  static constexpr int kMetricRememberedWiFiNetworkCountNumBuckets = 32;
  static constexpr HistogramMetric<PrefixName>
      kMetricRememberedSystemWiFiNetworkCountBySecurityModeFormat = {
          .n = PrefixName{"Network.Shill.WiFi.RememberedSystemNetworkCount."},
          .min = kMetricRememberedWiFiNetworkCountMin,
          .max = kMetricRememberedWiFiNetworkCountMax,
          .num_buckets = kMetricRememberedWiFiNetworkCountNumBuckets,
      };
  static constexpr HistogramMetric<PrefixName>
      kMetricRememberedUserWiFiNetworkCountBySecurityModeFormat = {
          .n = PrefixName{"Network.Shill.WiFi.RememberedUserNetworkCount."},
          .min = kMetricRememberedWiFiNetworkCountMin,
          .max = kMetricRememberedWiFiNetworkCountMax,
          .num_buckets = kMetricRememberedWiFiNetworkCountNumBuckets,
      };
  static constexpr HistogramMetric<FixedName>
      kMetricRememberedWiFiNetworkCount = {
          .n = FixedName{"Network.Shill.WiFi.RememberedNetworkCount"},
          .min = kMetricRememberedWiFiNetworkCountMin,
          .max = kMetricRememberedWiFiNetworkCountMax,
          .num_buckets = kMetricRememberedWiFiNetworkCountNumBuckets,
      };
  static constexpr HistogramMetric<FixedName> kMetricPasspointNetworkCount = {
      .n = FixedName{"Network.Shill.WiFi.PasspointNetworkCount"},
      .min = kMetricRememberedWiFiNetworkCountMin,
      .max = kMetricRememberedWiFiNetworkCountMax,
      .num_buckets = kMetricRememberedWiFiNetworkCountNumBuckets,
  };
  static constexpr HistogramMetric<FixedName> kMetricHiddenSSIDNetworkCount = {
      .n = FixedName{"Network.Shill.WiFi.HiddenSSIDNetworkCount"},
      .min = kMetricRememberedWiFiNetworkCountMin,
      .max = kMetricRememberedWiFiNetworkCountMax,
      .num_buckets = kMetricRememberedWiFiNetworkCountNumBuckets,
  };

  static constexpr char kMetricHiddenSSIDEverConnected[] =
      "Network.Shill.WiFi.HiddenSSIDEverConnected";
  static constexpr char kMetricWiFiCQMNotification[] =
      "Network.Shill.WiFi.CQMNotification";

  static constexpr char kMetricTimeToConnectMillisecondsSuffix[] =
      "TimeToConnect";
  static constexpr int kMetricTimeToConnectMillisecondsMax =
      60 * 1000;  // 60 seconds
  static constexpr int kMetricTimeToConnectMillisecondsMin = 1;
  static constexpr int kMetricTimeToConnectMillisecondsNumBuckets = 60;
  static constexpr char kMetricTimeToScanAndConnectMillisecondsSuffix[] =
      "TimeToScanAndConnect";
  static constexpr int kMetricTimeToDropSecondsMax = 8 * 60 * 60;  // 8 hours
  static constexpr int kMetricTimeToDropSecondsMin = 1;
  static constexpr char kMetricTimeToDisableMillisecondsSuffix[] =
      "TimeToDisable";
  static constexpr int kMetricTimeToDisableMillisecondsMax =
      60 * 1000;  // 60 seconds
  static constexpr int kMetricTimeToDisableMillisecondsMin = 1;
  static constexpr int kMetricTimeToDisableMillisecondsNumBuckets = 60;
  static constexpr char kMetricTimeToEnableMillisecondsSuffix[] =
      "TimeToEnable";
  static constexpr int kMetricTimeToEnableMillisecondsMax =
      60 * 1000;  // 60 seconds
  static constexpr int kMetricTimeToEnableMillisecondsMin = 1;
  static constexpr int kMetricTimeToEnableMillisecondsNumBuckets = 60;
  static constexpr char kMetricTimeToInitializeMillisecondsSuffix[] =
      "TimeToInitialize";
  static constexpr int kMetricTimeToInitializeMillisecondsMax =
      30 * 1000;  // 30 seconds
  static constexpr int kMetricTimeToInitializeMillisecondsMin = 1;
  static constexpr int kMetricTimeToInitializeMillisecondsNumBuckets = 30;
  static constexpr char kMetricTimeResumeToReadyMillisecondsSuffix[] =
      "TimeResumeToReady";
  static constexpr char kMetricTimeToConfigMillisecondsSuffix[] =
      "TimeToConfig";
  static constexpr char kMetricTimeToJoinMillisecondsSuffix[] = "TimeToJoin";
  static constexpr char kMetricTimeToOnlineMillisecondsSuffix[] =
      "TimeToOnline";
  static constexpr char kMetricTimeToPortalMillisecondsSuffix[] =
      "TimeToPortal";
  static constexpr char kMetricTimeToRedirectFoundMillisecondsSuffix[] =
      "TimeToRedirectFound";
  static constexpr char kMetricTimeToScanMillisecondsSuffix[] = "TimeToScan";
  static constexpr int kMetricTimeToScanMillisecondsMax =
      180 * 1000;  // 3 minutes
  static constexpr int kMetricTimeToScanMillisecondsMin = 1;
  static constexpr int kMetricTimeToScanMillisecondsNumBuckets = 90;
  static constexpr int kTimerHistogramMillisecondsMax = 45 * 1000;
  static constexpr int kTimerHistogramMillisecondsMaxLarge = 90 * 1000;
  static constexpr int kTimerHistogramMillisecondsMin = 1;

  // Called with the number of detection attempts when the PortalDetector
  // completes and the result is 'online'.
  static constexpr HistogramMetric<NameByTechnology>
      kPortalDetectorAttemptsToOnline = {
          .n = {"PortalDetector.AttemptsToOnline",
                TechnologyLocation::kAfterName},
          .min = 1,
          .max = 20,
          .num_buckets = 20,
      };

  // Called with the number of detection attempts when the PortalDetector
  // completes or is stopped and the result is a non connected state.
  static constexpr HistogramMetric<NameByTechnology>
      kPortalDetectorAttemptsToDisconnect = {
          .n = {"PortalDetector.AttemptsToDisconnect",
                TechnologyLocation::kAfterName},
          .min = 1,
          .max = 20,
          .num_buckets = 20,
      };

  // Called with the number of detection attempts when a Service first
  // transitions to redirect-found.
  static constexpr HistogramMetric<NameByTechnology>
      kPortalDetectorAttemptsToRedirectFound = {
          .n = {"PortalDetector.AttemptsToRedirectFound",
                TechnologyLocation::kAfterName},
          .min = 1,
          .max = 10,
          .num_buckets = 10,
      };

  static constexpr char kMetricWiFiScanTimeInEbusyMilliseconds[] =
      "Network.Shill.WiFi.ScanTimeInEbusy";

  static constexpr char kMetricPowerManagerKey[] = "metrics";

  // Signal strength when link becomes unreliable (multiple link monitor
  // failures in short period of time). This name of this metric uses "Wifi"
  // instead of "WiFi" because its name used to be constructed from a
  // Technology value.
  static constexpr HistogramMetric<FixedName>
      kMetricUnreliableLinkSignalStrength = {
          .n = FixedName{"Network.Shill.Wifi.UnreliableLinkSignalStrength"},
          .min = 1,
          .max = 100,
          .num_buckets = 40,
      };

  // AP 802.11r/k/v support statistics.
  static constexpr char kMetricAp80211kSupport[] =
      "Network.Shill.WiFi.Ap80211kSupport";
  static constexpr char kMetricAp80211vDMSSupport[] =
      "Network.Shill.WiFi.Ap80211vDMSSupport";
  static constexpr char kMetricAp80211vBSSMaxIdlePeriodSupport[] =
      "Network.Shill.WiFi.Ap80211vBSSMaxIdlePeriodSupport";
  static constexpr char kMetricAp80211vBSSTransitionSupport[] =
      "Network.Shill.WiFi.Ap80211vBSSTransitionSupport";
  static constexpr char kMetricCiscoAdaptiveFTSupport[] =
      "Network.Shill.WiFi.CiscoAdaptiveFTSupport";
  static constexpr EnumMetric<FixedName> kMetricLinkApDisconnectReason = {
      .n = FixedName{"Network.Shill.WiFi.ApDisconnectReason"},
      .max = IEEE_80211::kReasonCodeMax,
  };
  static constexpr EnumMetric<FixedName> kMetricLinkClientDisconnectReason = {
      .n = FixedName{"Network.Shill.WiFi.ClientDisconnectReason"},
      .max = IEEE_80211::kReasonCodeMax,
  };

  // 802.11 Status Codes for auth/assoc failures
  static constexpr char kMetricWiFiAssocFailureType[] =
      "Network.Shill.WiFi.AssocFailureType";
  static constexpr char kMetricWiFiAuthFailureType[] =
      "Network.Shill.WiFi.AuthFailureType";

  // Roam time for FT and non-FT key management suites.
  static constexpr char kMetricWifiRoamTimePrefix[] =
      "Network.Shill.WiFi.RoamTime";
  static constexpr int kMetricWifiRoamTimeMillisecondsMax = 1000;
  static constexpr int kMetricWifiRoamTimeMillisecondsMin = 1;
  static constexpr int kMetricWifiRoamTimeNumBuckets = 20;

  // Roam completions for FT and non-FT key management suites.
  static constexpr char kMetricWifiRoamCompletePrefix[] =
      "Network.Shill.WiFi.RoamComplete";

  // Session Lengths for FT and non-FT key management suites.
  static constexpr char kMetricWifiSessionLengthPrefix[] =
      "Network.Shill.WiFi.SessionLength";
  static constexpr int kMetricWifiSessionLengthMillisecondsMax = 10000;
  static constexpr int kMetricWifiSessionLengthMillisecondsMin = 1;
  static constexpr int kMetricWifiSessionLengthNumBuckets = 20;

  // Suffixes for roam histograms.
  static constexpr char kMetricWifiPSKSuffix[] = "PSK";
  static constexpr char kMetricWifiFTPSKSuffix[] = "FTPSK";
  static constexpr char kMetricWifiEAPSuffix[] = "EAP";
  static constexpr char kMetricWifiFTEAPSuffix[] = "FTEAP";

  // Shill suspend action statistics, in milliseconds.
  static constexpr HistogramMetric<FixedName> kMetricSuspendActionTimeTaken = {
      .n = FixedName{"Network.Shill.SuspendActionTimeTaken"},
      .min = 1,
      .max = 20000,
      .num_buckets = kTimerHistogramNumBuckets,
  };

  // Cellular specific statistics.
  static constexpr HistogramMetric<FixedName>
      kMetricCellularSignalStrengthBeforeDrop = {
          .n = FixedName{"Network.Shill.Cellular.SignalStrengthBeforeDrop"},
          .min = 1,
          .max = 100,
          .num_buckets = 10,
      };

  // Number of peers used in a WireGuard connection.
  static constexpr HistogramMetric<FixedName> kMetricVpnWireGuardPeersNum = {
      .n = FixedName{"Network.Shill.Vpn.WireGuardPeersNum"},
      .min = 1,
      .max = 10,
      .num_buckets = 11,
  };

  // The length in seconds of a lease that has expired while the DHCP client was
  // attempting to renew the lease. CL:557297 changed the number of buckets for
  // the 'ExpiredLeaseLengthSeconds' metric. That would lead to confusing
  // display of samples collected before and after the change. To avoid that,
  // the 'ExpiredLeaseLengthSeconds' metric is renamed to
  // 'ExpiredLeaseLengthSeconds2'.
  static constexpr HistogramMetric<NameByTechnology>
      kMetricExpiredLeaseLengthSeconds = {
          .n = NameByTechnology{"ExpiredLeaseLengthSeconds2"},
          .min = 1,
          .max = 7 * 24 * 60 * 60,  // 7 days
          .num_buckets = 100,
      };

  // Number of wifi services available when auto-connect is initiated.
  static constexpr HistogramMetric<FixedName>
      kMetricWifiAutoConnectableServices = {
          .n = FixedName{"Network.Shill.WiFi.AutoConnectableServices"},
          .min = 1,
          .max = 50,
          .num_buckets = 10,
      };

  // Number of BSSes available for a wifi service when we attempt to connect
  // to that service.
  static constexpr HistogramMetric<FixedName> kMetricWifiAvailableBSSes = {
      .n = FixedName{"Network.Shill.WiFi.AvailableBSSesAtConnect"},
      .min = 1,
      .max = 50,
      .num_buckets = 10,
  };

  // Wifi TX bitrate in Mbps.
  static constexpr HistogramMetric<FixedName> kMetricWifiTxBitrate = {
      .n = FixedName{"Network.Shill.WiFi.TransmitBitrateMbps"},
      .min = 1,
      .max = 7000,
      .num_buckets = 100,
  };

  // Number of attempts made to connect to supplicant before success (max ==
  // failure).
  static constexpr HistogramMetric<FixedName> kMetricWifiSupplicantAttempts = {
      .n = FixedName{"Network.Shill.WiFi.SupplicantAttempts"},
      .min = 1,
      .max = 10,
      .num_buckets = 11,
  };

  // Assigned MTU values from PPP.
  static constexpr char kMetricPPPMTUValue[] = "Network.Shill.PPPMTUValue";

  // Wireless regulatory domain metric.
  static constexpr char kMetricRegulatoryDomain[] =
      "Network.Shill.WiFi.RegulatoryDomain";

  // MBO support metric.
  static constexpr char kMetricMBOSupport[] = "Network.Shill.WiFi.MBOSupport";

  // Seconds between latest WiFi rekey attempt and service failure, in seconds.
  static constexpr HistogramMetric<FixedName>
      kMetricTimeFromRekeyToFailureSeconds = {
          .n = FixedName{"Network.Shill.WiFi.TimeFromRekeyToFailureSeconds"},
          .min = 0,
          .max = 180,
          .num_buckets = 30,
      };

  enum WiFiRestartReason { kRestartReasonCannotAssoc = 0, kRestartReasonMax };
  // Metric to track when the WiFi device is has been requested to restart.
  // This metric is made to specifically track the hitrate of b/270746800.
  // TODO(b/278765529) This metric in addition to the shill driver restart
  // mechanism should be removed once the hitrate is deemed low enough.
  static constexpr EnumMetric<FixedName> kMetricNetworkWiFiRestartReason = {
      .n = FixedName{"Network.Shill.WiFi.RestartReason"},
      .max = kRestartReasonMax,
  };

  // Version number of the format of WiFi structured metrics. Changed when the
  // formatting of the metrics changes, so that the server-side code knows
  // which fields to expect.
  static constexpr int kWiFiStructuredMetricsVersion = 1;

  // When emitting WiFi structured metrics, if we encounter errors and the
  // numeric values of some of the fields can not be populated, use this as
  // value for the field.
  static constexpr int kWiFiStructuredMetricsErrorValue = -1;

  // 9999 is wpa_supplicant's value for "invalid RSSI", let's use the same.
  static constexpr int kWiFiStructuredMetricsErrorValueRSSI = 9999;

  // Some WiFi adapters like the ones integrated in some Qualcomm SoCs do not
  // have a PCI vendor/product/subsystem ID. When we detect such an adapter on
  // the system we use "0x0000" as PCI Vendor ID since that ID is not used by
  // the PCI-SIG. Otherwise if we assigned an actual vendor ID like Qualcomm's
  // ID we may have conflicting values with PCI devices from those vendors.
  static constexpr int kWiFiIntegratedAdapterVendorId = 0x0000;

  struct WiFiAdapterInfo {
    int vendor_id;
    int product_id;
    int subsystem_id;
  };

  enum WiFiSessionTagState {
    kWiFiSessionTagStateUnknown = 0,
    kWiFiSessionTagStateUnexpected = 1,
    kWiFiSessionTagStateExpected = 2,
    kWiFiSessionTagStateMax
  };
  static constexpr char kWiFiSessionTagStateMetricPrefix[] =
      "Network.Shill.WiFi.SessionTagState";
  static constexpr char kWiFiSessionTagConnectionAttemptSuffix[] =
      "ConnectionAttempt";
  static constexpr char kWiFiSessionTagConnectionAttemptResultSuffix[] =
      "ConnectionAttemptResult";
  static constexpr char kWiFiSessionTagDisconnectionSuffix[] = "Disconnection";
  static constexpr char kWiFiSessionTagLinkQualityTriggerSuffix[] =
      "LinkQualityTrigger";
  static constexpr char kWiFiSessionTagLinkQualityReportSuffix[] =
      "LinkQualityReport";

  enum WiFiBadPassphraseServiceType {
    kNonUserInitiatedNeverConnected = 0,
    kNonUserInitiatedConnectedBefore = 1,
    kUserInitiatedNeverConnected = 2,
    kUserInitiatedConnectedBefore = 3,
    kBadPassphraseServiceTypeMax
  };
  static constexpr EnumMetric<FixedName> kMetricWiFiBadPassphraseServiceType = {
      .n = FixedName{"Network.Shill.WiFi.BadPassphraseServiceType"},
      .max = kBadPassphraseServiceTypeMax,
  };

  Metrics();
  Metrics(const Metrics&) = delete;
  Metrics& operator=(const Metrics&) = delete;

  virtual ~Metrics();

  // Converts the WiFi frequency into the associated UMA channel enumerator.
  static WiFiChannel WiFiFrequencyToChannel(uint16_t frequency);

  // Converts WiFi Channel to the associated frequency range.
  static WiFiFrequencyRange WiFiChannelToFrequencyRange(WiFiChannel channel);

  // Converts a flimflam Security/SecurityClass into its UMA security
  // enumerator.
  static WirelessSecurity WiFiSecurityToEnum(const WiFiSecurity& security);
  static WirelessSecurity WiFiSecurityClassToEnum(const std::string& security);

  // Converts a flimflam EAP outer protocol string into its UMA enumerator.
  static EapOuterProtocol EapOuterProtocolStringToEnum(
      const std::string& outer);

  // Converts a flimflam EAP inner protocol string into its UMA enumerator.
  static EapInnerProtocol EapInnerProtocolStringToEnum(
      const std::string& inner);

  // Converts portal detection result to UMA portal result enumerator.
  static PortalResult PortalDetectionResultToEnum(
      const PortalDetector::Result& result);

  // Converts service connect failure to UMA service error enumerator.
  static NetworkServiceError ConnectFailureToServiceErrorEnum(
      Service::ConnectFailure failure);

  // Registers a service with this object so it can use the timers to track
  // state transition metrics.
  void RegisterService(const Service& service);

  // Deregisters the service from this class.  All state transition timers
  // will be removed.
  void DeregisterService(const Service& service);

  // Tracks the time it takes |service| to go from |start_state| to
  // |stop_state|.  When |stop_state| is reached, the time is sent to UMA.
  virtual void AddServiceStateTransitionTimer(const Service& service,
                                              const std::string& histogram_name,
                                              Service::ConnectState start_state,
                                              Service::ConnectState stop_state);

  // Specializes |metric_name| with the specified |technology_id| and
  // |location|.
  static std::string GetFullMetricName(
      const char* metric_name,
      Technology technology_id,
      TechnologyLocation location = TechnologyLocation::kBeforeName);

  // Implements DefaultServiceObserver.
  void OnDefaultLogicalServiceChanged(
      const ServiceRefPtr& logical_service) override;
  void OnDefaultPhysicalServiceChanged(
      const ServiceRefPtr& physical_service) override;

  // Notifies this object that |service| state has changed.
  virtual void NotifyServiceStateChanged(const Service& service,
                                         Service::ConnectState new_state);

  // Notifies this object of the end of a suspend attempt.
  void NotifySuspendDone();

  // Notifies this object that suspend actions started executing.
  void NotifySuspendActionsStarted();

  // Notifies this object that suspend actions have been completed.
  // |success| is true, if the suspend actions completed successfully.
  void NotifySuspendActionsCompleted(bool success);

  // Notifies this object of a failure in patchpanel::NeighborLinkMonitor for
  // a WiFi connection.
  void NotifyNeighborLinkMonitorFailure(Technology tech,
                                        IPAddress::Family family,
                                        patchpanel::Client::NeighborRole role);

  // Notifies this object that an AP was discovered and of that AP's 802.11k
  // support.
  void NotifyAp80211kSupport(bool neighbor_list_supported);

  // Notifies this object that an AP was discovered and of that AP's 802.11r
  // support.
  void NotifyAp80211rSupport(bool ota_ft_supported, bool otds_ft_supported);

  // Notifies this object that an AP was discovered and of that AP's 802.11v
  // DMS support.
  void NotifyAp80211vDMSSupport(bool dms_supported);

  // Notifies this object that an AP was discovered and of that AP's 802.11v
  // BSS Max Idle Period support.
  void NotifyAp80211vBSSMaxIdlePeriodSupport(
      bool bss_max_idle_period_supported);

  // Notifies this object that an AP was discovered and of that AP's 802.11v
  // BSS Transition support.
  void NotifyAp80211vBSSTransitionSupport(bool bss_transition_supported);

  // Notifies this object that an AP was discovered with Cisco Adaptive FT
  // support.
  void NotifyCiscoAdaptiveFTSupport(bool adaptive_ft_supported);

  // Notifies this object of WiFi disconnect.
  // TODO(b/234176329): Deprecate those metrics once
  // go/cros-wifi-structured-metrics-dd has fully landed.
  virtual void Notify80211Disconnect(WiFiDisconnectByWhom by_whom,
                                     IEEE_80211::WiFiReasonCode reason);

  // Notifies this object that an AP has switched channels.
  void NotifyApChannelSwitch(uint16_t frequency, uint16_t new_frequency);

  // Registers a device with this object so the device can use the timers to
  // track state transition metrics.
  void RegisterDevice(int interface_index, Technology technology);

  // Checks to see if the device has already been registered.
  bool IsDeviceRegistered(int interface_index, Technology technology);

  // Deregisters the device from this class.  All state transition timers
  // will be removed.
  virtual void DeregisterDevice(int interface_index);

  // Notifies this object that a device has been initialized.
  void NotifyDeviceInitialized(int interface_index);

  // Notifies this object that a device has started the enable process.
  void NotifyDeviceEnableStarted(int interface_index);

  // Notifies this object that a device has completed the enable process.
  void NotifyDeviceEnableFinished(int interface_index);

  // Notifies this object that a device has started the disable process.
  void NotifyDeviceDisableStarted(int interface_index);

  // Notifies this object that a device has completed the disable process.
  void NotifyDeviceDisableFinished(int interface_index);

  // Notifies this object that a device has started the scanning process.
  virtual void NotifyDeviceScanStarted(int interface_index);

  // Notifies this object that a device has completed the scanning process.
  virtual void NotifyDeviceScanFinished(int interface_index);

  // Report the status of the scan.
  mockable void ReportDeviceScanResultToUma(Metrics::WiFiScanResult result);

  // Terminates an underway scan (does nothing if a scan wasn't underway).
  virtual void ResetScanTimer(int interface_index);

  // Notifies this object that a device has started the connect process.
  virtual void NotifyDeviceConnectStarted(int interface_index);

  // Notifies this object that a device has completed the connect process.
  virtual void NotifyDeviceConnectFinished(int interface_index);

  // Resets both the connect_timer and the scan_connect_timer the timer (the
  // latter so that a future connect will not erroneously be associated with
  // the previous scan).
  virtual void ResetConnectTimer(int interface_index);

  // Notifies this object that a cellular device has been dropped by the
  // network.
  void NotifyCellularDeviceDrop(const std::string& network_technology,
                                uint16_t signal_strength);

  // Notifies this object of the resulting status of a cellular connection
  void NotifyCellularConnectionResult(Error::Type error,
                                      ApnList::ApnType apn_type);

  // Notifies this object of the entitlement check result
  virtual void NotifyCellularEntitlementCheckResult(
      Metrics::CellularEntitlementCheck result);

  struct DetailedCellularConnectionResult {
    // The values are used in metrics and thus should not be changed.
    enum class IPConfigMethod {
      kUnknown = 0,
      kPPP = 1,
      kStatic = 2,
      kDHCP = 3
    };
    enum class ConnectionAttemptType {
      kUnknown = 0,
      kUserConnect = 1,
      kAutoConnect = 2
    };
    Error::Type error;
    std::string detailed_error;
    std::string uuid;
    shill::Stringmap apn_info;
    IPConfigMethod ipv4_config_method;
    IPConfigMethod ipv6_config_method;
    std::string home_mccmnc;
    std::string serving_mccmnc;
    std::string roaming_state;
    uint32_t tech_used;
    uint32_t iccid_length;
    uint32_t sim_type;
    std::string gid1;
    uint32_t modem_state;
    int interface_index;
    uint32_t use_apn_revamp_ui;
    ConnectionAttemptType connection_attempt_type;
    uint32_t subscription_error_seen;
  };

  // Notifies this object of the resulting status of a cellular connection
  virtual void NotifyDetailedCellularConnectionResult(
      const DetailedCellularConnectionResult& result);

  // Notifies this object about the reason of failed user-initiated connection
  // attempt.
  virtual void NotifyUserInitiatedConnectionFailureReason(
      const Service::ConnectFailure failure);

  // Sends linear histogram data to UMA.
  virtual bool SendEnumToUMA(const std::string& name, int sample, int max);

  // Sends bool to UMA.
  virtual bool SendBoolToUMA(const std::string& name, bool b);

  // Send logarithmic histogram data to UMA.
  virtual bool SendToUMA(
      const std::string& name, int sample, int min, int max, int num_buckets);

  // Sends sparse histogram data to UMA.
  virtual bool SendSparseToUMA(const std::string& name, int sample);

  // Notifies this object that connection diagnostics have been performed, and
  // the connection issue that was diagnosed is |issue|.
  virtual void NotifyConnectionDiagnosticsIssue(const std::string& issue);

  // Notifies this object that of the HS20 support of an access that has
  // been connected to.
  void NotifyHS20Support(bool hs20_supported, int hs20_version_number);

  // Calculate Regulatory domain value given two letter country code.
  // Return value corresponds to Network.Shill.WiFi.RegulatoryDomain histogram
  // buckets. The full enum can be found in
  // /chromium/src/tools/metrics/histograms/enums.xml.
  static int GetRegulatoryDomainValue(std::string country_code);

  // Notifies this object of the MBO support of the access point that has been
  // connected to.
  void NotifyMBOSupport(bool mbo_support);

  // Notifies this object that of the stream classification support of an access
  // point that has been connected to.
  void NotifyStreamClassificationSupport(bool scs_supported,
                                         bool mscs_supported);

  // Notifies this object that of the alternate EDCA support of an access point
  // that has been connected to.
  void NotifyAlternateEDCASupport(bool alternate_edca_supported);

  // Emits the |WiFiAdapterStateChanged| structured event that notifies that
  // the WiFi adapter has been enabled or disabled. Includes the IDs describing
  // the type of the adapter (e.g. PCI IDs).
  mockable void NotifyWiFiAdapterStateChanged(bool enabled,
                                              const WiFiAdapterInfo& info);

  enum ConnectionAttemptType {
    kAttemptTypeUnknown = 0,
    kAttemptTypeUserInitiated = 1,
    kAttemptTypeAuto = 2
  };

  enum SSIDProvisioningMode {
    kProvisionUnknown = 0,
    kProvisionManual = 1,
    kProvisionPolicy = 2,
    kProvisionSync = 3
  };

  struct WiFiConnectionAttemptInfo {
    ConnectionAttemptType type;
    WiFiNetworkPhyMode mode;
    WirelessSecurity security;
    EapInnerProtocol eap_inner;
    EapOuterProtocol eap_outer;
    WiFiFrequencyRange band;
    WiFiChannel channel;
    int rssi;
    std::string ssid;
    std::string bssid;
    SSIDProvisioningMode provisioning_mode;
    bool ssid_hidden;
    int ap_oui;
    struct ApSupportedFeatures {
      struct Ap80211krv {
        int neighbor_list_supported = kWiFiStructuredMetricsErrorValue;
        int ota_ft_supported = kWiFiStructuredMetricsErrorValue;
        int otds_ft_supported = kWiFiStructuredMetricsErrorValue;
        int dms_supported = kWiFiStructuredMetricsErrorValue;
        int bss_max_idle_period_supported = kWiFiStructuredMetricsErrorValue;
        int bss_transition_supported = kWiFiStructuredMetricsErrorValue;
      } krv_info;
      struct ApHS20 {
        int supported = kWiFiStructuredMetricsErrorValue;
        int version = kWiFiStructuredMetricsErrorValue;
      } hs20_info;
      int mbo_supported = kWiFiStructuredMetricsErrorValue;
    } ap_features;
  };

  static WiFiConnectionAttemptInfo::ApSupportedFeatures ConvertEndPointFeatures(
      const WiFiEndpoint* ep);

  // Emits the |WiFiConnectionAttempt| structured event that notifies that the
  // device is attempting to connect to an AP. It describes the parameters of
  // the connection (channel/band, security mode, etc.).
  virtual void NotifyWiFiConnectionAttempt(
      const WiFiConnectionAttemptInfo& info, uint64_t session_tag);

  // Emits the |WiFiConnectionAttemptResult| structured event that describes
  // the result of the corresponding |WiFiConnectionAttempt| event.
  virtual void NotifyWiFiConnectionAttemptResult(
      NetworkServiceError result_code, uint64_t session_tag);

  enum WiFiDisconnectionType {
    kWiFiDisconnectionTypeUnknown = 0,
    kWiFiDisconnectionTypeExpectedUserAction = 1,
    kWiFiDisconnectionTypeExpectedRoaming = 2,
    kWiFiDisconnectionTypeUnexpectedAPDisconnect = 3,
    kWiFiDisconnectionTypeUnexpectedSTADisconnect = 4
  };

  // Emits the |WiFiConnectionEnd| structured event.
  virtual void NotifyWiFiDisconnection(WiFiDisconnectionType type,
                                       IEEE_80211::WiFiReasonCode reason,
                                       uint64_t session_tag);

  enum WiFiLinkQualityTrigger {
    kWiFiLinkQualityTriggerUnknown = 0,
    kWiFiLinkQualityTriggerCQMRSSILow = 1,
    kWiFiLinkQualityTriggerCQMRSSIHigh = 2,
    kWiFiLinkQualityTriggerCQMBeaconLoss = 3,
    kWiFiLinkQualityTriggerCQMPacketLoss = 4,
    kWiFiLinkQualityTriggerBackgroundCheck = 5,
    kWiFiLinkQualityTriggerIPConfigurationStart = 6,
    kWiFiLinkQualityTriggerConnected = 7,
    kWiFiLinkQualityTriggerDHCPRenewOnRoam = 8,
    kWiFiLinkQualityTriggerDHCPSuccess = 9,
    kWiFiLinkQualityTriggerDHCPFailure = 10,
    kWiFiLinkQualityTriggerSlaacFinished = 11,
    kWiFiLinkQualityTriggerNetworkValidationStart = 12,
    kWiFiLinkQualityTriggerNetworkValidationSuccess = 13,
    kWiFiLinkQualityTriggerNetworkValidationFailure = 14,
  };

  enum WiFiChannelWidth {
    kWiFiChannelWidthUnknown = 0,
    kWiFiChannelWidth20MHz = 1,
    kWiFiChannelWidth40MHz = 2,
    kWiFiChannelWidth80MHz = 3,
    kWiFiChannelWidth80p80MHz = 4,  // 80+80MHz channels.
    kWiFiChannelWidth160MHz = 5,
    kWiFiChannelWidth320MHz = 6,
  };

  enum WiFiLinkMode {
    kWiFiLinkModeUnknown = 0,
    kWiFiLinkModeLegacy = 1,
    kWiFiLinkModeVHT = 2,
    kWiFiLinkModeHE = 3,
    kWiFiLinkModeEHT = 4,
  };

  enum WiFiGuardInterval {
    kWiFiGuardIntervalUnknown = 0,
    kWiFiGuardInterval_0_4 = 1,
    kWiFiGuardInterval_0_8 = 2,
    kWiFiGuardInterval_1_6 = 3,
    kWiFiGuardInterval_3_2 = 4,
  };

  struct WiFiRxTxStats {
    int64_t packets = kWiFiStructuredMetricsErrorValue;
    int64_t bytes = kWiFiStructuredMetricsErrorValue;
    int bitrate = kWiFiStructuredMetricsErrorValue;  // unit is 100 Kb/s.
    int mcs = kWiFiStructuredMetricsErrorValue;
    WiFiLinkMode mode = kWiFiLinkModeUnknown;
    WiFiGuardInterval gi = kWiFiGuardIntervalUnknown;
    int nss = kWiFiStructuredMetricsErrorValue;
    int dcm = kWiFiStructuredMetricsErrorValue;
    bool operator==(const WiFiRxTxStats& other) const {
      if (packets != other.packets) {
        return false;
      }
      if (bytes != other.bytes) {
        return false;
      }
      if (bitrate != other.bitrate) {
        return false;
      }
      if (mcs != other.mcs) {
        return false;
      }
      if (mode != other.mode) {
        return false;
      }
      if (gi != other.gi) {
        return false;
      }
      if (nss != other.nss) {
        return false;
      }
      if (dcm != other.dcm) {
        return false;
      }
      return true;
    }
    bool operator!=(const WiFiRxTxStats& other) const {
      return !(*this == other);
    }
  };

  enum BTStack {
    kBTStackUnknown = 0,
    kBTStackBlueZ = 1,
    kBTStackFloss = 2,
  };

  // For consistency, use the same integer values as Floss
  // https://android.googlesource.com/platform/packages/modules/Bluetooth/+/ac69da6c45771293530338709ee6e9599065ca5d/system/gd/rust/topshim/src/profiles/mod.rs#7
  enum BTProfileConnectionState {
    kBTProfileConnectionStateDisconnected = 0,
    kBTProfileConnectionStateDisconnecting = 1,
    kBTProfileConnectionStateConnecting = 2,
    kBTProfileConnectionStateConnected = 3,
    kBTProfileConnectionStateActive = 4,
    kBTProfileConnectionStateInvalid = 0x7FFFFFFE,
  };

  struct WiFiLinkQualityReport {
    int64_t tx_retries = kWiFiStructuredMetricsErrorValue;
    int64_t tx_failures = kWiFiStructuredMetricsErrorValue;
    int64_t rx_drops = kWiFiStructuredMetricsErrorValue;
    int chain0_signal = kWiFiStructuredMetricsErrorValueRSSI;
    int chain0_signal_avg = kWiFiStructuredMetricsErrorValueRSSI;
    int chain1_signal = kWiFiStructuredMetricsErrorValueRSSI;
    int chain1_signal_avg = kWiFiStructuredMetricsErrorValueRSSI;
    int beacon_signal_avg = kWiFiStructuredMetricsErrorValueRSSI;
    int64_t beacons_received = kWiFiStructuredMetricsErrorValue;
    int64_t beacons_lost = kWiFiStructuredMetricsErrorValue;
    int64_t expected_throughput = kWiFiStructuredMetricsErrorValue;
    WiFiChannelWidth width = kWiFiChannelWidthUnknown;
    WiFiRxTxStats rx;
    WiFiRxTxStats tx;
    bool bt_enabled = false;
    BTStack bt_stack = kBTStackUnknown;
    BTProfileConnectionState bt_hfp = kBTProfileConnectionStateInvalid;
    BTProfileConnectionState bt_a2dp = kBTProfileConnectionStateInvalid;
    bool bt_active_scanning = false;
    bool operator==(const WiFiLinkQualityReport& other) const {
      if (tx_retries != other.tx_retries) {
        return false;
      }
      if (tx_failures != other.tx_failures) {
        return false;
      }
      if (rx_drops != other.rx_drops) {
        return false;
      }
      if (chain0_signal != other.chain0_signal) {
        return false;
      }
      if (chain0_signal_avg != other.chain0_signal_avg) {
        return false;
      }
      if (chain1_signal != other.chain1_signal) {
        return false;
      }
      if (chain1_signal_avg != other.chain1_signal_avg) {
        return false;
      }
      if (beacon_signal_avg != other.beacon_signal_avg) {
        return false;
      }
      if (beacons_received != other.beacons_received) {
        return false;
      }
      if (beacons_lost != other.beacons_lost) {
        return false;
      }
      if (expected_throughput != other.expected_throughput) {
        return false;
      }
      if (width != other.width) {
        return false;
      }
      if (rx != other.rx) {
        return false;
      }
      if (tx != other.tx) {
        return false;
      }
      if (bt_enabled != other.bt_enabled) {
        return false;
      }
      if (bt_stack != other.bt_stack) {
        return false;
      }
      if (bt_hfp != other.bt_hfp) {
        return false;
      }
      if (bt_a2dp != other.bt_a2dp) {
        return false;
      }
      if (bt_active_scanning != other.bt_active_scanning) {
        return false;
      }
      return true;
    }
    bool operator!=(const WiFiLinkQualityReport& other) const {
      return !(*this == other);
    }
  };

  // Emits the |WiFiLinkQualityTrigger| structured event.
  mockable void NotifyWiFiLinkQualityTrigger(WiFiLinkQualityTrigger trigger,
                                             uint64_t session_tag);

  // Emits the |WiFiLinkQualityReport| structured event. It contains information
  // about the quality of the wireless link (e.g. MCS index, rate of packet
  // loss, etc.)
  mockable void NotifyWiFiLinkQualityReport(const WiFiLinkQualityReport& report,
                                            uint64_t session_tag);

  // Returns a persistent hash to be used to uniquely identify an APN.
  static int64_t HashApn(const std::string& uuid,
                         const std::string& apn_name,
                         const std::string& username,
                         const std::string& password);

  // Converts GID1 from hex string to int64_t
  static std::optional<int64_t> IntGid1(const std::string& gid1);

  // Notifies the object that the wifi connection became unreliable.
  virtual void NotifyWiFiConnectionUnreliable();

  // Notifies the object that the BSSID has changed.
  virtual void NotifyBSSIDChanged();

  // Notifies the object that a rekey event has started.
  virtual void NotifyRekeyStart();

  // Notifies this object of the status when bad-passphrase is identified
  virtual void NotifyWiFiBadPassphrase(bool ever_connected, bool user_initiate);

  // Sends linear histogram data to UMA for a metric with a fixed name.
  virtual void SendEnumToUMA(const EnumMetric<FixedName>& metric, int sample);

  // Sends linear histogram data to UMA for a metric split by APN type.
  virtual void SendEnumToUMA(const EnumMetric<NameByApnType>& metric,
                             ApnList::ApnType type,
                             int sample);

  // Sends linear histogram data to UMA for a metric split by shill
  // Technology.
  virtual void SendEnumToUMA(const EnumMetric<NameByTechnology>& metric,
                             Technology tech,
                             int sample);

  // Sends linear histogram data to UMA for a metric split by VPN type.
  virtual void SendEnumToUMA(const EnumMetric<NameByVPNType>& metric,
                             VPNType type,
                             int sample);

  // Sends linear histogram data to UMA for a metric with a prefix name.
  virtual void SendEnumToUMA(const EnumMetric<PrefixName>& metric,
                             const std::string& suffix,
                             int sample);

  // Sends logarithmic histogram data to UMA for a metric with a fixed name.
  virtual void SendToUMA(const HistogramMetric<FixedName>& metric, int sample);

  // Sends logarithmic histogram data to UMA for a metric split by shill
  // Technology.
  virtual void SendToUMA(const HistogramMetric<NameByTechnology>& metric,
                         Technology tech,
                         int sample);

  // Sends logarithmic histogram data to UMA for a metric with a prefix name.
  virtual void SendToUMA(const HistogramMetric<PrefixName>& metric,
                         const std::string& suffix,
                         int sample);

  void SetLibraryForTesting(MetricsLibraryInterface* library);

 private:
  friend class MetricsTest;
  FRIEND_TEST(MetricsTest, FrequencyToChannel);
  FRIEND_TEST(MetricsTest, ResetConnectTimer);
  FRIEND_TEST(MetricsTest, ServiceFailure);
  FRIEND_TEST(MetricsTest, TimeFromRekeyToFailureBSSIDChange);
  FRIEND_TEST(MetricsTest, TimeFromRekeyToFailureExceedMaxDuration);
  FRIEND_TEST(MetricsTest, TimeFromRekeyToFailureValidDuration);
  FRIEND_TEST(MetricsTest, TimeOnlineTimeToDrop);
  FRIEND_TEST(MetricsTest, TimeToConfig);
  FRIEND_TEST(MetricsTest, TimeToOnline);
  FRIEND_TEST(MetricsTest, TimeToPortal);
  FRIEND_TEST(MetricsTest, TimeToScanIgnore);
  FRIEND_TEST(MetricsTest, WiFiServicePostReady);
  FRIEND_TEST(MetricsTest, NotifySuspendActionsCompleted_Success);
  FRIEND_TEST(MetricsTest, NotifySuspendActionsCompleted_Failure);
  FRIEND_TEST(MetricsTest, NotifySuspendActionsStarted);
  FRIEND_TEST(WiFiMainTest, UpdateGeolocationObjects);

  using TimerReporters =
      std::vector<std::unique_ptr<chromeos_metrics::TimerReporter>>;
  using TimerReportersList = std::list<chromeos_metrics::TimerReporter*>;
  using TimerReportersByState =
      std::map<Service::ConnectState, TimerReportersList>;
  struct ServiceMetrics {
    // All TimerReporter objects are stored in |timers| which owns the objects.
    // |start_on_state| and |stop_on_state| contain pointers to the
    // TimerReporter objects and control when to start and stop the timers.
    TimerReporters timers;
    TimerReportersByState start_on_state;
    TimerReportersByState stop_on_state;
  };

  struct DeviceMetrics {
    DeviceMetrics() {}
    Technology technology;
    std::unique_ptr<chromeos_metrics::TimerReporter> initialization_timer;
    std::unique_ptr<chromeos_metrics::TimerReporter> enable_timer;
    std::unique_ptr<chromeos_metrics::TimerReporter> disable_timer;
    std::unique_ptr<chromeos_metrics::TimerReporter> scan_timer;
    std::unique_ptr<chromeos_metrics::TimerReporter> connect_timer;
    std::unique_ptr<chromeos_metrics::TimerReporter> scan_connect_timer;
  };
  using DeviceMetricsLookupMap =
      std::map<const int, std::unique_ptr<DeviceMetrics>>;

  static constexpr uint16_t kWiFiBandwidth5MHz = 5;
  static constexpr uint16_t kWiFiBandwidth20MHz = 20;
  static constexpr uint16_t kWiFiFrequency2412 = 2412;
  static constexpr uint16_t kWiFiFrequency2472 = 2472;
  static constexpr uint16_t kWiFiFrequency2484 = 2484;
  static constexpr uint16_t kWiFiFrequency5170 = 5170;
  static constexpr uint16_t kWiFiFrequency5180 = 5180;
  static constexpr uint16_t kWiFiFrequency5230 = 5230;
  static constexpr uint16_t kWiFiFrequency5240 = 5240;
  static constexpr uint16_t kWiFiFrequency5320 = 5320;
  static constexpr uint16_t kWiFiFrequency5500 = 5500;
  static constexpr uint16_t kWiFiFrequency5700 = 5700;
  static constexpr uint16_t kWiFiFrequency5745 = 5745;
  static constexpr uint16_t kWiFiFrequency5825 = 5825;
  static constexpr uint16_t kWiFiFrequency5955 = 5955;
  static constexpr uint16_t kWiFiFrequency7115 = 7115;

  void InitializeCommonServiceMetrics(const Service& service);
  void UpdateServiceStateTransitionMetrics(ServiceMetrics* service_metrics,
                                           Service::ConnectState new_state);
  void SendServiceFailure(const Service& service);

  DeviceMetrics* GetDeviceMetrics(int interface_index) const;

  // For unit test purposes.
  void set_time_online_timer(chromeos_metrics::Timer* timer) {
    time_online_timer_.reset(timer);  // Passes ownership
  }
  void set_time_to_drop_timer(chromeos_metrics::Timer* timer) {
    time_to_drop_timer_.reset(timer);  // Passes ownership
  }
  void set_time_resume_to_ready_timer(chromeos_metrics::Timer* timer) {
    time_resume_to_ready_timer_.reset(timer);  // Passes ownership
  }
  void set_time_suspend_actions_timer(chromeos_metrics::Timer* timer) {
    time_suspend_actions_timer.reset(timer);  // Passes ownership
  }
  void set_time_to_scan_timer(int interface_index,
                              chromeos_metrics::TimerReporter* timer) {
    DeviceMetrics* device_metrics = GetDeviceMetrics(interface_index);
    device_metrics->scan_timer.reset(timer);  // Passes ownership
  }
  void set_time_to_connect_timer(int interface_index,
                                 chromeos_metrics::TimerReporter* timer) {
    DeviceMetrics* device_metrics = GetDeviceMetrics(interface_index);
    device_metrics->connect_timer.reset(timer);  // Passes ownership
  }
  void set_time_to_scan_connect_timer(int interface_index,
                                      chromeos_metrics::TimerReporter* timer) {
    DeviceMetrics* device_metrics = GetDeviceMetrics(interface_index);
    device_metrics->scan_connect_timer.reset(timer);  // Passes ownership
  }
  void set_time_between_rekey_and_connection_failure_timer(
      chromeos_metrics::Timer* timer) {
    time_between_rekey_and_connection_failure_timer_.reset(
        timer);  // Passes ownership
  }

  // Return a pseudonymized string (salted+hashed) version of the session tag.
  std::string PseudonymizeTag(uint64_t tag);

  // |library_| points to |metrics_library_| when shill runs normally.
  // However, in order to allow for unit testing, we point |library_| to a
  // MetricsLibraryMock object instead.
  MetricsLibrary metrics_library_;
  MetricsLibraryInterface* library_;
  // Map of ServiceMetrics objects indexed by the RPC identifier of the
  // associated services.
  std::map<std::string, std::unique_ptr<ServiceMetrics>> services_metrics_;
  Technology last_default_technology_;
  bool was_last_online_;
  // Randomly generated 32 bytes used as a salt to pseudonymize session tags.
  base::StringPiece pseudo_tag_salt_;
  std::unique_ptr<chromeos_metrics::Timer> time_online_timer_;
  std::unique_ptr<chromeos_metrics::Timer> time_to_drop_timer_;
  std::unique_ptr<chromeos_metrics::Timer> time_resume_to_ready_timer_;
  std::unique_ptr<chromeos_metrics::Timer> time_suspend_actions_timer;
  std::unique_ptr<chromeos_metrics::Timer>
      time_between_rekey_and_connection_failure_timer_;
  DeviceMetricsLookupMap devices_metrics_;
  Time* time_;
};

}  // namespace shill

#endif  // SHILL_METRICS_H_
