// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_METRICS_H_
#define PATCHPANEL_METRICS_H_

namespace patchpanel {

// UMA metrics name for patchpanel Manager Dbus API calls.
constexpr char kDbusUmaEventMetrics[] = "Network.Patchpanel.Dbus";
// UMA metrics name for ArcService events.
constexpr char kArcServiceUmaEventMetrics[] = "Network.Patchpanel.ArcService";

// UMA metrics events for |kDbusUmaEventMetrics|;
enum class DbusUmaEvent {
  kUnknown = 0,
  kArcStartup = 1,
  kArcStartupSuccess = 2,
  kArcShutdown = 3,
  kArcShutdownSuccess = 4,
  kArcVmStartup = 5,
  kArcVmStartupSuccess = 6,
  kArcVmShutdown = 7,
  kArcVmShutdownSuccess = 8,
  kTerminaVmStartup = 9,
  kTerminaVmStartupSuccess = 10,
  kTerminaVmShutdown = 11,
  kTerminaVmShutdownSuccess = 12,
  kParallelsVmStartup = 13,
  kParallelsVmStartupSuccess = 14,
  kParallelsVmShutdown = 15,
  kParallelsVmShutdownSuccess = 16,
  kSetVpnIntent = 17,
  kSetVpnIntentSuccess = 18,
  kConnectNamespace = 19,
  kConnectNamespaceSuccess = 20,
  kGetTrafficCounters = 21,
  kGetTrafficCountersSuccess = 22,
  kModifyPortRule = 23,
  kModifyPortRuleSuccess = 24,
  kGetDevices = 25,
  kGetDevicesSuccess = 26,
  kSetVpnLockdown = 27,
  kSetVpnLockdownSuccess = 28,
  kSetDnsRedirectionRule = 29,
  kSetDnsRedirectionRuleSuccess = 30,
  kCreateLocalOnlyNetwork = 31,
  kCreateLocalOnlyNetworkSuccess = 32,
  kCreateTetheredNetwork = 33,
  kCreateTetheredNetworkSuccess = 34,
  kGetDownstreamNetworkInfo = 35,
  kGetDownstreamNetworkInfoSuccess = 36,

  kMaxValue,
};

// UMA metrics events for |kArcServiceUmaEventMetrics|;
enum class ArcServiceUmaEvent {
  kUnknown = 0,
  kStart = 1,
  kStartSuccess = 2,
  kStartWithoutStop = 3,
  kStop = 4,
  kStopSuccess = 5,
  kStopBeforeStart = 6,
  kAddDevice = 7,
  kAddDeviceSuccess = 8,
  kSetVethMtuError = 10,
  kOneTimeContainerSetupError = 11,

  kMaxValue,
};

}  // namespace patchpanel

#endif  // PATCHPANEL_METRICS_H_
