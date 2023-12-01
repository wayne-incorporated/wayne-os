// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_WIFI_WAKE_ON_WIFI_INTERFACE_H_
#define SHILL_WIFI_WAKE_ON_WIFI_INTERFACE_H_

#include <optional>
#include <string>
#include <vector>

#include <base/time/time.h>

#include "shill/callbacks.h"
#include "shill/wifi/wifi.h"

namespace shill {

class ByteString;
class Error;
class Nl80211Message;
class PropertyStore;

// Base class for WakeOnWiFi implementations. This is so stub and mock
// implementations don't pull in e.g. WakeOnWiFi members.
//
// This is just the interface; for explanations of each method and a
// detailed diagram of the state machine, look at wake_on_wifi.h.

class WakeOnWiFiInterface {
 public:
  using InitiateScanCallback = base::OnceCallback<void(const WiFi::FreqSet&)>;
  // Callback used to report the wake reason for the current dark resume to
  // powerd.
  using RecordWakeReasonCallback =
      base::RepeatingCallback<void(const std::string&)>;

  // Types of triggers that we can program the NIC to wake the WiFi device.
  enum WakeOnWiFiTrigger {
    kWakeTriggerUnsupported = 0,  // Used for reporting, not programming NIC.
    // deprecated: kWakeTriggerPattern = 1,
    kWakeTriggerDisconnect = 2,
    kWakeTriggerSSID = 3
  };

  virtual ~WakeOnWiFiInterface() = default;

  virtual void InitPropertyStore(PropertyStore* store) = 0;
  virtual void Start() = 0;
  virtual void ParseWakeOnWiFiCapabilities(
      const Nl80211Message& nl80211_message) = 0;
  virtual void OnBeforeSuspend(
      bool is_connected,
      const std::vector<ByteString>& allowed_ssids,
      ResultCallback done_callback,
      base::OnceClosure renew_dhcp_lease_callback,
      base::OnceClosure remove_supplicant_networks_callback,
      std::optional<base::TimeDelta> time_to_next_lease_renewal) = 0;
  virtual void OnAfterResume() = 0;
  virtual void OnDarkResume(
      bool is_connected,
      const std::vector<ByteString>& allowed_ssids,
      ResultCallback done_callback,
      base::OnceClosure renew_dhcp_lease_callback,
      InitiateScanCallback initiate_scan_callback,
      const base::RepeatingClosure& remove_supplicant_networks_callback) = 0;
  virtual void OnConnectedAndReachable(
      std::optional<base::TimeDelta> time_to_next_lease_renewal) = 0;
  virtual void ReportConnectedToServiceAfterWake(bool is_connected,
                                                 int seconds_in_suspend) = 0;
  virtual void OnNoAutoConnectableServicesAfterScan(
      const std::vector<ByteString>& allowed_ssids,
      base::OnceClosure remove_supplicant_networks_callback,
      InitiateScanCallback initiate_scan_callback) = 0;
  virtual void OnScanStarted(bool is_active_scan) = 0;
  virtual void OnScanCompleted() = 0;
  virtual void OnWiphyIndexReceived(uint32_t index) = 0;
};

}  // namespace shill

#endif  // SHILL_WIFI_WAKE_ON_WIFI_INTERFACE_H_
