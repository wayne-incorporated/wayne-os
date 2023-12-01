// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_WIFI_WAKE_ON_WIFI_H_
#define SHILL_WIFI_WAKE_ON_WIFI_H_

#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/cancelable_callback.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST
#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>
#include <base/time/time.h>
#include <brillo/timers/alarm_timer.h>

#include "shill/callbacks.h"
#include "shill/net/event_history.h"
#include "shill/net/ip_address.h"
#include "shill/net/netlink_manager.h"
#include "shill/refptr_types.h"
#include "shill/wifi/wake_on_wifi_interface.h"
#include "shill/wifi/wifi.h"

namespace shill {

class ByteString;
class Error;
class EventDispatcher;
class GetWakeOnWiFiMessage;
class Metrics;
class Nl80211Message;
class PropertyStore;
class SetWakeOnWiFiMessage;

// |WakeOnWiFi| performs all wake on WiFi related tasks and logic (e.g.
// suspend/dark resume/resume logic, NIC wowlan programming via nl80211), and
// stores the state necessary to perform these actions.
//
// Shill implements wake on WiFi features:
//      Dark connect: this feature allows the CrOS device to maintain WiFi
//      connectivity while suspended, and to wake from suspend in a low-power
//      state (dark resume) to maintain or re-establish WiFi connectivity.
// This feature can be enabled/disabled by assigning the appropriate value to
// |wake_on_wifi_features_enabled_|.
//
// Note that wake on WiFi features are different from wake on WiFi triggers. The
// former refers to shill's suspend/resume/dark resume handling logic, whereas
// the latter refers to the NIC's  ability to wake the CPU on certain network
// events (e.g. disconnects). In order for shill's wake on WiFi features to
// work, the platform must be compiled with wake on WiFi support (i.e.
// DISABLE_WAKE_ON_WIFI not set), and its NIC must support the triggers required
// for the features to work (see
// WakeOnWiFi::WakeOnWiFiDarkConnectEnabledAndSupported for more details).
//
// The logic shill uses before, during (i.e. during dark resume), and after
// suspend when both wake on WiFi features are enabled are described below:
//
// OnBeforeSuspend
// ================
// This function is run when Manager announces an upcoming system suspend.
//
//         +--------------+
//         |          Yes |   +----------------+
// +-------+--------+     +-->|Renew DHCP Lease|
// |  Connected &   |         +------+---------+
// |holding expiring|                |
// |  DHCP lease?   |                v
// +------+---------+         +--------------------+
//        |               +-> |BeforeSuspendActions|
//        |           No  |   +--------------------+
//        +---------------+
//
// OnDarkResume
// =============
// This function is run when Manager announces that the system has entered
// dark resume and that there is an upcoming system suspend.
//
// +-------------+      +------------+     Unsupported     +----------+
// |  Too many   +----->|Wake reason?+-------------------->|Connected?|
// |dark resumes?|  No  +------------+                     +-+-----+--+
// +------+------+                |                          |     |
//        | Yes                   | Disconnect/           No |     | Yes
//        v                       |    SSID                  |     |
// +-------------------+          v                          |     |
// |  Disable Wake on  |        +------------+               |     v
// |  WiFi, start wake |        |  Initiate  |<--------------+    +--------+
// |  to scan timer &  |        |passive scan|                    |Get DHCP|
// |  report readiness |        +-+----------+           +------->| Lease  |
// +-------------------+          | ScanDone         Yes |        +--+---+-+
//                                v                      |           |   |
//                              +-------------+      +---------+     |   |
//                         No   | Any services| Yes  |Connected|     |   |
//         +--------------------+available for+----->| to AP?  |     |   |
//         |                    | autoconnect?|      +---+-----+     |   |
//         |                    +-------------+          |           |   |
//         |                                             |No         |   |
//         v                                             |           |   |
// +--------------------+       +-------+                |           |   |
// |BeforeSuspendActions|<------+Timeout|<---------------+       No  |   |
// +--------------------+       +-------+<---------------------------+   |
//         ^                                                             |
//         |                   +-------------------+                     |
//         +-------------------+   OnGetDHCPLease/ |             Yes     |
//                             |OnIPv6ConfigUpdated|<--------------------+
//                             +-------------------+
//
// BeforeSuspendActions
// =====================
// This function is run immediately before the system reports suspend readiness
// to Manager. This is the common "exit path" taken by OnBeforeSuspend and
// OnDarkResume before suspending.
//
// +----------------------+        No
// | Dark connect feature +---------------------------------+
// |enabled and supported?|                                 |
// +--+-------------------+                                 |
//    |                                                     |
//    |Yes    Yes   +----------------------------+          |        +---------+
//    |     +-----> |Set Wake on Disconnect flag,+--+    +--v----+   |Report   |
//    |     |       |Start Lease Renewal Timer*  |  |    |Program|   |Suspend  |
//    |     |       +----------------------------+  +--> |  NIC  |   |Readiness|
// +--v-----+-+                                     |    +-+---+-+   +--+------+
// |Connected?|                                     |      |   ^        ^
// +--------+-+                                     |      |   |Failed  |
//          |                                       |      ^   |        |Success
//          |       +----------------------------+  |  +---+---+---+    |
//          +-----> |Set Wake on SSID flag,      +--+  |  Verify   +----+
//            No    |Start Wake To Scan Timer**  |     |Programming|
//                  +----------------------------+     +-----------+
//
// *  if necessary (as indicated by caller of BeforeSuspendActions).
// ** if we need to allow more SSIDs than our NIC supports.
//
// OnAfterResume
// ==============
// This is run after Manager announces that the system has fully resumed from
// suspend.
//
// Wake on WiFi is disabled on the NIC if it was enabled before suspend or
// dark resume, and both the wake to scan timer and DHCP lease renewal timers
// are stopped.

class WakeOnWiFi : public WakeOnWiFiInterface {
 public:
  WakeOnWiFi(NetlinkManager* netlink_manager,
             EventDispatcher* dispatcher,
             Metrics* metrics,
             RecordWakeReasonCallback record_wake_reason_callback);
  WakeOnWiFi(const WakeOnWiFi&) = delete;
  WakeOnWiFi& operator=(const WakeOnWiFi&) = delete;

  ~WakeOnWiFi() override;

  // Registers |store| with properties related to wake on WiFi.
  void InitPropertyStore(PropertyStore* store) override;

  // Starts |metrics_timer_| so that wake on WiFi related metrics are
  // periodically collected.
  void Start() override;

  // Given a NL80211_CMD_NEW_WIPHY message |nl80211_message|, parses the
  // wake on WiFi capabilities of the NIC and set relevant members of this
  // WakeOnWiFi object to reflect the supported capbilities.
  void ParseWakeOnWiFiCapabilities(
      const Nl80211Message& nl80211_message) override;
  // Callback invoked when the system reports its wakeup reason.
  //
  // Arguments:
  //  - |netlink_message|: wakeup report message (note: must manually check
  //    this message to make sure it is a wakeup report message).
  //
  // Note: Assumes only one wakeup reason is received. If more than one is
  // received, the only first one parsed will be handled.
  void OnWakeupReasonReceived(const NetlinkMessage& netlink_message);
  // Performs pre-suspend actions relevant to wake on WiFi functionality.
  //
  // Arguments:
  //  - |is_connected|: whether the WiFi device is connected.
  //  - |allowed_ssids|: list of SSIDs that the NIC will be programmed to wake
  //    the system on if the NIC is programmed to wake on SSID.
  //  - |done_callback|: callback to invoke when suspend  actions have
  //    completed.
  //  - |renew_dhcp_lease_callback|: callback to invoke to initiate DHCP lease
  //    renewal.
  //  - |remove_supplicant_networks_callback|: callback to invoke
  //    to remove all networks from WPA supplicant.
  //  - |time_to_next_lease_renewal|: duration until next DHCP lease renewal is
  //    due, if there is a DHCP lease to renew; std::nullopt otherwise.
  void OnBeforeSuspend(
      bool is_connected,
      const std::vector<ByteString>& allowed_ssids,
      ResultCallback done_callback,
      base::OnceClosure renew_dhcp_lease_callback,
      base::OnceClosure remove_supplicant_networks_callback,
      std::optional<base::TimeDelta> time_to_next_lease_renewal) override;
  // Performs post-resume actions relevant to wake on wireless functionality.
  void OnAfterResume() override;
  // Performs and post actions to be performed in dark resume.
  //
  // Arguments:
  //  - |is_connected|: whether the WiFi device is connected.
  //  - |allowed_ssids|: list of SSIDs that the NIC will be programmed to wake
  //    the system on if the NIC is programmed to wake on SSID.
  //  - |done_callback|: callback to invoke when dark resume actions have
  //    completed.
  //  - |renew_dhcp_lease_callback|: callback to invoke to initiate DHCP lease
  //    renewal.
  //  - |initate_scan_callback|: callback to invoke to initiate a scan.
  //  - |remove_supplicant_networks_callback|: callback to invoke
  //    to remove all networks from WPA supplicant.
  void OnDarkResume(bool is_connected,
                    const std::vector<ByteString>& allowed_ssids,
                    ResultCallback done_callback,
                    base::OnceClosure renew_dhcp_lease_callback,
                    InitiateScanCallback initiate_scan_callback,
                    const base::RepeatingClosure&
                        remove_supplicant_networks_callback) override;
  // Called when we the current service is connected, and we have IP
  // reachability. Calls WakeOnWiFi::BeforeSuspendActions if we are in dark
  // resume to end the current dark resume. Otherwise, does nothing.
  void OnConnectedAndReachable(
      std::optional<base::TimeDelta> time_to_next_lease_renewal) override;
  // Callback invoked to report whether this WiFi device is connected to
  // a service after waking from suspend.
  void ReportConnectedToServiceAfterWake(bool is_connected,
                                         int seconds_in_suspend) override;
  // Called in WiFi::ScanDoneTask when there are no WiFi services available
  // for auto-connect after a scan. |initiate_scan_callback| is used for dark
  // resume scan retries.
  void OnNoAutoConnectableServicesAfterScan(
      const std::vector<ByteString>& allowed_ssids,
      base::OnceClosure remove_supplicant_networks_callback,
      InitiateScanCallback initiate_scan_callback) override;
  // Called by WiFi when it is notified by the kernel that a scan has started.
  // If |is_active_scan| is true, the scan is an active scan. Otherwise, the
  // scan is a passive scan.
  void OnScanStarted(bool is_active_scan) override;

  // Called by WiFi when a scan is completed.
  void OnScanCompleted() override;

  void OnWiphyIndexReceived(uint32_t index) override;

 private:
  friend class WakeOnWiFiTest;  // access to several members for tests
  friend class WiFiObjectTest;  // netlink_manager_
  // kMaxSetWakeOnWiFiRetries.
  FRIEND_TEST(WakeOnWiFiTestWithMockDispatcher,
              RetrySetWakeOnWiFiConnections_LessThanMaxRetries);
  FRIEND_TEST(WakeOnWiFiTestWithMockDispatcher,
              RetrySetWakeOnWiFiConnections_MaxAttemptsWithCallbackSet);
  FRIEND_TEST(WakeOnWiFiTestWithMockDispatcher,
              RetrySetWakeOnWiFiConnections_MaxAttemptsCallbackUnset);
  // kDarkResumeActionsTimeout
  FRIEND_TEST(WakeOnWiFiTestWithMockDispatcher,
              OnBeforeSuspend_DHCPLeaseRenewal);
  // Dark resume wake reason strings (e.g. kWakeReasonStringDisconnect)
  FRIEND_TEST(WakeOnWiFiTestWithMockDispatcher,
              OnWakeupReasonReceived_Disconnect);
  FRIEND_TEST(WakeOnWiFiTestWithMockDispatcher, OnWakeupReasonReceived_SSID);
  // kMaxDarkResumesPerPeriodShort
  // kDarkResumeFrequencySamplingPeriodShort,
  // kMaxDarkResumesPerPeriodShort
  FRIEND_TEST(WakeOnWiFiTestWithDispatcher,
              OnDarkResume_NotConnected_MaxDarkResumes_ShortPeriod);
  // kDarkResumeFrequencySamplingPeriodLong,
  // kMaxDarkResumesPerPeriodLong,
  // kDarkResumeFrequencySamplingPeriodShort,
  // kMaxDarkResumesPerPeriodShort
  FRIEND_TEST(WakeOnWiFiTestWithDispatcher,
              OnDarkResume_NotConnected_MaxDarkResumes_LongPeriod);
  // kMaxFreqsForDarkResumeScanRetries, kMaxDarkResumeScanRetries
  FRIEND_TEST(WakeOnWiFiTestWithDispatcher, InitiateScanInDarkResume);

  static const char kWakeOnWiFiNotAllowed[];
  static constexpr base::TimeDelta kVerifyWakeOnWiFiSettingsDelay =
      base::Milliseconds(300);
  static const int kMaxSetWakeOnWiFiRetries;
  static constexpr base::TimeDelta kMetricsReportingFrequency =
      base::Minutes(10);
  static const uint32_t kDefaultWakeToScanPeriodSeconds;
  static const uint32_t kDefaultNetDetectScanPeriodSeconds;
  static constexpr base::TimeDelta kImmediateDHCPLeaseRenewalThreshold =
      base::Minutes(1);
  static constexpr base::TimeDelta kDarkResumeFrequencySamplingPeriodShort =
      base::Minutes(1);
  static constexpr base::TimeDelta kDarkResumeFrequencySamplingPeriodLong =
      base::Minutes(10);
  static const int kMaxDarkResumesPerPeriodShort;
  static const int kMaxDarkResumesPerPeriodLong;
  static base::TimeDelta DarkResumeActionsTimeout;  // non-const for testing
  static const int kMaxFreqsForDarkResumeScanRetries;
  static const int kMaxDarkResumeScanRetries;

  bool GetWakeOnWiFiAllowed(Error* error);
  bool SetWakeOnWiFiAllowed(const bool& enabled, Error* error);
  std::string GetWakeOnWiFiFeaturesEnabled(Error* error);
  bool SetWakeOnWiFiFeaturesEnabled(const std::string& enabled, Error* error);
  std::string GetLastWakeReason(Error* error);
  // Helper function to run |suspend_actions_done_callback_|.
  void RunSuspendActionsDoneCallback(const Error& error);

  // Creates and sets an attribute in a NL80211 message |msg| which indicates
  // the index of the wiphy interface to program. Returns true iff |msg| is
  // successfully configured.
  static bool ConfigureWiphyIndex(Nl80211Message* msg, int32_t index);
  // Creates and sets attributes in an SetWakeOnWiFiMessage |msg| so that
  // the message will disable wake-on-packet functionality of the NIC with wiphy
  // index |wiphy_index|. Returns true iff |msg| is successfully configured.
  // NOTE: Assumes that |msg| has not been altered since construction.
  static bool ConfigureDisableWakeOnWiFiMessage(SetWakeOnWiFiMessage* msg,
                                                uint32_t wiphy_index,
                                                Error* error);
  // Creates and sets attributes in a SetWakeOnWiFiMessage |msg|
  // so that the message will program the NIC with wiphy index |wiphy_index|
  // with wake on wireless triggers in |trigs|. If |trigs| contains the kSSID
  // trigger, the message is configured to program the NIC to wake on the SSIDs
  // in |allowed_ssids|.
  // Returns true iff |msg| is successfully configured.
  // NOTE: Assumes that |msg| has not been altered since construction.
  static bool ConfigureSetWakeOnWiFiSettingsMessage(
      SetWakeOnWiFiMessage* msg,
      const std::set<WakeOnWiFiTrigger>& trigs,
      uint32_t wiphy_index,
      uint32_t net_detect_scan_period_seconds,
      const std::vector<ByteString>& allowed_ssids,
      Error* error);
  // Creates and sets attributes in an GetWakeOnWiFiMessage msg| so that
  // the message will request for wake-on-packet settings information from the
  // NIC with wiphy index |wiphy_index|. Returns true iff |msg| is successfully
  // configured.
  // NOTE: Assumes that |msg| has not been altered since construction.
  static bool ConfigureGetWakeOnWiFiSettingsMessage(GetWakeOnWiFiMessage* msg,
                                                    uint32_t wiphy_index,
                                                    Error* error);
  // Given a NL80211_CMD_GET_WOWLAN response or NL80211_CMD_SET_WOWLAN request
  // |msg|, returns true iff the wake-on-wifi trigger settings in |msg| match
  // those in |trigs|. Performs the following checks for the following triggers:
  // - kWakeTriggerDisconnect: checks that the wake on disconnect flag is
  //   present and set.
  // - kSSID: checks that the SSIDs in |allowed_ssids| and the scan interval
  //   |net_detect_scan_period_seconds| match those reported in |msg|.
  // Note: finding a trigger is in |msg| that is not expected based on the flags
  // in |trig| also counts as a mismatch.
  static bool WakeOnWiFiSettingsMatch(
      const Nl80211Message& msg,
      const std::set<WakeOnWiFiTrigger>& trigs,
      uint32_t net_detect_scan_period_seconds,
      const std::vector<ByteString>& allowed_ssids);
  // Handler for NL80211 message error responses from NIC wake on WiFi setting
  // programming attempts.
  void OnWakeOnWiFiSettingsErrorResponse(
      NetlinkManager::AuxiliaryMessageType type,
      const NetlinkMessage* raw_message);
  // Message handler for NL80211_CMD_SET_WOWLAN responses.
  static void OnSetWakeOnWiFiConnectionResponse(
      const Nl80211Message& nl80211_message);
  // Request wake on WiFi settings for this WiFi device.
  void RequestWakeOnWiFiSettings();
  // Verify that the wake on WiFi settings programmed into the NIC match
  // those recorded locally for this device in |wake_on_packet_connections_|,
  // |wake_on_wifi_triggers_|, and |wake_on_allowed_ssids_|.
  void VerifyWakeOnWiFiSettings(const Nl80211Message& nl80211_message);
  // Sends an NL80211 message to program the NIC with wake on WiFi settings
  // configured in |wake_on_packet_connections_|, |wake_on_allowed_ssids_|, and
  // |wake_on_wifi_triggers_|. If |wake_on_wifi_triggers_| is empty, calls
  // WakeOnWiFi::DisableWakeOnWiFi.
  void ApplyWakeOnWiFiSettings();
  // Helper function called by |ApplyWakeOnWiFiSettings| that sends an NL80211
  // message to program the NIC to disable wake on WiFi.
  void DisableWakeOnWiFi();
  // Calls |ApplyWakeOnWiFiSettings| and counts this call as
  // a retry. If |kMaxSetWakeOnWiFiRetries| retries have already been
  // performed, resets counter and returns.
  void RetrySetWakeOnWiFiConnections();
  // Utility function to check if wake on WiFi is not supported or disabled.
  bool WakeOnWiFiDisabled();
  // Utility functions to check which wake on WiFi features are currently
  // enabled based on the descriptor |wake_on_wifi_features_enabled_| and
  // are supported by the NIC.
  bool WakeOnWiFiDarkConnectEnabledAndSupported();
  // Actions executed before normal suspend and dark resume suspend.
  //
  // Arguments:
  //  - |is_connected|: whether the WiFi device is connected.
  //  - |time_to_next_lease_renewal|: duration until next DHCP lease renewal is
  //    due if start the DHCP lease renewal timer; std::nullopt if not.
  //  - |remove_supplicant_networks_callback|: callback to invoke
  //    to remove all networks from WPA supplicant.
  void BeforeSuspendActions(
      bool is_connected,
      std::optional<base::TimeDelta> time_to_next_lease_renewal,
      base::OnceClosure remove_supplicant_networks_callback);

  // Parses an attribute list containing the SSID matches that caused the
  // system wake, along with the corresponding channels that these SSIDs were
  // detected in. Returns a set of unique frequencies that the reported
  // SSID matches occured in.
  //
  // Arguments:
  //  - |results_list|: Nested attribute list containing an array of nested
  //    attributes which contain the NL80211_ATTR_SSID or
  //    NL80211_ATTR_SCAN_FREQUENCIES attributes. This attribute list is assumed
  //    to have been extracted from a NL80211_CMD_SET_WOWLAN response message
  //    using the NL80211_WOWLAN_TRIG_NET_DETECT_RESULTS id.
  static WiFi::FreqSet ParseWakeOnSSIDResults(
      AttributeListConstRefPtr results_list);

  // Sets the |dark_resume_scan_retries_left_| counter if necessary, then runs
  // |initiate_scan_callback| with |freqs|.
  void InitiateScanInDarkResume(InitiateScanCallback initiate_scan_callback,
                                const WiFi::FreqSet& freqs);

  // Pointers to objects owned by the WiFi object that created this object.
  EventDispatcher* dispatcher_;
  NetlinkManager* netlink_manager_;
  Metrics* metrics_;
  // Executes after the NIC's wake on WiFi settings are configured via
  // NL80211 messages to verify that the new configuration has taken effect.
  // Calls RequestWakeOnWiFiSettings.
  base::CancelableOnceClosure verify_wake_on_wifi_settings_callback_;
  // Callback to be invoked after all suspend actions finish executing both
  // before regular suspend and before suspend in dark resume.
  ResultCallback suspend_actions_done_callback_;
  // Number of retry attempts to program the NIC's wake-on-WiFi settings.
  int num_set_wake_on_wifi_retries_;
  // Keeps track of triggers that the NIC will be programmed to wake from
  // while suspended.
  std::set<WakeOnWiFiTrigger> wake_on_wifi_triggers_;
  // Keeps track of what wake on wifi triggers this WiFi device supports.
  std::set<WakeOnWiFiTrigger> wake_on_wifi_triggers_supported_;
  // Max number of SSIDs this WiFi device can be programmed to wake on at one
  // time.
  uint32_t wake_on_wifi_max_ssids_;
  // Keeps track of SSIDs that this device will wake on the appearance of while
  // the device is suspended. Only used if the NIC is programmed to wake on
  // SSIDs.
  std::vector<ByteString> wake_on_allowed_ssids_;
  uint32_t wiphy_index_;
  bool wiphy_index_received_;
  // Describes if wake on WiFi is allowed to be enabled.
  bool wake_on_wifi_allowed_;
  // Describes the wake on WiFi features that are currently enabled.
  std::string wake_on_wifi_features_enabled_;
  // Timer that wakes the system to renew DHCP leases.
  std::unique_ptr<brillo::timers::SimpleAlarmTimer> dhcp_lease_renewal_timer_;
  // Timer that wakes the system to scan for networks.
  std::unique_ptr<brillo::timers::SimpleAlarmTimer> wake_to_scan_timer_;
  // Executes when the dark resume actions timer expires. Calls
  // ScanTimerHandler.
  base::CancelableOnceClosure dark_resume_actions_timeout_callback_;
  // Whether shill is currently in dark resume.
  bool in_dark_resume_;
  // Period (in seconds) between instances where the system wakes from suspend
  // to scan for networks in dark resume.
  uint32_t wake_to_scan_period_seconds_;
  // Period (in seconds) between instances where the NIC performs Net Detect
  // scans while the system is suspended.
  uint32_t net_detect_scan_period_seconds_;
  // Timestamps of dark resume wakes that took place during the current
  // or most recent suspend.
  EventHistory dark_resume_history_;
  // Last wake reason reported by the kernel.
  WakeOnWiFiTrigger last_wake_reason_;
  // Whether or not to always start |wake_to_scan_timer_| before suspend.
  bool force_wake_to_scan_timer_;
  // Frequencies that the last wake on SSID matches reported by the kernel
  // occurred in.
  WiFi::FreqSet last_ssid_match_freqs_;
  // How many more times to retry the last dark resume scan that shill launched
  // if no auto-connectable services were found.
  int dark_resume_scan_retries_left_;

  // connected_before_suspend_ is written once in OnBeforeSuspend
  // and never reset. It can be read by anyone until it is overwritten
  // by the next invocation of OnBeforeSuspend
  bool connected_before_suspend_;

  // Hardware address of the WiFi device that owns the specific
  // wake_on_wifi object.
  const std::string mac_address_;

  // Callback invoked to report the wake reason for the current dark resume to
  // powerd.
  RecordWakeReasonCallback record_wake_reason_callback_;

  // Netlink broadcast handler, for wakeup reasons.
  NetlinkManager::NetlinkMessageHandler netlink_handler_;

  base::WeakPtrFactory<WakeOnWiFi> weak_ptr_factory_;
};

}  // namespace shill

#endif  // SHILL_WIFI_WAKE_ON_WIFI_H_
