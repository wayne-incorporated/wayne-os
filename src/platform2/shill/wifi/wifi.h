// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_WIFI_WIFI_H_
#define SHILL_WIFI_WIFI_H_

// A WiFi device represents a wireless network interface implemented as an IEEE
// 802.11 station.  An Access Point (AP) (or, more correctly, a Basic Service
// Set(BSS)) is represented by a WiFiEndpoint.  An AP provides a WiFiService,
// which is the same concept as Extended Service Set (ESS) in 802.11,
// identified by an SSID.  A WiFiService includes zero or more WiFiEndpoints
// that provide that service.
//
// A WiFi device interacts with a real device through WPA Supplicant.
// Wifi::Start() creates a connection to WPA Supplicant, represented by
// |supplicant_interface_proxy_|.  [1]
//
// A WiFi device becomes aware of WiFiEndpoints through BSSAdded signals from
// WPA Supplicant, which identifies them by a "path".  The WiFi object maintains
// an EndpointMap in |endpoint_by_rpcid_|, in which the key is the "path" and
// the value is a pointer to a WiFiEndpoint object.  When a WiFiEndpoint is
// added, it is associated with a WiFiService.
//
// The WiFi device connects to a WiFiService, not a WiFiEndpoint, through WPA
// Supplicant. It is the job of WPA Supplicant to select a BSS (aka
// WiFiEndpoint) to connect to.  The protocol for establishing a connection is
// as follows:
//
//  1.  The WiFi device sends AddNetwork to WPA Supplicant, which returns a
//  "network path" when done.
//
//  2.  The WiFi device sends SelectNetwork, indicating the network path
//  received in 1, to WPA Supplicant, which begins the process of associating
//  with an AP in the ESS.  At this point the WiFiService which is being
//  connected is called the |pending_service_|.
//
//  3.  During association to an EAP-TLS network, WPA Supplicant can send
//  multiple "Certification" events, which provide information about the
//  identity of the remote entity.
//
//  4.  When association is complete, WPA Supplicant sends a PropertiesChanged
//  signal to the WiFi device, indicating a change in the CurrentBSS.  The
//  WiFiService indicated by the new value of CurrentBSS is set as the
//  |current_service_|, and |pending_service_| is (normally) cleared.
//
// Some key things to notice are 1) WPA Supplicant does the work of selecting
// the AP (aka WiFiEndpoint) and it tells the WiFi device which AP it selected.
// 2) The process of connecting is asynchronous.  There is a |current_service_|
// to which the WiFi device is presently using and a |pending_service_| to which
// the WiFi device has initiated a connection.
//
// A WiFi device is notified that an AP has gone away via the BSSRemoved signal.
// When the last WiFiEndpoint of a WiFiService is removed, the WiFiService
// itself is deleted.
//
// TODO(gmorain): Add explanation of hidden SSIDs.
//
// WPA Supplicant's PropertiesChanged signal communicates changes in the state
// of WPA Supplicant's current service.  This state is stored in
// |supplicant_state_| and reflects WPA Supplicant's view of the state of the
// connection to an AP.  Changes in this state sometimes cause state changes in
// the WiFiService to which a WiFi device is connected.  For example, when WPA
// Supplicant signals the new state to be "completed", then the WiFiService
// state gets changed to "configuring".  State change notifications are not
// reliable because WPA Supplicant may coalesce state changes in quick
// succession so that only the last of the changes is signaled.
//
// Notes:
//
// 1.  Shill's definition of the interface is described in
// shill/dbus_proxies/supplicant-interface.xml, and the WPA Supplicant's
// description of the same interface is in
// third_party/wpa_supplicant/doc/dbus.doxygen.

#include <linux/nl80211.h>
#include <time.h>

#include <list>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/cancelable_callback.h>
#include <base/functional/callback_forward.h>
#include <base/memory/weak_ptr.h>
#include <base/strings/string_piece.h>
#include <base/time/time.h>
#include <chromeos/patchpanel/dbus/client.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/device.h"
#include "shill/mockable.h"
#include "shill/net/ieee80211.h"
#include "shill/net/ip_address.h"
#include "shill/net/netlink_manager.h"
#include "shill/net/rtnl_link_stats.h"
#include "shill/net/shill_time.h"
#include "shill/refptr_types.h"
#include "shill/service.h"
#include "shill/store/key_value_store.h"
#include "shill/supplicant/supplicant_event_delegate_interface.h"
#include "shill/supplicant/supplicant_manager.h"
#include "shill/wifi/wifi_link_statistics.h"
#include "shill/wifi/wifi_state.h"

namespace shill {

class Error;
class Metrics;
class NetlinkManager;
class NetlinkMessage;
class Nl80211Message;
class SupplicantEAPStateHandler;
class SupplicantInterfaceProxyInterface;
class SupplicantProcessProxyInterface;
class WakeOnWiFiInterface;
class WiFiCQM;
class WiFiPhy;
class WiFiProvider;
class WiFiService;

// WiFi class. Specialization of Device for WiFi.
class WiFi : public Device, public SupplicantEventDelegateInterface {
 public:
  using FreqSet = std::set<uint32_t>;

  WiFi(Manager* manager,
       const std::string& link,
       const std::string& address,
       int interface_index,
       uint32_t phy_index,
       std::unique_ptr<WakeOnWiFiInterface> wake_on_wifi);
  WiFi(const WiFi&) = delete;
  WiFi& operator=(const WiFi&) = delete;

  ~WiFi() override;

  // Returns phy index associated with WiFi device.
  uint32_t phy_index() const { return phy_index_; }

  void Start(EnabledStateChangedCallback callback) override;
  void Stop(EnabledStateChangedCallback callback) override;
  void Scan(Error* error, const std::string& reason) override;
  void EnsureScanAndConnectToBestService(Error* error);
  // Callback for system suspend.
  void OnBeforeSuspend(ResultCallback callback) override;
  // Callback for dark resume.
  void OnDarkResume(ResultCallback callback) override;
  // Callback for system resume. If this WiFi device is idle, a scan
  // is initiated. Additionally, the base class implementation is
  // invoked unconditionally.
  void OnAfterResume() override;
  // Callback for when a service is configured with an IP.
  void OnConnected() override;
  // Callback for when the selected service is changed.
  void OnSelectedServiceChanged(const ServiceRefPtr& old_service) override;
  // Callback for when a service fails to configure with an IP.
  void OnIPConfigFailure() override;

  // Implementation of SupplicantEventDelegateInterface.  These methods
  // are called by SupplicantInterfaceProxy, in response to events from
  // wpa_supplicant.
  void BSSAdded(const RpcIdentifier& BSS,
                const KeyValueStore& properties) override;
  void BSSRemoved(const RpcIdentifier& BSS) override;
  void Certification(const KeyValueStore& properties) override;
  void EAPEvent(const std::string& status,
                const std::string& parameter) override;
  void InterworkingAPAdded(const RpcIdentifier& BSS,
                           const RpcIdentifier& cred,
                           const KeyValueStore& properties) override;
  void InterworkingSelectDone() override;
  void PropertiesChanged(const KeyValueStore& properties) override;
  void ScanDone(const bool& success) override;
  void StationAdded(const RpcIdentifier& Station,
                    const KeyValueStore& properties) override{};
  void StationRemoved(const RpcIdentifier& Station) override{};
  void PskMismatch() override;

  // Unregister and Reregister WiFi device.
  virtual void Restart();

  // Called by WiFiService.
  virtual void ConnectTo(WiFiService* service, Error* error);

  // After checking |service| state is active, initiate
  // process of disconnecting.  Log and return if not active.
  virtual void DisconnectFromIfActive(WiFiService* service);

  // If |service| is connected, initiate the process of disconnecting it.
  // Otherwise, if it a pending or current service, discontinue the process
  // of connecting and return |service| to the idle state.
  virtual void DisconnectFrom(WiFiService* service);
  virtual bool IsIdle() const;
  // Clear any cached credentials wpa_supplicant may be holding for
  // |service|.  This has a side-effect of disconnecting the service
  // if it is connected.
  virtual void ClearCachedCredentials(const WiFiService* service);

  // Called by WiFiEndpoint.
  virtual void NotifyEndpointChanged(const WiFiEndpointConstRefPtr& endpoint);

  // Utility, used by WiFiService and WiFiEndpoint.
  // Replace non-ASCII characters with '?'. Return true if one or more
  // characters were changed.
  static bool SanitizeSSID(std::string* ssid);

  // Formats |ssid| for logging purposes, to ease scrubbing.
  static std::string LogSSID(const std::string& ssid);

  virtual bool IsCurrentService(const WiFiService* service) const {
    return service == current_service_.get();
  }

  bool random_mac_supported() const { return random_mac_supported_; }

  bool IsPendingService(const WiFiService* service) const {
    return service == pending_service_.get();
  }

  const WiFiEndpointConstRefPtr GetCurrentEndpoint() const;

  // Overridden from Device superclass
  void UpdateGeolocationObjects(
      std::vector<GeolocationInfo>* geolocation_infos) const override;
  // Called by a WiFiService when it disassociates itself from this Device.
  virtual void DisassociateFromService(const WiFiServiceRefPtr& service);

  // Called by a WiFiService when it unloads to destroy its lease file.
  virtual void DestroyServiceLease(const WiFiService& service);

  // Remove all networks from WPA supplicant.
  // Passed as a callback to |wake_on_wifi_| where it is used.
  void RemoveSupplicantNetworks();

  bool RequestRoam(const std::string& addr, Error* error) override;

  bool SupportsWPA3() const;

  void GetDeviceHardwareIds(int* vendor, int* product, int* subsystem) const;

  // Inherited from Device.
  void OnNeighborReachabilityEvent(
      int interface_index,
      const IPAddress& ip_address,
      patchpanel::Client::NeighborRole role,
      patchpanel::Client::NeighborStatus status) override;

  mockable int16_t GetSignalLevelForActiveService();

  // Add a set of Passpoint credentials to WPA supplicant.
  bool AddCred(const PasspointCredentialsRefPtr& credentials);

  // Removes a set of Passpoint credentials from WPA supplicant.
  bool RemoveCred(const PasspointCredentialsRefPtr& credentials);

  // Process old_rtnl_link_stats64 information
  void OnReceivedRtnlLinkStatistics(const old_rtnl_link_stats64& stats);

  // Send a structured event to notify that we've requested link statistics
  // from the driver.
  mockable void EmitStationInfoRequestEvent(
      WiFiLinkStatistics::Trigger trigger);

  // Sets the BSSID allowlist in WPA supplicant for the |service|. This doesn't
  // affect the currently connected network if there is one. Any changes will
  // take effect on the next network (re)connection.
  mockable bool SetBSSIDAllowlist(const WiFiService* service,
                                  const Strings& bssid_allowlist,
                                  Error* error);

 private:
  // Result from a BSSAdded or BSSRemoved event.
  struct ScanResult {
    ScanResult() : is_removal(false) {}
    ScanResult(const RpcIdentifier& path_in,
               const KeyValueStore& properties_in,
               bool is_removal_in)
        : path(path_in), properties(properties_in), is_removal(is_removal_in) {}
    RpcIdentifier path;
    KeyValueStore properties;
    bool is_removal;
  };

  struct PendingScanResults {
    PendingScanResults() : is_complete(false) {}
    explicit PendingScanResults(base::OnceClosure process_results_callback)
        : is_complete(false), callback(std::move(process_results_callback)) {}

    // List of pending scan results to process.
    std::vector<ScanResult> results;

    // If true, denotes that the scan is complete (ScanDone() was called).
    bool is_complete;

    // Cancelable closure used to process the scan results.
    base::CancelableOnceClosure callback;
  };

  // Result of a match between an access point and a set of credentials.
  struct InterworkingBSS {
    InterworkingBSS(const RpcIdentifier& bss_in,
                    const RpcIdentifier& cred_in,
                    const KeyValueStore& properties_in)
        : bss_path(bss_in), cred_path(cred_in), properties(properties_in) {}

    // Supplicant D-Bus path of the endpoint
    RpcIdentifier bss_path;
    // Supplicant D-Bus path of the set of credentials
    RpcIdentifier cred_path;
    // Match properties (priorities, ...)
    KeyValueStore properties;
  };

  friend class WiFiObjectTest;  // access to supplicant_*_proxy_, link_up_
  friend class WiFiTimerTest;   // kNumFastScanAttempts, kFastScanInterval
  friend class WiFiMainTest;    // wifi_state_
  FRIEND_TEST(WiFiMainTest, AppendBgscan);
  FRIEND_TEST(WiFiMainTest, BackgroundScan);  // wifi_state_
  FRIEND_TEST(WiFiMainTest, BSSIDChangeInvokesNotifyBSSIDChange);
  FRIEND_TEST(WiFiMainTest, ConnectToServiceNotPending);  // wifi_state
  FRIEND_TEST(WiFiMainTest, ConnectToServiceWithoutRecentIssues);
  // is_debugging_connection_
  FRIEND_TEST(WiFiMainTest, ConnectToWithError);       // wifi_state_
  FRIEND_TEST(WiFiMainTest, ConnectWhileNotScanning);  // wifi_state_
  FRIEND_TEST(WiFiMainTest, CurrentBSSChangedUpdateServiceEndpoint);
  FRIEND_TEST(WiFiMainTest, DisconnectReasonUpdated);
  FRIEND_TEST(WiFiMainTest, DisconnectReasonCleared);
  FRIEND_TEST(WiFiMainTest, CurrentAuthModeChanged);  // supplicant_auth_mode_
  FRIEND_TEST(WiFiMainTest, GetSuffixFromAuthMode);
  FRIEND_TEST(WiFiMainTest, FlushBSSOnResume);  // kMaxBSSResumeAgeSeconds
  FRIEND_TEST(WiFiMainTest, FullScanConnectingToConnected);
  FRIEND_TEST(WiFiMainTest,
              FullScanFindsNothing);                  // wifi_state_
  FRIEND_TEST(WiFiMainTest, InitialSupplicantState);  // kInterfaceStateUnknown
  FRIEND_TEST(WiFiMainTest, NoScansWhileConnecting);  // ScanState
  FRIEND_TEST(WiFiMainTest, PendingScanEvents);       // EndpointMap
  FRIEND_TEST(WiFiMainTest, EnsuredScan);             // wifi_state_
  FRIEND_TEST(WiFiMainTest,
              QueueEnsuredScan);  // wifi_state_
  FRIEND_TEST(WiFiMainTest,
              QueuedEnsuredScan);  // wifi_state_
  FRIEND_TEST(WiFiMainTest,
              QueuedEnsuredScanFoundNothing);  // wifi_state_
  FRIEND_TEST(WiFiMainTest,
              QueuedEnsuredScanBackgroundScanFinished);  // wifi_state_
  FRIEND_TEST(WiFiMainTest,
              QueuedEnsuredScanInterruptedByConnect);  // wifi_state_
  FRIEND_TEST(WiFiMainTest,
              QueuedEnsuredScanInterruptedByConnecting);  // wifi_state_
  FRIEND_TEST(
      WiFiMainTest,
      QueuedEnsuredScanInterruptedByTransitionToConnecting);  // wifi_state_
  FRIEND_TEST(
      WiFiMainTest,
      QueuedEnsuredScanInterruptedByUnexpectedIdleState);  // wifi_state_
  FRIEND_TEST(WiFiMainTest, RekeyInvokesNotifyRekeyStart);
  FRIEND_TEST(WiFiMainTest, ScanRejected);               // wifi_state_
  FRIEND_TEST(WiFiMainTest, ScanResults);                // EndpointMap
  FRIEND_TEST(WiFiMainTest, ScanStateHandleDisconnect);  // ScanState
  FRIEND_TEST(WiFiMainTest, ScanStateNotScanningNoUma);  // ScanState
  FRIEND_TEST(WiFiMainTest, ScanStateUma);               // wifi_state_
  FRIEND_TEST(WiFiMainTest, Stop);  // weak_ptr_factory_while_started_
  FRIEND_TEST(WiFiMainTest, TimeoutPendingServiceWithEndpoints);
  FRIEND_TEST(WiFiMainTest,
              UnreliableConnectionInvokesNotifyWiFiConnectionUnreliable);
  FRIEND_TEST(WiFiMainTest,
              UpdateGeolocationObjects);  // kWiFiGeolocationInfoExpiration
  FRIEND_TEST(WiFiPropertyTest, BgscanMethodProperty);  // bgscan_method_
  // interworking_select_enabled_ and need_interworking_select_
  FRIEND_TEST(WiFiPropertyTest, PasspointInterworkingProperty);
  FRIEND_TEST(WiFiTimerTest, FastRescan);          // kFastScanInterval
  FRIEND_TEST(WiFiTimerTest, RequestStationInfo);  // kRequestStationInfoPeriod
  // kPostWakeConnectivityReportDelay
  FRIEND_TEST(WiFiTimerTest, ResumeDispatchesConnectivityReportTask);
  // kFastScanInterval
  FRIEND_TEST(WiFiTimerTest, StartScanTimer_HaveFastScansRemaining);
  // wifi_state_
  FRIEND_TEST(WiFiMainTest, ResetScanStateWhenScanFailed);
  // kPostScanFailedDelay
  FRIEND_TEST(WiFiTimerTest, ScanDoneDispatchesTasks);
  // kMaxPassiveScanRetries, kMaxFreqsForPassiveScanRetries
  FRIEND_TEST(WiFiMainTest, InitiateScanInDarkResume_Idle);
  FRIEND_TEST(WiFiServiceTest, SetMACPolicy);
  FRIEND_TEST(WiFiServiceTest, UpdateMACAddressNonPersistentPolicy);
  FRIEND_TEST(WiFiServiceTest, UpdateMACAddressPersistentPolicy);
  FRIEND_TEST(WiFiServiceTest, UpdateMACAddressPolicySwitch);
  FRIEND_TEST(WiFiServiceTest, RandomizationNotSupported);

  using EndpointMap = std::map<const RpcIdentifier, WiFiEndpointRefPtr>;
  using ReverseServiceMap = std::map<const WiFiService*, RpcIdentifier>;

  static const char* const kDefaultBgscanMethod;
  static const int kSingleEndpointBgscanIntervalSeconds;
  static const uint16_t kBackgroundScanIntervalSeconds;
  static const uint16_t kDefaultScanIntervalSeconds;
  static const time_t kMaxBSSResumeAgeSeconds;
  static const char kInterfaceStateUnknown[];
  // Number of times to quickly attempt a scan after startup / disconnect.
  static const int kNumFastScanAttempts;
  static constexpr base::TimeDelta kFastScanInterval = base::Seconds(10);
  static constexpr base::TimeDelta kReconnectTimeout = base::Seconds(10);
  // Request the STA info from the driver periodically, among other things to
  // update the signal strength.
  static constexpr base::TimeDelta kRequestStationInfoPeriod =
      base::Seconds(20);
  // In addition to updating the link statistics locally, somewhat less
  // frequently (1 in |kReportStationInfoSample|) we also report the link
  // statistics through structured metrics.
  static constexpr int kReportStationInfoSample = 30;
  // Time to wait after waking from suspend to report the connection status to
  // metrics.
  // 1 second is less than the time it takes to scan and establish a new
  // connection after waking, but should be enough time for supplicant to update
  // its state.
  static constexpr base::TimeDelta kPostWakeConnectivityReportDelay =
      base::Seconds(1);
  // Time to wait after failing to launch a scan before resetting the scan state
  // to idle.
  static constexpr base::TimeDelta kPostScanFailedDelay = base::Seconds(10);
  // Used when enabling MAC randomization to request that the OUI remain
  // constant and the last three octets are randomized.
  static const std::vector<unsigned char> kRandomMacMask;
  // Used when wake_on_wifi_ is not available but related method is called.
  static const char kWakeOnWiFiNotSupported[];
  // Each cipher suite is 4 bytes as defined by IEEE 802.11-2016 section
  // 9.4.2.25.2.
  static constexpr uint32_t kWEP40CipherCode = 0x000FAC01;
  static constexpr uint32_t kWEP104CipherCode = 0x000FAC05;

  // WiFi geolocation information older than kWiFiGeolocationInfoExpiration will
  // be evicted when updating the geolocation cache
  static constexpr base::TimeDelta kWiFiGeolocationInfoExpiration =
      base::Minutes(20);

  void GetPhyInfo();
  std::string AppendBgscan(WiFiService* service,
                           KeyValueStore* service_params) const;
  bool ReconfigureBgscan(WiFiService* service);
  bool ReconfigureBgscanForRelevantServices();
  std::string GetBgscanMethod(Error* error);
  uint16_t GetBgscanShortInterval(Error* /* error */) {
    return bgscan_short_interval_seconds_;
  }
  int32_t GetBgscanSignalThreshold(Error* /* error */) {
    return bgscan_signal_threshold_dbm_;
  }
  // These methods can't be 'const' because they are passed to
  // HelpRegisterDerivedUint16 which don't take const methods.
  uint16_t GetScanInterval(Error* /* error */) /*const*/ {
    return scan_interval_seconds_;
  }
  bool GetInterworkingSelectEnabled(Error* /* error */) {
    return interworking_select_enabled_;
  }

  SupplicantProcessProxyInterface* supplicant_process_proxy() const;

  // RPC accessor for |station_stats_|.
  KeyValueStore GetLinkStatistics(Error* error);

  bool GetScanPending(Error* /* error */);
  bool GetWakeOnWiFiSupported(Error* /* error */);
  bool SetBgscanMethod(const std::string& method, Error* error);
  bool SetBgscanShortInterval(const uint16_t& seconds, Error* error);
  bool SetBgscanSignalThreshold(const int32_t& dbm, Error* error);
  bool SetScanInterval(const uint16_t& seconds, Error* error);
  void ClearBgscanMethod(Error* error);

  bool GetRandomMacEnabled(Error* error);
  bool SetRandomMacEnabled(const bool& enabled, Error* error);

  bool SetInterworkingSelectEnabled(const bool& enabled, Error* error);

  void AssocStatusChanged(const int32_t new_assoc_status);
  void AuthStatusChanged(const int32_t new_auth_status);
  void CurrentBSSChanged(const RpcIdentifier& new_bss);
  void DisconnectReasonChanged(const int32_t new_disconnect_reason);
  void CurrentAuthModeChanged(const std::string& auth_mode);
  void SignalChanged(const KeyValueStore& properties);
  // Return the correct Metrics suffix (PSK, FTPSK, EAP, FTEAP) corresponding to
  // the current service's authentication mode.
  std::string GetSuffixFromAuthMode(const std::string& auth_mode) const;
  // Return the RPC identifier associated with the wpa_supplicant network
  // entry created for |service|.  If one does not exist, an empty string
  // is returned, and |error| is populated.
  RpcIdentifier FindNetworkRpcidForService(const WiFiService* service,
                                           Error* error);

  // When wpa_supplicant move to the "connected" or "disconnected" state, make
  // the difference between maintenance events such as rekeying that don't
  // indicate an actual disconnection and other state changes that show
  // actual connections or disconnections.
  bool IsStateTransitionConnectionMaintenance(const WiFiService& service) const;

  // Make the difference between a failure to connect to a service and a
  // disconnection from a service we were connected to. Checking for
  // |pending_service_| is not necessarily sufficient, since it could be the
  // case that we were connected and were disconnected intentionally to attempt
  // to connect to another service, which would be pending.
  bool IsConnectionAttemptFailure(const WiFiService& service) const;

  void HandleDisconnect();
  // Update failure and state for disconnected service.
  // Set failure for disconnected service if disconnect is not user-initiated
  // and failure is not already set. Then set the state of the service back
  // to idle, so it can be used for future connections.
  void ServiceDisconnected(WiFiServiceRefPtr service, bool is_attempt_failure);
  // Check if disconnect_signal is out of range compared to threshold and
  // is not the default.
  bool SignalOutOfRange(const int16_t& disconnect_signal);
  // Log and send to UMA any auth/assoc status code indicating a failure.
  // Returns inferred type of failure, which is useful in cases where we don't
  // have a disconnect reason from supplicant.
  Service::ConnectFailure ExamineStatusCodes() const;
  void HandleRoam(const RpcIdentifier& new_bss, const RpcIdentifier& old_bss);
  void BSSAddedTask(const RpcIdentifier& BSS, const KeyValueStore& properties);
  void BSSRemovedTask(const RpcIdentifier& BSS);
  void CertificationTask(const KeyValueStore& properties);
  void EAPEventTask(const std::string& status, const std::string& parameter);
  void PropertiesChangedTask(const KeyValueStore& properties);
  void ScanDoneTask();
  void ScanFailedTask();
  void PskMismatchTask();
  // UpdateScanStateAfterScanDone is spawned as a task from ScanDoneTask in
  // order to ensure that it is run after the start of any connections that
  // result from a scan.  This works because supplicant sends all BSSAdded
  // signals to shill before it sends a ScanDone signal.  The code that
  // handles those signals launch tasks such that the tasks have the following
  // dependencies (an arrow from X->Y indicates X is ensured to run before
  // Y):
  //
  // [BSSAdded]-->[BssAddedTask]-->[SortServiceTask (calls ConnectTo)]
  //     |              |                 |
  //     V              V                 V
  // [ScanDone]-->[ScanDoneTask]-->[UpdateScanStateAfterScanDone]
  void UpdateScanStateAfterScanDone();
  void ScanTask();
  // When scans are limited to one ssid, alternate between broadcast probes
  // and directed probes. This is necessary because the broadcast probe takes
  // up one SSID slot, leaving no space for the directed probe.
  void AlternateSingleScans(ByteArrays* hidden_ssids);
  void StateChanged(const std::string& new_state);
  // Heuristic check if a connection failure was due to bad credentials.
  // Returns true and puts type of failure in |failure| if a credential
  // problem is detected.
  bool SuspectCredentials(WiFiServiceRefPtr service,
                          Service::ConnectFailure* failure) const;

  void HelpRegisterDerivedInt32(PropertyStore* store,
                                base::StringPiece name,
                                int32_t (WiFi::*get)(Error* error),
                                bool (WiFi::*set)(const int32_t& value,
                                                  Error* error));
  void HelpRegisterDerivedUint16(PropertyStore* store,
                                 base::StringPiece name,
                                 uint16_t (WiFi::*get)(Error* error),
                                 bool (WiFi::*set)(const uint16_t& value,
                                                   Error* error));
  void HelpRegisterDerivedBool(PropertyStore* store,
                               base::StringPiece name,
                               bool (WiFi::*get)(Error* error),
                               bool (WiFi::*set)(const bool& value,
                                                 Error* error));
  void HelpRegisterConstDerivedBool(PropertyStore* store,
                                    base::StringPiece name,
                                    bool (WiFi::*get)(Error* error));
  void HelpRegisterConstDerivedUint16s(PropertyStore* store,
                                       base::StringPiece name,
                                       Uint16s (WiFi::*get)(Error* error));

  // Disable a network entry in wpa_supplicant, and catch any exception
  // that occurs.  Returns false if an exception occurred, true otherwise.
  bool DisableNetwork(const RpcIdentifier& network);
  // Disable the wpa_supplicant network entry associated with |service|.
  // Any cached credentials stored in wpa_supplicant related to this
  // network entry will be preserved.  This will have the side-effect of
  // disconnecting this service if it is currently connected.  Returns
  // true if successful, otherwise returns false and populates |error|
  // with the reason for failure.
  virtual bool DisableNetworkForService(const WiFiService* service,
                                        Error* error);
  // Remove a network entry from wpa_supplicant, and catch any exception
  // that occurs.  Returns false if an exception occurred, true otherwise.
  bool RemoveNetwork(const RpcIdentifier& network);
  // Remove the wpa_supplicant network entry associated with |service|.
  // Any cached credentials stored in wpa_supplicant related to this
  // network entry will be removed.  This will have the side-effect of
  // disconnecting this service if it is currently connected.  Returns
  // true if successful, otherwise returns false and populates |error|
  // with the reason for failure.
  virtual bool RemoveNetworkForService(const WiFiService* service,
                                       Error* error);
  // Perform the next in a series of progressive scans.
  void ProgressiveScanTask();
  // Recovers from failed progressive scan.
  void OnFailedProgressiveScan();
  // Restart fast scanning after disconnection.
  void RestartFastScanAttempts();
  // Schedules a scan attempt at time |scan_interval_seconds_| in the
  // future.  Cancels any currently pending scan timer.
  void StartScanTimer();
  // Cancels any currently pending scan timer.
  void StopScanTimer();
  // Initiates a scan, if idle. Reschedules the scan timer regardless.
  void ScanTimerHandler();
  // Abort any current scan (at the shill-level; let any request that's
  // already gone out finish).
  void AbortScan();
  // Abort any current scan and start a new scan of type |type| if shill is
  // currently idle.
  void InitiateScan();
  // Suppresses manager auto-connects and flushes supplicant BSS cache, then
  // triggers the passive scan. Meant for use in dark resume where we want to
  // ensure that shill and supplicant do not use stale information to launch
  // connection attempts.
  void InitiateScanInDarkResume(const FreqSet& freqs);
  // If |freqs| contains at least one frequency channel a passive scan is
  // launched on all the frequencies in |freqs|. Otherwise, a passive scan is
  // launched on all channels.
  void TriggerPassiveScan(const FreqSet& freqs);
  // Starts a timer in order to limit the length of an attempt to
  // connect to a pending network.
  void StartPendingTimer();
  // Cancels any currently pending network timer.
  void StopPendingTimer();
  // Aborts a pending network that is taking too long to connect.
  void PendingTimeoutHandler();
  // Starts a timer in order to limit the length of an attempt to
  // reconnect to the current network.
  void StartReconnectTimer();
  // Stops any pending reconnect timer.
  void StopReconnectTimer();
  // Disconnects from the current service that is taking too long
  // to reconnect on its own.
  void ReconnectTimeoutHandler();
  // Sets the current pending service.  If the argument is non-NULL,
  // the Pending timer is started and the associated service is set
  // to "Associating", otherwise it is stopped.
  void SetPendingService(const WiFiServiceRefPtr& service);

  void OnSupplicantPresence(bool present);
  // Called by ScopeLogger when WiFi debug scope is enabled/disabled.
  void OnWiFiDebugScopeChanged(bool enabled);
  // Enable or disable debugging for the current connection attempt.
  void SetConnectionDebugging(bool enabled);

  // Send a structured event with the link statistics that had been requested.
  void EmitStationInfoReceivedEvent(
      const WiFiLinkStatistics::StationStats& stats);

  // Query the state of the BT stack and populate the relevant fields of the
  // WiFiLinkQualityReport.
  void AddBTStateToLinkQualityReport(
      Metrics::WiFiLinkQualityReport& report) const;

  // Request and retrieve information about the currently connected station.
  void RequestStationInfo(WiFiLinkStatistics::Trigger trigger);
  void OnReceivedStationInfo(const Nl80211Message& nl80211_message);
  static bool ParseStationBitrate(const AttributeListConstRefPtr& rate_info,
                                  WiFiLinkStatistics::RxTxStats* stats);
  void HandleUpdatedLinkStatistics();
  void StopRequestingStationInfo();
  void ResetStationInfoRequests();

  void ConnectToSupplicant();

  std::string GetServiceLeaseName(const WiFiService& service);

  // Netlink message handler for NL80211_CMD_NEW_WIPHY messages; copies
  // device's supported frequencies from that message into
  // |all_scan_frequencies_|.
  void OnNewWiphy(const Nl80211Message& nl80211_message);

  // Utility function used to detect the end of PHY info dump.
  void OnGetPhyInfoAuxMessage(NetlinkManager::AuxiliaryMessageType type,
                              const NetlinkMessage* raw_message);

  // Requests regulatory information via NL80211_CMD_GET_REG.
  void GetRegulatory();

  void OnTriggerPassiveScanResponse(const Nl80211Message& netlink_message);

  void SetPhyState(WiFiState::PhyState new_state,
                   WiFiState::ScanMethod new_method,
                   const char* reason);

  // Handles the phy state transitions required to make a ensured scan.
  // Note: This is an internal method designed only to be called when the phy
  // is idle.  Calling this from contexts in which the phy is not idle will
  // have unexpected behavior (the scan may not actually occur).
  void HandleEnsuredScan(WiFiState::PhyState old_state);
  void ReportScanResultToUma(WiFiState::PhyState state,
                             WiFiState::ScanMethod method);

  // Call WakeOnWiFi::PrepareForWakeOnWiFiBeforeSuspend.
  void OnIPv4ConfiguredWithDHCPLease(int interface_index) override;
  void OnIPv6ConfiguredWithSLAACAddress(int interface_index) override;

  // These Device functions are overridden for retrieving link statistics.
  void OnGetDHCPLease(int interface_index) override;
  void OnGetDHCPFailure(int interface_index) override;
  void OnGetSLAACAddress(int interface_index) override;
  void OnNetworkValidationStart(int interface_index) override;
  void OnNetworkValidationSuccess() override;
  void OnNetworkValidationFailure() override;

  void RetrieveLinkStatistics(WiFiLinkStatistics::Trigger event);

  // Returns true iff the WiFi device is connected to the current service.
  bool IsConnectedToCurrentService();

  // Callback invoked to report whether this WiFi device is connected to
  // a service after waking from suspend. Wraps around a Call the function
  // with the same name in WakeOnWiFi.
  void ReportConnectedToServiceAfterWake();

  // Add a scan result to the list of pending scan results, and post a task
  // for handling these results if one is not already running.
  void AddPendingScanResult(const RpcIdentifier& path,
                            const KeyValueStore& properties,
                            bool is_removal);

  // Callback invoked to handle pending scan results from AddPendingScanResult.
  void PendingScanResultsHandler();

  // Given a NL80211_CMD_NEW_WIPHY message |nl80211_message|, parses the
  // feature flags and sets members of this WiFi class appropriately.
  void ParseFeatureFlags(const Nl80211Message& nl80211_message);

  // Given a NL80211_CMD_NEW_WIPHY message |nl80211_message|, parses the
  // cipher suites and sets members of this WiFi class appropriately.
  void ParseCipherSuites(const Nl80211Message& nl80211_message);

  // Callback invoked when broadcasted netlink messages are received.
  // Forwards (Wiphy)RegChangeMessages and TriggerScanMessages to their
  // appropriate handler functions.
  void HandleNetlinkBroadcast(const NetlinkMessage& netlink_message);

  // Called when the kernel broadcasts a notification that a scan has
  // started.
  void OnScanStarted(const Nl80211Message& scan_trigger_msg);

  // Handles NL80211_CMD_GET_REG.
  void OnGetReg(const Nl80211Message& nl80211_message);

  // Handles regulatory domain changes (NL80211_CMD_WIPHY_REG_CHANGE and
  // NL80211_CMD_REG_CHANGE).
  void OnRegChange(const Nl80211Message& nl80211_message);

  // Handles country change metric.
  void HandleCountryChange(const std::string& country_code);

  // Helper function for setting supplicant_interface_proxy_ pointer.
  void SetSupplicantInterfaceProxy(
      std::unique_ptr<SupplicantInterfaceProxyInterface> proxy);

  // Helper function that obtains interface capabilities and uses them to
  // reconfigure WiFi behavior
  void GetAndUseInterfaceCapabilities();

  // Helper function that configures max # of hidden SSIDs to scan for according
  // to the contents of interface capabilities
  void ConfigureScanSSIDLimit(const KeyValueStore& caps);

  // Bringing the interface down before disabling the device means that
  // wpa_supplicant can receive a deauth event from the kernel before
  // shill asks for a disconnection. wpa_supplicant reads this as an
  // unexpected disconnect event and incorrectly blocklists the AP. The
  // blocklist ends up getting cleared immediately afterward when we
  // deinitialize the interface so there's no functional reason for
  // this, but it makes the logs easier to read.
  bool ShouldBringNetworkInterfaceDownAfterDisabled() const override {
    return true;
  }

  // Called when link becomes unreliable (multiple link monitor failures
  // detected in short period of time).
  void OnUnreliableLink();
  // Called when link becomes reliable (no link failures in a predefined period
  // of time).
  void OnReliableLink();
  // Respond to a LinkMonitor failure. Called in OnNeighborReachabilityEvent().
  void OnLinkMonitorFailure(IPAddress::Family family);

  // Get total received byte counters for the underlying network interface.
  uint64_t GetReceiveByteCount();

  bool SupportsWEP() const;

  // Get the WiFiPhy object from provider which corresponds to phy_index_.
  const WiFiPhy* GetWiFiPhy() const;

  // Pointer to the provider object that maintains WiFiService objects.
  WiFiProvider* provider_;

  // Store cached copies of singletons for speed/ease of testing.
  Time* time_;

  // Number of times we have attempted to set up device via wpa_supplicant
  // {Create,Get}Interface() since the last Start(). Errors may be transient or
  // they may be permanent, so we only retry a limited number of times.
  int supplicant_connect_attempts_;

  bool supplicant_present_;

  std::unique_ptr<SupplicantInterfaceProxyInterface>
      supplicant_interface_proxy_;
  // wpa_supplicant's RPC path for this device/interface.
  RpcIdentifier supplicant_interface_path_;
  // The rpcid used as the key is wpa_supplicant's D-Bus path for the
  // Endpoint (BSS, in supplicant parlance).
  EndpointMap endpoint_by_rpcid_;
  // Map from Services to the D-Bus path for the corresponding wpa_supplicant
  // Network.
  ReverseServiceMap rpcid_by_service_;
  // The Service we are presently connected to. May be nullptr is we're not
  // not connected to any Service.
  WiFiServiceRefPtr current_service_;
  // The Service we're attempting to connect to. May be nullptr if we're
  // not attempting to connect to a new Service. If non-NULL, should
  // be distinct from |current_service_|. (A service should not
  // simultaneously be both pending, and current.)
  WiFiServiceRefPtr pending_service_;
  std::string supplicant_state_;
  RpcIdentifier supplicant_bss_;
  int32_t supplicant_assoc_status_;
  int32_t supplicant_auth_status_;
  // Sanitized disconnect reason received from supplicant. If there is currently
  // no disconnect reason set, this will be of value
  // IEEE_80211::kDisconnectReasonInvalid.
  IEEE_80211::WiFiReasonCode supplicant_disconnect_reason_;
  int16_t disconnect_signal_dbm_;
  int16_t disconnect_threshold_dbm_;

  // The maximum number of SSIDs that may be included in scan requests.
  int max_ssids_per_scan_;

  // The auth mode of the last successful connection.
  std::string supplicant_auth_mode_;
  // Indicates that we should flush supplicant's BSS cache after the
  // next scan completes.
  bool need_bss_flush_;
  struct timeval resumed_at_;
  // Executes when the (foreground) scan timer expires. Calls ScanTimerHandler.
  base::CancelableOnceClosure scan_timer_callback_;
  // Executes when a pending service connect timer expires. Calls
  // PendingTimeoutHandler.
  base::CancelableOnceClosure pending_timeout_callback_;
  // Executes when a reconnecting service timer expires. Calls
  // ReconnectTimeoutHandler.
  base::CancelableOnceClosure reconnect_timeout_callback_;
  // Executes periodically while a service is connected, to update the
  // signal strength from the currently connected AP.
  base::CancelableOnceClosure request_station_info_callback_;
  // Keep track of how many times we've requested the STA info from the driver.
  // We used the number to report the STA info to the structured metrics every
  // X times.
  int station_info_reqs_;
  // Executes when WPA supplicant reports that a scan has failed via a ScanDone
  // signal.
  base::CancelableOnceClosure scan_failed_callback_;
  // Number of remaining fast scans to be done during startup and disconnect.
  int fast_scans_remaining_;
  // Indicates that the current BSS has reached the completed state according
  // to supplicant.
  bool has_already_completed_;
  // Indicates that the current BSS for a connected service has changed, which
  // implies that a driver-based roam has been initiated.  If this roam
  // succeeds, we should renew our lease.
  bool is_roaming_in_progress_;
  // In WiFi::EAPEventTask, we infer the specific EAP authentication failure (if
  // there is one), and store it in |pending_eap_failure_| to be used later when
  // we actually disconnect from the network.
  Service::ConnectFailure pending_eap_failure_;
  // Indicates that we are debugging a problematic connection.
  bool is_debugging_connection_;
  // Tracks the process of an EAP negotiation.
  std::unique_ptr<SupplicantEAPStateHandler> eap_state_handler_;

  // Time when link monitor last failed.
  time_t last_link_monitor_failed_time_;
  // Callback to invoke when link becomes reliable again after it was previously
  // unreliable.
  base::CancelableOnceClosure reliable_link_callback_;

  // Properties
  std::string bgscan_method_;
  uint16_t bgscan_short_interval_seconds_;
  int32_t bgscan_signal_threshold_dbm_;
  uint16_t scan_interval_seconds_;

  NetlinkManager* netlink_manager_;

  bool random_mac_supported_;
  bool random_mac_enabled_;
  bool sched_scan_supported_;

  // Holds the list of scan results waiting to be processed and a cancelable
  // closure for processing the pending tasks in PendingScanResultsHandler().
  std::unique_ptr<PendingScanResults> pending_scan_results_;

  std::unique_ptr<WiFiState> wifi_state_;

  // Indicates if the last scan skipped the broadcast probe.
  bool broadcast_probe_was_skipped_;

  // Indicates if Passpoint interworking selection is enabled, i.e. if the
  // device is allowed to start interworking selection when the conditions are
  // met.
  bool interworking_select_enabled_;

  // Count of Hotspot 2.0/Passpoint compatible endpoints currently known.
  uint32_t hs20_bss_count_;

  // Indicates that we should start an interworking selection after the next
  // scan, either because a new  set of credentials was added or a Passpoint
  // compatible endpoint appeared.
  bool need_interworking_select_;

  // Timestamp of the start of last interworkign select call to the supplicant.
  std::optional<base::Time> last_interworking_select_timestamp_;

  // Holds the list of interworking matches waiting to be processed.
  std::vector<InterworkingBSS> pending_matches_;

  // Used to compute the number of bytes received since the link went up.
  uint64_t receive_byte_count_at_connect_;

  // Used to report the current state of our wireless link.
  WiFiLinkStatistics::StationStats station_stats_;

  // Used for the diagnosis on link failures defined in WiFiLinkStatistics.
  std::unique_ptr<WiFiLinkStatistics> wifi_link_statistics_;
  // Keep the current network event for RTNL link statistics.
  WiFiLinkStatistics::Trigger current_rtnl_network_event_ =
      WiFiLinkStatistics::Trigger::kUnknown;

  // List of the events that have requested STA info but whose request hasn't
  // been serviced yet.
  std::list<WiFiLinkStatistics::Trigger> pending_nl80211_stats_requests_;

  // Phy interface index of this WiFi device.
  uint32_t phy_index_;

  // Used to access connection quality monitor features.
  std::unique_ptr<WiFiCQM> wifi_cqm_;

  std::unique_ptr<WakeOnWiFiInterface> wake_on_wifi_;

  // Netlink broadcast handler, for scan results.
  NetlinkManager::NetlinkMessageHandler netlink_handler_;

  // Managed supplicant listener, for watching service (re)start.
  std::unique_ptr<SupplicantManager::ScopedSupplicantListener>
      scoped_supplicant_listener_;

  // For weak pointers that will be invalidated in Stop().
  base::WeakPtrFactory<WiFi> weak_ptr_factory_while_started_;

  // For weak pointers that will only be invalidated at destruction. Useful for
  // callbacks that need to survive Restart().
  base::WeakPtrFactory<WiFi> weak_ptr_factory_;

  std::set<uint32_t> supported_cipher_suites_;
};

}  // namespace shill

#endif  // SHILL_WIFI_WIFI_H_
