// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_CELLULAR_CAPABILITY_3GPP_H_
#define SHILL_CELLULAR_CELLULAR_CAPABILITY_3GPP_H_

#include <deque>
#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <ModemManager/ModemManager.h>
#include <base/containers/flat_map.h>
#include <base/containers/flat_set.h>
#include <base/memory/weak_ptr.h>
#include <base/time/time.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/callbacks.h"
#include "shill/cellular/cellular.h"
#include "shill/cellular/cellular_bearer.h"
#include "shill/cellular/dbus_objectmanager_proxy_interface.h"
#include "shill/cellular/mm1_modem_location_proxy_interface.h"
#include "shill/cellular/mm1_modem_modem3gpp_profile_manager_proxy_interface.h"
#include "shill/cellular/mm1_modem_modem3gpp_proxy_interface.h"
#include "shill/cellular/mm1_modem_proxy_interface.h"
#include "shill/cellular/mm1_modem_signal_proxy_interface.h"
#include "shill/cellular/mm1_modem_simple_proxy_interface.h"
#include "shill/cellular/mm1_sim_proxy_interface.h"
#include "shill/cellular/subscription_state.h"
#include "shill/data_types.h"
#include "shill/store/key_value_store.h"

namespace shill {

class CellularBearer;
class Error;
class Metrics;
class PendingActivationStore;

// CellularCapability3gpp handles modems using the
// org.freedesktop.ModemManager1 DBUS interface.  This class is used for
// all types of modems, i.e. GSM and LTE modems.
class CellularCapability3gpp {
 public:
  static const base::TimeDelta kTimeoutConnect;
  static const base::TimeDelta kTimeoutDefault;
  static const base::TimeDelta kTimeoutDisconnect;
  static const base::TimeDelta kTimeoutEnable;
  static const base::TimeDelta kTimeoutGetLocation;
  static const base::TimeDelta kTimeoutRegister;
  static const base::TimeDelta kTimeoutReset;
  static const base::TimeDelta kTimeoutScan;
  static const base::TimeDelta kTimeoutSetInitialEpsBearer;
  static const base::TimeDelta kTimeoutSetupLocation;
  static const base::TimeDelta kTimeoutSetupSignal;
  static const base::TimeDelta kTimeoutSetupSignalThresholds;
  static const base::TimeDelta kTimeoutEnterPin;
  static const base::TimeDelta kTimeoutRegistrationDroppedUpdate;
  static const base::TimeDelta kTimeoutSetPowerState;
  static const base::TimeDelta kTimeoutSetNextAttachApn;

  using ScanResults = std::vector<KeyValueStore>;
  using ScanResult = KeyValueStore;
  using LockRetryData = std::map<uint32_t, uint32_t>;
  using SignalQuality = std::tuple<uint32_t, bool>;
  using ModesData = std::tuple<uint32_t, uint32_t>;
  using SupportedModes = std::vector<ModesData>;
  using PcoList = std::vector<std::tuple<uint32_t, bool, std::vector<uint8_t>>>;
  using Profiles = std::vector<brillo::VariantDictionary>;

  using SimProperties = Cellular::SimProperties;

  CellularCapability3gpp(Cellular* cellular,
                         ControlInterface* control_interface,
                         Metrics* metrics,
                         PendingActivationStore* pending_activation_store);
  CellularCapability3gpp(const CellularCapability3gpp&) = delete;
  CellularCapability3gpp& operator=(const CellularCapability3gpp&) = delete;

  ~CellularCapability3gpp();

  Cellular* cellular() const { return cellular_; }
  ControlInterface* control_interface() const { return control_interface_; }
  Metrics* metrics() const { return metrics_; }
  PendingActivationStore* pending_activation_store() const {
    return pending_activation_store_;
  }

  std::string GetTypeString() const;
  void SetInitialProperties(const InterfaceToProperties& properties);

  // -------------------------------------------------------------------------
  // Modem management
  // -------------------------------------------------------------------------

  // StartModem attempts to put the modem in a state in which it is usable for
  // creating services and establishing connections (if network conditions
  // permit). It potentially consists of multiple non-blocking calls to the
  // modem-manager server. After each call, control is passed back up to the
  // main loop. Each time a reply to a non-blocking call is received, the
  // operation advances to the next step, until either an error occurs in one of
  // them, or all the steps have been completed, at which point StartModem() is
  // finished.
  void StartModem(ResultCallback callback);

  // Sets a flag to be used by |StopModem| to decide if the modem will be set
  // to low power mode as the last step. By default, |StopModem| does set the
  // modem to low power mode.
  void SetModemToLowPowerModeOnModemStop(bool set_low_power);

  // StopModem asynchronously disconnects, disables and sets the modem to low
  // power mode. If |SetModemToLowPowerModeOnModemStop| was called with a
  // `false` value, |StopModem| will not set the modem to low power mode.
  // |callback| is invoked when this completes and the result is passed to the
  // callback.
  void StopModem(ResultCallback callback);

  // Resets the modem.
  void Reset(ResultCallback callback);

  // -------------------------------------------------------------------------
  // Activation
  // -------------------------------------------------------------------------

  // Returns true if service activation is required.
  bool IsServiceActivationRequired() const;

  // Returns true if the modem is being activated.
  bool IsActivating() const;

  // Initiates the necessary to steps to verify that the cellular service has
  // been activated. Once these steps have been completed, the service should
  // be marked as activated.
  void CompleteActivation(Error* error);

  // -------------------------------------------------------------------------
  // Network service and registration
  // -------------------------------------------------------------------------

  // Asks the modem to scan for networks asynchronously.
  //
  // When the results are ready, update the kFoundNetworksProperty and send a
  // property change notification.  Finally, callback must be invoked to inform
  // the caller that the scan has completed.
  //
  // Errors are not generally reported, but on error the kFoundNetworksProperty
  // should be cleared and a property change notification sent out.
  //
  // TODO(jglasgow): Implement real error handling.
  void Scan(base::OnceClosure started_callback,
            ResultStringmapsCallback finished_callback);

  // Builds the Attach APN try list and configures the APN on the modem.
  void ConfigureAttachApn();

  // Sets the parameters specified by |properties| for the LTE initial EPS
  // bearer used at registration, particularly the 'Attach' APN settings.
  // specified by |properties|.
  void SetInitialEpsBearer(const KeyValueStore& properties,
                           ResultCallback callback);

  // Registers on a network with |network_id|.
  void RegisterOnNetwork(const std::string& network_id,
                         ResultCallback callback);

  // Returns true if the modem is registered on a network, which can be a home
  // or roaming network. It is possible that we cannot determine whether it is
  // a home or roaming network, but we still consider the modem is registered.
  bool IsRegistered() const;

  // If we are informed by means of something other than a signal indicating
  // a registration state change that the modem has unregistered from the
  // network, we need to update the network-type-specific capability object.
  void SetUnregistered(bool searching);

  // Invoked by the parent Cellular device when a new service is created.
  void OnServiceCreated();

  // Returns all active access technologies
  uint32_t GetActiveAccessTechnologies() const;

  // Returns an empty string if the network technology is unknown.
  std::string GetNetworkTechnologyString() const;

  std::string GetRoamingStateString() const;

  // -------------------------------------------------------------------------
  // Connection management
  // -------------------------------------------------------------------------

  // Connects the modem to a network, specifying the relevant APN type
  // associated to this connection, as well as the APN list to try. Only one
  // connection of a given APN type is expected for now.
  void Connect(ApnList::ApnType apn_type,
               const std::deque<Stringmap>& apn_try_list,
               ResultCallback callback);

  // Disconnects the modem from all networks.
  void DisconnectAll(ResultCallback callback);
  // Disconnects the modem from the network specified by the APN type.
  void Disconnect(ApnList::ApnType apn_type, ResultCallback callback);

  // Returns a pointer to the current active bearer object or nullptr if no
  // active bearer exists. The returned bearer object is managed by this
  // capability object.
  CellularBearer* GetActiveBearer(ApnList::ApnType apn_type) const;

  const std::vector<MobileOperatorMapper::MobileAPN>& GetProfiles() const;

  // ------------------------------------------------------------------------
  // Modem Type
  // ------------------------------------------------------------------------
  bool IsModemFM101();
  bool IsModemFM350();
  bool IsModemL850();
  // -------------------------------------------------------------------------
  // SIM lock management
  // -------------------------------------------------------------------------

  void RequirePin(const std::string& pin,
                  bool require,
                  ResultCallback callback);

  void EnterPin(const std::string& pin, ResultCallback callback);

  void UnblockPin(const std::string& unblock_code,
                  const std::string& pin,
                  ResultCallback callback);

  void ChangePin(const std::string& old_pin,
                 const std::string& new_pin,
                 ResultCallback callback);

  // Returns a KeyValueStore with kSIMLock* properties set if available, or
  // an empty KeyValueStore if not.
  KeyValueStore SimLockStatusToProperty(Error* error);

  // Sends a request to the modem to set the primary SIM slot to the slot
  // matching |iccid|. If |iccid| is empty, switches to the first valid slot.
  bool SetPrimarySimSlotForIccid(const std::string& iccid);

  // -------------------------------------------------------------------------
  // Location reporting
  // -------------------------------------------------------------------------

  void SetupLocation(uint32_t sources,
                     bool signal_location,
                     ResultCallback callback);

  void GetLocation(StringCallback callback);

  bool IsLocationUpdateSupported() const;

  // -------------------------------------------------------------------------
  // Signal reporting
  // -------------------------------------------------------------------------

  void SetupSignal(uint32_t rate, ResultCallback callback);

  void SetupSignalThresholds(const KeyValueStore& settings,
                             ResultCallback callback);

  // Used to encapsulate bounds for rssi/rsrp
  struct SignalQualityBounds {
    const double min_threshold;
    const double max_threshold;

    // Convert signal_quality to a percentage between 0 and 100
    // If signal_quality < min_threshold, clamp to 0 %
    // If signal_quality > max_threshold, clamp to 100 %
    double GetAsPercentage(double signal_quality) const;
  };

  // -------------------------------------------------------------------------
  // Online payment portal information
  // -------------------------------------------------------------------------

  // Updates the online payment portal information, if any, for the cellular
  // provider.
  void UpdateServiceOLP();

  // -------------------------------------------------------------------------

  void GetProperties();

  // Property change handler.
  void OnPropertiesChanged(const std::string& interface,
                           const KeyValueStore& changed_properties);

  void SetDBusPropertiesProxyForTesting(
      std::unique_ptr<DBusPropertiesProxy> dbus_properties_proxy);

  uint32_t access_technologies_for_testing() const {
    return access_technologies_;
  }
  const RpcIdentifier& sim_path_for_testing() const { return sim_path_; }
  const base::flat_map<RpcIdentifier, SimProperties>&
  sim_properties_for_testing() const {
    return sim_properties_;
  }
  void set_sim_properties_for_testing(
      const base::flat_map<RpcIdentifier, SimProperties>& sim_properties) {
    sim_properties_ = sim_properties;
  }

  // Constants used in scan results.  Make available to unit tests.
  static const char kStatusProperty[];
  static const char kOperatorLongProperty[];
  static const char kOperatorShortProperty[];
  static const char kOperatorCodeProperty[];
  static const char kOperatorAccessTechnologyProperty[];

  static const SignalQualityBounds kRssiBounds;
  static const SignalQualityBounds kRsrpBounds;
  static const SignalQualityBounds kRscpBounds;

  static const char kRsrpProperty[];
  static const char kRssiProperty[];
  static const char kRscpProperty[];

  // Keys for bearer stats properties. The unit of link speeds in the key value
  // store come from modem manager is bps.
  static const char kUplinkSpeedBpsProperty[];
  static const char kDownlinkSpeedBpsProperty[];

  static const char kRssiThresholdProperty[];
  static const char kErrorThresholdProperty[];
  static const uint32_t kRssiThreshold;
  static const bool kErrorThreshold;

  static const int kUnknownLockRetriesLeft;

  // Root path. The SIM path is reported by ModemManager to be the root path
  // when no SIM is present.
  static const RpcIdentifier kRootPath;

 private:
  friend class CellularTest;
  friend class CellularCapability3gppTest;
  friend class CellularServiceProviderTest;
  // CellularCapability3gppTimerTest
  FRIEND_TEST(CellularCapability3gppTest, GetMdnForOLP);
  FRIEND_TEST(CellularCapability3gppTest, GetTypeString);
  FRIEND_TEST(CellularCapability3gppTest, IsMdnValid);
  FRIEND_TEST(CellularCapability3gppTest, IsRegistered);
  FRIEND_TEST(CellularCapability3gppTest, IsServiceActivationRequired);
  FRIEND_TEST(CellularCapability3gppTest, IsValidSimPath);
  FRIEND_TEST(CellularCapability3gppTest, NormalizeMdn);
  FRIEND_TEST(CellularCapability3gppTest, OnLockRetriesChanged);
  FRIEND_TEST(CellularCapability3gppTest, OnLockTypeChanged);
  FRIEND_TEST(CellularCapability3gppTest, OnModemCurrentCapabilitiesChanged);
  FRIEND_TEST(CellularCapability3gppTest, OnSimLockPropertiesChanged);
  FRIEND_TEST(CellularCapability3gppTest, PropertiesChanged);
  FRIEND_TEST(CellularCapability3gppTest, SignalPropertiesChanged);
  FRIEND_TEST(CellularCapability3gppTest, Reset);
  FRIEND_TEST(CellularCapability3gppTest, SetInitialEpsBearer);
  FRIEND_TEST(CellularCapability3gppTest, DisconnectSingleBearer);
  FRIEND_TEST(CellularCapability3gppTest, SimLockStatusChanged);
  FRIEND_TEST(CellularCapability3gppTest, SimLockStatusToProperty);
  FRIEND_TEST(CellularCapability3gppTest, SimPathChanged);
  FRIEND_TEST(CellularCapability3gppTest, SimPropertiesChanged);
  FRIEND_TEST(CellularCapability3gppTest, StartModemInWrongState);
  FRIEND_TEST(CellularCapability3gppTest, StartModemWithDeferredEnableFailure);
  FRIEND_TEST(CellularCapability3gppTest, UpdateActiveBearers);
  FRIEND_TEST(CellularCapability3gppTest, UpdateLinkSpeed);
  FRIEND_TEST(CellularCapability3gppTest, UpdatePendingActivationState);
  FRIEND_TEST(CellularCapability3gppTest, UpdateRegistrationState);
  FRIEND_TEST(CellularCapability3gppTest,
              UpdateRegistrationStateModemNotConnected);
  FRIEND_TEST(CellularCapability3gppTest, UpdateServiceActivationState);
  FRIEND_TEST(CellularCapability3gppTest, UpdateServiceOLP);
  FRIEND_TEST(CellularCapability3gppTimerTest, CompleteActivation);
  // CellularTest
  FRIEND_TEST(CellularTest, ModemStateChangeLostRegistration);

  // Single connection attempt context
  struct ConnectionAttemptInfo {
    std::deque<Stringmap> apn_try_list;
    bool simple_connect;
    ResultCallback result_callback;
  };

  // SimLockStatus represents the fields in the Cellular.SIMLockStatus
  // DBUS property of the shill device.
  struct SimLockStatus {
    SimLockStatus()
        : enabled(false), lock_type(MM_MODEM_LOCK_UNKNOWN), retries_left(0) {}

    bool enabled;
    MMModemLock lock_type;
    int32_t retries_left;
  };

  // Methods used in starting a modem
  void EnableModemCompleted(ResultCallback callback, const Error& error);

  // Methods used in stopping a modem
  void Stop_Completed(ResultCallback callback, const Error& error);
  void Stop_Disable(ResultCallback callback);
  void Stop_DisableCompleted(ResultCallback callback, const Error& error);
  void Stop_PowerDown(ResultCallback callback, const Error& stop_disable_error);
  void Stop_PowerDownCompleted(ResultCallback callback,
                               const Error& stop_disable_error,
                               const Error& error);

  void Register(ResultCallback callback);

  // Updates |active_bearers_| to match the currently active bearers.
  void UpdateActiveBearers();

  Stringmap ParseScanResult(const ScanResult& result);

  void SetApnProperties(const Stringmap& apn_info, KeyValueStore* properties);

  // Disable dual-stack on FM350
  // TODO(b/228528516) Remove this hack once the fix for
  // b/228042798 lands.
  bool IsDualStackSupported();
  void SetNextAttachApn();
  void ScheduleNextAttach(const Error& error);
  void FillInitialEpsBearerPropertyMap(KeyValueStore* properties);
  void UpdateLastConnectedAttachApnOnRegistered();

  // Returns true if a connect error should be retried.  This function
  // abstracts modem specific behavior for modems which do a lousy job
  // of returning specific errors on connect failures.
  bool RetriableConnectError(const Error& error) const;

  // Signal callbacks
  void OnModemStateChangedSignal(int32_t old_state,
                                 int32_t new_state,
                                 uint32_t reason);

  // Profile manager signal handlers and callbacks
  void OnProfilesListReply(ResultCallback callback,
                           const Profiles& results,
                           const Error& error);
  void OnModem3gppProfileManagerUpdatedSignal();

  // Property Change notification handlers
  void OnModemPropertiesChanged(const KeyValueStore& properties);

  void OnModemCurrentCapabilitiesChanged(uint32_t current_capabilities);
  void OnMdnChanged(const std::string& mdn);
  void OnModemStateChanged(Cellular::ModemState state);
  void OnAccessTechnologiesChanged(uint32_t access_technologies);
  void OnBearersChanged(const RpcIdentifiers& bearers);
  void OnLockRetriesChanged(const LockRetryData& lock_retries);
  void OnLockTypeChanged(MMModemLock unlock_required);
  void OnSimLockStatusChanged();

  // Returns false if the MDN is empty or if the MDN consists of all 0s.
  bool IsMdnValid() const;

  // 3GPP property change handlers
  void OnModem3gppPropertiesChanged(const KeyValueStore& properties);
  void OnProfilesChanged(const Profiles& profiles);
  void On3gppRegistrationChanged(MMModem3gppRegistrationState state,
                                 const std::string& operator_code,
                                 const std::string& operator_name);
  void Handle3gppRegistrationChange(MMModem3gppRegistrationState updated_state,
                                    const std::string& updated_operator_code,
                                    const std::string& updated_operator_name);
  void OnSubscriptionStateChanged(SubscriptionState updated_subscription_state);
  void OnFacilityLocksChanged(uint32_t locks);
  void OnPcoChanged(const PcoList& pco_list);
  void OnModemSignalPropertiesChanged(const KeyValueStore& props);

  // SIM property change handlers
  void RequestSimProperties(size_t slot, RpcIdentifier sim_path);
  void OnGetSimProperties(
      size_t slot,
      RpcIdentifier sim_path,
      std::unique_ptr<DBusPropertiesProxy> sim_properties_proxy,
      const KeyValueStore& properties);

  // Bearer property change handlers
  void OnBearerPropertiesChanged(const KeyValueStore& properties);

  // Generic connection attempt logic
  void ConnectionAttemptComplete(ApnList::ApnType apn_type, const Error& error);
  bool ConnectionAttemptInitialize(ApnList::ApnType apn_type,
                                   const std::deque<Stringmap>& apn_try_list,
                                   ResultCallback result_callback);
  KeyValueStore ConnectionAttemptNextProperties(ApnList::ApnType apn_type);
  void ConnectionAttemptConnect(ApnList::ApnType apn_type);
  void ConnectionAttemptOnConnectReply(ApnList::ApnType apn_type,
                                       const RpcIdentifier& bearer,
                                       const Error& error);
  bool ConnectionAttemptContinue(ApnList::ApnType apn_type);
  void ConnectionAttemptAbortAll();

  // Method callbacks
  void OnRegisterReply(ResultCallback callback, const Error& error);
  void OnResetReply(ResultCallback callback, const Error& error);
  void OnScanReply(ResultStringmapsCallback callback,
                   const ScanResults& results,
                   const Error& error);
  void OnSetupLocationReply(const Error& error);
  void OnGetLocationReply(StringCallback callback,
                          const std::map<uint32_t, brillo::Any>& results,
                          const Error& error);
  void OnSetupSignalReply(const Error& error);
  void OnSetupSignalThresholdsReply(const Error& error);
  void OnSetInitialEpsBearerReply(ResultCallback callback, const Error& error);

  // Returns the normalized version of |mdn| by keeping only digits in |mdn|
  // and removing other non-digit characters.
  std::string NormalizeMdn(const std::string& mdn) const;

  void InitProxies();
  void ReleaseProxies();

  // Post-payment activation handlers.
  void UpdatePendingActivationState();

  // Returns the operator-specific form of |mdn|, which is passed to the online
  // payment portal of a cellular operator.
  std::string GetMdnForOLP(const MobileOperatorInfo* operator_info) const;

  // Returns true, if |sim_path| constitutes a valid SIM path. Currently, a
  // path is accepted to be valid, as long as it is not equal to one of ""
  // and "/".
  bool IsValidSimPath(const RpcIdentifier& sim_path) const;

  void UpdateSims();
  void OnAllSimPropertiesReceived();
  void SetPrimarySimSlot(size_t slot);

  // Post-payment activation handlers.
  void ResetAfterActivation();
  void UpdateServiceActivationState();
  void OnResetAfterActivationReply(const Error& error);

  // Update uplink and downlink speed in service.
  void UpdateLinkSpeed(const KeyValueStore& properties);

  Cellular* cellular_;
  ControlInterface* control_interface_;
  Metrics* metrics_;
  PendingActivationStore* pending_activation_store_;

  bool proxies_initialized_ = false;
  std::unique_ptr<mm1::ModemModem3gppProxyInterface> modem_3gpp_proxy_;
  std::unique_ptr<mm1::ModemModem3gppProfileManagerProxyInterface>
      modem_3gpp_profile_manager_proxy_;
  std::unique_ptr<mm1::ModemProxyInterface> modem_proxy_;
  std::unique_ptr<mm1::ModemSimpleProxyInterface> modem_simple_proxy_;
  std::unique_ptr<mm1::ModemSignalProxyInterface> modem_signal_proxy_;
  std::unique_ptr<mm1::SimProxyInterface> sim_proxy_;
  std::unique_ptr<mm1::ModemLocationProxyInterface> modem_location_proxy_;
  std::unique_ptr<DBusPropertiesProxy> dbus_properties_proxy_;
  std::unique_ptr<DBusPropertiesProxy> default_bearer_dbus_properties_proxy_;

  // Used to enrich information about the network operator in |ParseScanResult|.
  // TODO(pprabhu) Instead instantiate a local |MobileOperatorInfo| instance
  // once the context has been separated out. (crbug.com/363874)
  std::unique_ptr<MobileOperatorInfo> parsed_scan_result_operator_info_;

  MMModem3gppRegistrationState registration_state_ =
      MM_MODEM_3GPP_REGISTRATION_STATE_UNKNOWN;

  // Bits based on MMModemCapabilities
  // Technologies supported without a reload
  uint32_t current_capabilities_ = MM_MODEM_CAPABILITY_NONE;
  // Bits based on MMModemAccessTechnology
  uint32_t access_technologies_ = MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN;

  Stringmap serving_operator_;
  std::string desired_network_;

  // Ongoing connection attempts sorted by APN type
  std::map<ApnList::ApnType, ConnectionAttemptInfo> connection_attempts_;

  // Properties.
  std::deque<Stringmap> attach_apn_try_list_;
  // For attach APN, we don't really know if the APN is good or not, we only
  // know if ModemManager used the provided attach APN or not.
  Stringmap last_attach_apn_;
  bool resetting_ = false;
  SimLockStatus sim_lock_status_;
  SubscriptionState subscription_state_ = SubscriptionState::kUnknown;
  std::map<ApnList::ApnType, std::unique_ptr<CellularBearer>> active_bearers_;
  RpcIdentifiers bearer_paths_;
  bool reset_done_ = false;
  std::vector<MobileOperatorMapper::MobileAPN> profiles_;
  bool set_modem_to_low_power_mode_on_stop_ = true;

  // SIM properties
  RpcIdentifier sim_path_;
  uint32_t primary_sim_slot_ = 0u;
  RpcIdentifiers sim_slots_;
  base::flat_set<RpcIdentifier> pending_sim_requests_;
  base::flat_map<RpcIdentifier, SimProperties> sim_properties_;

  // Sometimes flaky cellular network causes the 3GPP registration state to
  // rapidly change from registered --> searching and back. Delay such updates
  // a little to smooth over temporary registration loss.
  base::CancelableOnceClosure registration_dropped_update_callback_;
  base::TimeDelta registration_dropped_update_timeout_ =
      kTimeoutRegistrationDroppedUpdate;

  // If the service providers DB contains multiple possible attach APNs, shill
  // needs to try all of them until the UE is registered in the network.
  base::CancelableOnceClosure try_next_attach_apn_callback_;

  base::WeakPtrFactory<CellularCapability3gpp> weak_ptr_factory_;
};

}  // namespace shill

#endif  // SHILL_CELLULAR_CELLULAR_CAPABILITY_3GPP_H_
