// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_CELLULAR_H_
#define SHILL_CELLULAR_CELLULAR_H_

#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <base/strings/string_piece.h>
#include <base/time/time.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/cellular/apn_list.h"
#include "shill/cellular/carrier_entitlement.h"
#include "shill/cellular/dbus_objectmanager_proxy_interface.h"
#include "shill/cellular/mobile_operator_info.h"
#include "shill/device.h"
#include "shill/device_id.h"
#include "shill/event_dispatcher.h"
#include "shill/metrics.h"
#include "shill/mockable.h"
#include "shill/refptr_types.h"
#include "shill/rpc_task.h"
#include "shill/tethering_manager.h"

namespace shill {

class CellularCapability3gpp;
class Error;
class ExternalTask;
class NetlinkSockDiag;
class ProcessManager;
class RTNLListener;
class RTNLMessage;

class Cellular : public Device,
                 public RpcTaskDelegate,
                 public MobileOperatorInfo::Observer {
 public:
  enum class State {
    // Initial state. No Capability exists.
    kDisabled,
    // A Modem object and a corresponding Capability have been created but the
    // Modem has not started.
    kEnabled,
    // A Start request has been sent to the Modem.
    kModemStarting,
    // The Modem Start has completed.
    kModemStarted,
    // A Stop request has been sent to the Modem.
    kModemStopping,
    // The modem has registered with a network. A Cellular Service will be
    // created if necessary and associated with this Device.
    kRegistered,
    // The modem has connected to a network.
    kConnected,
    // The network interface is up.
    kLinked,
  };

  // This enum must be kept in sync with ModemManager's MMModemState enum.
  enum ModemState {
    kModemStateFailed = -1,
    kModemStateUnknown = 0,
    kModemStateInitializing = 1,
    kModemStateLocked = 2,
    kModemStateDisabled = 3,
    kModemStateDisabling = 4,
    kModemStateEnabling = 5,
    kModemStateEnabled = 6,
    kModemStateSearching = 7,
    kModemStateRegistered = 8,
    kModemStateDisconnecting = 9,
    kModemStateConnecting = 10,
    kModemStateConnected = 11,
  };

  // Enum for SIM types
  enum SimType {
    kSimTypeUnknown = 0,
    kSimTypePsim = 1,
    kSimTypeEsim = 2,
  };

  // Used in Cellular and CellularCapability3gpp to store and pass properties
  // associated with a SIM Profile.
  struct SimProperties {
    size_t slot;
    std::string iccid;
    std::string eid;
    std::string operator_id;
    std::string spn;
    std::string imsi;
    std::string gid1;
    bool operator==(const SimProperties& other) const {
      return slot == other.slot && iccid == other.iccid && eid == other.eid &&
             operator_id == other.operator_id && spn == other.spn &&
             imsi == other.imsi && gid1 == other.gid1;
    }
  };

  // Static helper for logging.
  static std::string GetStateString(State state);
  static std::string GetModemStateString(ModemState modem_state);

  // Helper to build a fallback empty APN
  static Stringmap BuildFallbackEmptyApn(ApnList::ApnType apn_type);

  // |path| is the ModemManager.Modem DBus object path (e.g.,
  // "/org/freedesktop/ModemManager1/Modem/0"). |service| is the modem
  // mananager service name (e.g., /org/freedesktop/ModemManager1).
  Cellular(Manager* manager,
           const std::string& link_name,
           const std::string& address,
           int interface_index,
           const std::string& service,
           const RpcIdentifier& path);
  Cellular(const Cellular&) = delete;
  Cellular& operator=(const Cellular&) = delete;

  ~Cellular() override;

  // Returns the legacy identifier used by GetStorageIdentifier for loading
  // entries from older profiles. TODO(b/181843251): Remove after M94.
  std::string GetLegacyEquipmentIdentifier() const;

  // Returns the Capability type if |capability_| has been created.
  std::string GetTechnologyFamily(Error* error);

  // Returns the device id as a string if it has been set.
  std::string GetDeviceId(Error* error);

  // Returns whether the device supports multiplexed data sessions
  bool GetMultiplexSupport();

  // Inherited from Device.
  std::string GetStorageIdentifier() const override;
  bool Load(const StoreInterface* storage) override;
  bool Save(StoreInterface* storage) override;
  void Start(EnabledStateChangedCallback callback) override;
  void Stop(EnabledStateChangedCallback callback) override;
  bool IsUnderlyingDeviceEnabled() const override;
  void Scan(Error* error, const std::string& /*reason*/) override;
  void RegisterOnNetwork(const std::string& network_id,
                         ResultCallback callback) override;
  void RequirePin(const std::string& pin,
                  bool require,
                  ResultCallback callback) override;
  void EnterPin(const std::string& pin, ResultCallback callback) override;
  void UnblockPin(const std::string& unblock_code,
                  const std::string& pin,
                  ResultCallback callback) override;
  void ChangePin(const std::string& old_pin,
                 const std::string& new_pin,
                 ResultCallback callback) override;
  void Reset(ResultCallback callback) override;
  void DropConnection() override;
  void SetServiceState(Service::ConnectState state) override;
  void SetServiceFailure(Service::ConnectFailure failure_state) override;
  void SetServiceFailureSilent(Service::ConnectFailure failure_state) override;
  void OnConnected() override;
  void OnBeforeSuspend(ResultCallback callback) override;
  void OnAfterResume() override;
  void UpdateGeolocationObjects(
      std::vector<GeolocationInfo>* geolocation_infos) const override;

  // Performs the necessary steps to bring the service to the activated state,
  // once an online payment has been done.
  void CompleteActivation(Error* error);

  // Configures the attach APN in the modem.
  virtual void ConfigureAttachApn();
  // Asynchronously detach then re-attach the network.
  virtual void ReAttach();

  // Cancel any pending connect request.
  void CancelPendingConnect();

  void OnScanStarted();
  void OnScanReply(const Stringmaps& found_networks, const Error& error);

  // Asynchronously queries capability for cellular location.
  void PollLocation();

  void HandleNewSignalQuality(uint32_t strength);

  // Processes a change in the modem registration state, possibly creating,
  // destroying or updating the CellularService.
  void HandleNewRegistrationState();

  // Called when the associated Modem object is destroyed.
  void OnModemDestroyed();

  // Returns true if |service| is connectable.
  bool GetConnectable(CellularService* service) const;

  // Asynchronously connects the modem to |service|. Changes the primary slot if
  // required. Populates |error| on failure, leaves it unchanged otherwise.
  virtual void Connect(CellularService* service, Error* error);

  // Asynchronously disconnects the modem from the current network and populates
  // |error| on failure, leaves it unchanged otherwise.
  virtual void Disconnect(Error* error, const char* reason);

  // Called when the Modem object is created to set the initial properties.
  void SetInitialProperties(const InterfaceToProperties& properties);

  void OnModemStateChanged(ModemState new_state);

  // Called to send detailed metrics for the last connection attempt.
  void NotifyDetailedCellularConnectionResult(const Error& error,
                                              ApnList::ApnType apn_type,
                                              const shill::Stringmap& apn_info);

  // Is the underlying device in the process of activating?
  bool IsActivating() const;

  // Starts and stops scheduled location polls
  void StartLocationPolling();
  void StopLocationPolling();

  // Initiate PPP link. Called from capabilities.
  virtual void StartPPP(const std::string& serial_device);
  // Callback for |ppp_task_|.
  virtual void OnPPPDied(pid_t pid, int exit);

  // Implements RpcTaskDelegate, for |ppp_task_|.
  void GetLogin(std::string* user, std::string* password) override;
  void Notify(const std::string& reason,
              const std::map<std::string, std::string>& dict) override;

  // Register DBus Properties exposed by the Device interface of shill.
  void RegisterProperties();

  // |dbus_path| and |mac_address| may change if the associated Modem restarts.
  void UpdateModemProperties(const RpcIdentifier& dbus_path,
                             const std::string& mac_address);

  // Returns a unique identifier for a SIM Card. For physical cards this will be
  // the ICCID and there should only be one matching service. For eSIM cards,
  // this will be the eUICCID (eID) and there may be multiple services
  // associated with the card.
  const std::string& GetSimCardId() const;

  // Returns true if |sim_card_id| matches any available SIM cards.
  bool HasIccid(const std::string& iccid) const;

  // Sets the SIM properties and the primary SIM, and updates services and
  // state accordingly.
  void SetSimProperties(const std::vector<SimProperties>& slot_properties,
                        size_t primary_slot);

  // Verifies if the device is entitled to use the Hotspot feature.
  void EntitlementCheck(
      base::OnceCallback<void(TetheringManager::EntitlementStatus)> callback);

  // Called when an OTA profile update arrives from the network.
  void OnProfilesChanged();

  // Returns a list of APNs of type |apn_type| to try. The logic when using
  // SetApn and SetCustomApnList(APN UI revamp) differs. When using
  // |SetCustomApnList| and the user has set at least 1 APN , only custom APNs
  // will be included in the list, otherwise the logic is the same as |SetApn|.
  // The APNs returned when using |SetApn| are in the following order:
  // - the APN, if any, that was set by the user(for SetApn only)
  // - APNs that the modem reports as provisioned profiles
  // - the list of APNs found in the mobile broadband provider DB for the
  //   home provider associated with the current SIM
  // - the last APN that resulted in a successful connection attempt on the
  //   current network (if any)
  std::deque<Stringmap> BuildApnTryList(ApnList::ApnType apn_type) const;

  // Same as BuildApnTryList, but it only returns IA APNs.
  std::deque<Stringmap> BuildAttachApnTryList() const;
  // Same as BuildApnTryList, but it only returns DEFAULT APNs.
  std::deque<Stringmap> BuildDefaultApnTryList() const;
  // Same as BuildApnTryList, but it only returns DUN APNs.
  std::deque<Stringmap> BuildTetheringApnTryList() const;

  // Update the home provider. This information may be from the SIM or received
  // OTA.
  void UpdateHomeProvider();

  // Update the serving operator info.
  void UpdateServingOperator();

  // Implements MobileOperatorInfo::Observer:
  void OnOperatorChanged() override;

  const CellularServiceRefPtr& service() const { return service_; }
  MobileOperatorInfo* mobile_operator_info() const {
    return mobile_operator_info_.get();
  }
  State state() const { return state_; }
  ModemState modem_state() const { return modem_state_; }
  bool allow_roaming_property() const { return allow_roaming_; }

  bool StateIsConnected();
  bool StateIsRegistered();
  bool StateIsStarted();

  // DBus property getters
  const std::string& dbus_service() const { return dbus_service_; }
  const RpcIdentifier& dbus_path() const { return dbus_path_; }
  const Stringmap& home_provider() const { return home_provider_; }
  bool scanning_supported() const { return scanning_supported_; }
  const std::string& eid() const { return eid_; }
  const std::string& esn() const { return esn_; }
  const std::string& firmware_revision() const { return firmware_revision_; }
  const std::string& hardware_revision() const { return hardware_revision_; }
  const DeviceId* device_id() const { return device_id_.get(); }
  const std::string& imei() const { return imei_; }
  const std::string& imsi() const { return imsi_; }
  const std::string& mdn() const { return mdn_; }
  const std::string& meid() const { return meid_; }
  const std::string& min() const { return min_; }
  const std::string& manufacturer() const { return manufacturer_; }
  const std::string& model_id() const { return model_id_; }
  const std::string& mm_plugin() const { return mm_plugin_; }
  bool scanning() const { return scanning_; }

  const std::string& selected_network() const { return selected_network_; }
  const Stringmaps& found_networks() const { return found_networks_; }
  bool sim_present() const { return sim_present_; }
  const Stringmaps& apn_list() const { return apn_list_; }
  const std::string& iccid() const { return iccid_; }
  bool allow_roaming() const { return allow_roaming_; }
  bool policy_allow_roaming() const { return policy_allow_roaming_; }
  bool provider_requires_roaming() const { return provider_requires_roaming_; }
  bool use_attach_apn() const { return use_attach_apn_; }

  bool inhibited() const { return inhibited_; }
  const std::string& connect_pending_iccid() const {
    return connect_pending_iccid_;
  }

  // Property setters. TODO(b/176904580): Rename SetFoo and alphabetize.
  void SetScanningSupported(bool scanning_supported);
  void SetEquipmentId(const std::string& equipment_id);
  void SetEsn(const std::string& esn);
  void SetFirmwareRevision(const std::string& firmware_revision);
  void SetHardwareRevision(const std::string& hardware_revision);
  void SetDeviceId(std::unique_ptr<DeviceId> device_id);
  void SetImei(const std::string& imei);
  void SetMdn(const std::string& mdn);
  void SetMeid(const std::string& meid);
  void SetMin(const std::string& min);
  void SetManufacturer(const std::string& manufacturer);
  void SetModelId(const std::string& model_id);
  void SetMMPlugin(const std::string& mm_plugin);
  void SetMaxActiveMultiplexedBearers(uint32_t max_multiplexed_bearers);

  void SetSelectedNetwork(const std::string& selected_network);
  void SetFoundNetworks(const Stringmaps& found_networks);
  void SetPrimaryMultiplexedInterface(const std::string& interface_name);
  void SetProviderRequiresRoaming(bool provider_requires_roaming);
  bool IsRoamingAllowed();
  void SetApnList(const Stringmaps& apn_list);

  // TODO(b/267804414): Called whenever the tethering feature flag changes
  // value. This is a temporary function to switch mobile operator databases
  // until b/249387693 is completed.
  void TetheringAllowedUpdated(bool allowed);

  // Sets a Service for testing. When set, Cellular does not create or destroy
  // the associated Service.
  void SetServiceForTesting(CellularServiceRefPtr service);
  void SetSelectedServiceForTesting(CellularServiceRefPtr service);

  void set_home_provider_for_testing(const Stringmap& home_provider) {
    home_provider_ = home_provider;
  }
  void set_mobile_operator_info_for_testing(
      MobileOperatorInfo* mobile_operator_info) {
    mobile_operator_info_.reset(mobile_operator_info);
  }
  void clear_found_networks_for_testing() { found_networks_.clear(); }
  CellularCapability3gpp* capability_for_testing() { return capability_.get(); }
  const KeyValueStores& sim_slot_info_for_testing() { return sim_slot_info_; }
  void set_modem_state_for_testing(ModemState state) { modem_state_ = state; }
  void set_eid_for_testing(const std::string& eid) { eid_ = eid; }
  void set_iccid_for_testing(const std::string& iccid) { iccid_ = iccid; }
  void set_state_for_testing(const State& state) { state_ = state; }
  void set_skip_establish_link_for_testing(bool on) {
    skip_establish_link_for_testing_ = on;
  }

  // Public to ease testing without real RTNL link events.
  void LinkDeleted(int interface_index);
  void LinkUp(int interface_index);
  void LinkDown(int interface_index);

  // Delay before connecting to pending connect requests. This helps prevent
  // connect failures while the Modem is still starting up.
  static constexpr base::TimeDelta kPendingConnectDelay = base::Seconds(2);

 private:
  friend class CellularTest;
  friend class CellularServiceTest;
  friend class CellularServiceProviderTest;
  friend class ModemTest;
  FRIEND_TEST(CellularTest, ChangeServiceState);
  FRIEND_TEST(CellularTest, ChangeServiceStatePPP);
  FRIEND_TEST(CellularTest, CompareApns);
  FRIEND_TEST(CellularTest, CompareApnsFromStorage);
  FRIEND_TEST(CellularTest, CompareApnsFromApnList);
  FRIEND_TEST(CellularTest, CompareApns);
  FRIEND_TEST(CellularTest, CompareApnsFromStorage);
  FRIEND_TEST(CellularTest, CompareApnsFromApnList);
  FRIEND_TEST(CellularTest, CompareApns);
  FRIEND_TEST(CellularTest, CompareApnsFromStorage);
  FRIEND_TEST(CellularTest, CompareApnsFromApnList);
  FRIEND_TEST(CellularTest, Connect);
  FRIEND_TEST(CellularTest, ConnectFailure);
  FRIEND_TEST(CellularTest, Disconnect);
  FRIEND_TEST(CellularTest, DisconnectFailure);
  FRIEND_TEST(CellularTest, DropConnection);
  FRIEND_TEST(CellularTest, DropConnectionPPP);
  FRIEND_TEST(CellularTest, EstablishLinkDHCP);
  FRIEND_TEST(CellularTest, EstablishLinkPPP);
  FRIEND_TEST(CellularTest, EstablishLinkStatic);
  FRIEND_TEST(CellularTest, EstablishLinkFailureNoBearer);
  FRIEND_TEST(CellularTest, EstablishLinkFailureMismatchedDataInterface);
  FRIEND_TEST(CellularTest, HomeProviderServingOperator);
  FRIEND_TEST(CellularTest, LinkEventUpWithPPP);
  FRIEND_TEST(CellularTest, LinkEventUpWithoutPPP);
  FRIEND_TEST(CellularTest, Notify);
  FRIEND_TEST(CellularTest, OnAfterResumeDisableInProgressWantDisabled);
  FRIEND_TEST(CellularTest, OnAfterResumeDisableQueuedWantEnabled);
  FRIEND_TEST(CellularTest, OnAfterResumeDisabledWantDisabled);
  FRIEND_TEST(CellularTest, OnAfterResumeDisabledWantEnabled);
  FRIEND_TEST(CellularTest, OnAfterResumePowerDownInProgressWantEnabled);
  FRIEND_TEST(CellularTest, OnPPPDied);
  FRIEND_TEST(CellularTest, PPPConnectionFailedAfterAuth);
  FRIEND_TEST(CellularTest, PPPConnectionFailedBeforeAuth);
  FRIEND_TEST(CellularTest, PPPConnectionFailedDuringAuth);
  FRIEND_TEST(CellularTest, PPPConnectionFailedAfterConnect);
  FRIEND_TEST(CellularTest, RequiredApnExists);
  FRIEND_TEST(CellularTest, SetPolicyAllowRoaming);
  FRIEND_TEST(CellularTest, SetUseAttachApn);
  FRIEND_TEST(CellularTest, StopPPPOnDisconnect);
  FRIEND_TEST(CellularTest, StorageIdentifier);
  FRIEND_TEST(CellularTest, StartPPP);
  FRIEND_TEST(CellularTest, StartPPPAfterEthernetUp);
  FRIEND_TEST(CellularTest, StartPPPAlreadyStarted);
  FRIEND_TEST(CellularTest, UpdateGeolocationObjects);
  // Names of properties in storage
  static const char kAllowRoaming[];
  static const char kPolicyAllowRoaming[];
  static const char kUseAttachApn[];

  // Modem Manufacturer Name
  static const char kQ6V5ModemManufacturerName[];

  // Modem driver remoteproc pattern
  static const char kQ6V5RemoteprocPattern[];

  // Modem driver sysfs base path
  static const char kQ6V5SysfsBasePath[];

  // Modem driver name
  static const char kQ6V5DriverName[];

  // Temporary database used to test tethering on carriers that require DUN APNs
  static const char kTetheringTestDatabasePath[];

  // Time between stop and start of modem device
  static constexpr base::TimeDelta kModemResetTimeout = base::Seconds(1);

  // Time between asynchronous calls to ModemManager1's GetLocation()
  static constexpr base::TimeDelta kPollLocationInterval = base::Minutes(5);

  // Cleans up the APN try list removing invalid entries
  static void ValidateApnTryList(std::deque<Stringmap>& apn_try_list);

  enum class StopSteps {
    // Initial state.
    kStopModem,
    // The modem has been stopped.
    kModemStopped,
  };

  void CreateCapability();
  void DestroyCapability();

  // TODO(b/173635024): Fix order of cellular.h and .cc methods.
  void StartModem(EnabledStateChangedCallback callback);
  void StartModemCallback(EnabledStateChangedCallback callback,
                          const Error& error);
  void StopModemCallback(EnabledStateChangedCallback callback,
                         const Error& error);
  void DestroySockets();

  bool ShouldBringNetworkInterfaceDownAfterDisabled() const override;

  void SetDbusPath(const shill::RpcIdentifier& dbus_path);
  void SetState(State state);
  void SetModemState(ModemState modem_state_state);
  void SetScanning(bool scanning);
  void SetScanningProperty(bool scanning);

  void OnEnabled();
  void OnConnecting();
  void OnDisconnected();
  void OnDisconnectFailed();
  void NotifyCellularConnectionResult(const Error& error,
                                      const std::string& iccid,
                                      bool is_user_triggered,
                                      ApnList::ApnType apn_type);
  // Invoked when the modem is connected to the cellular network to transition
  // to the network-connected state and bring the network interface up.
  void EstablishLink();

  void LinkMsgHandler(const RTNLMessage& msg);

  void SetPrimarySimProperties(const SimProperties& properties);
  void SetSimSlotProperties(const std::vector<SimProperties>& slot_properties,
                            int primary_slot);

  void SetRegistered();

  // Creates or destroys services as required.
  void UpdateServices();

  // Creates and registers services for the available SIMs and sets
  // |service_| to the primary (active) service.
  void CreateServices();

  // Destroys all services and the connection, if any. This also eliminates any
  // circular references between this device and the associated service,
  // allowing eventual device destruction.
  void DestroyAllServices();

  // Compares 2 APN configurations ignoring fields that are not connection
  // properties. This is needed since we add tags to the APN Stringmap to track
  // information related to each APN, but these properties are not used as
  // connection properties.
  bool CompareApns(const Stringmap& apn1, const Stringmap& apn2) const;

  bool IsRequiredByCarrierApn(const Stringmap& apn) const;
  bool RequiredApnExists(ApnList::ApnType apn_type) const;

  // Creates or updates services for secondary SIMs.
  void UpdateSecondaryServices();

  // HelpRegisterDerived*: Expose a property over RPC, with the name |name|.
  //
  // Reads of the property will be handled by invoking |get|.
  // Writes to the property will be handled by invoking |set|.
  // Clearing the property will be handled by PropertyStore.
  void HelpRegisterDerivedBool(base::StringPiece name,
                               bool (Cellular::*get)(Error* error),
                               bool (Cellular::*set)(const bool& value,
                                                     Error* error));
  void HelpRegisterConstDerivedString(
      base::StringPiece name, std::string (Cellular::*get)(Error* error));

  void OnConnectReply(std::string iccid,
                      bool is_user_triggered,
                      const Error& error);
  void OnDisconnectReply(const Error& error);

  void ReAttachOnDetachComplete(const Error& error);

  // DBus accessors
  bool GetPolicyAllowRoaming(Error* /*error*/);
  bool SetPolicyAllowRoaming(const bool& value, Error* error);
  bool GetInhibited(Error* /*error*/);
  bool SetInhibited(const bool& inhibited, Error* error);
  KeyValueStore GetSimLockStatus(Error* error);
  void SetSimPresent(bool sim_present);

  // TODO(b/277792069): Remove when Chrome removes the attach APN code.
  // DBUS accessors to read/modify the use of an Attach APN
  bool GetUseAttachApn(Error* /*error*/) { return true; }
  bool SetUseAttachApn(const bool& value, Error* error);

  // When shill terminates or ChromeOS suspends, this function is called to
  // disconnect from the cellular network.
  void StartTermination();

  // This method is invoked upon the completion of StartTermination().
  void OnTerminationCompleted(const Error& error);

  // This function does the final cleanup once a disconnect request terminates.
  // Returns true, if the device state is successfully changed.
  bool DisconnectCleanup();

  // Executed after the asynchronous CellularCapability3gpp::StartModem
  // call from OnAfterResume completes.
  static void LogRestartModemResult(const Error& error);

  // Handler to reset qcom-q6v5-mss based modems
  bool ResetQ6V5Modem();

  // Get reset path for Q6V5 modem
  base::FilePath GetQ6V5ModemResetPath();

  // Handler to check if modem is based on qcom-q6v5-mss
  bool IsQ6V5Modem();

  // Execute the next step to Stop cellular.
  void StopStep(EnabledStateChangedCallback callback,
                const Error& error_result);

  // Terminate the pppd process associated with this Device, and remove the
  // association between the PPPDevice and our CellularService. If this
  // Device is not using PPP, the method has no effect.
  void StopPPP();

  // Handlers for PPP events. Dispatched from Notify().
  void OnPPPAuthenticated();
  void OnPPPAuthenticating();
  void OnPPPConnected(const std::map<std::string, std::string>& params);

  bool ModemIsEnabledButNotRegistered();

  void SetPendingConnect(const std::string& iccid);
  void ConnectToPending();
  void ConnectToPendingAfterDelay();
  void ConnectToPendingFailed(Service::ConnectFailure failure);
  void ConnectToPendingCancel();

  void UpdateScanning();
  void GetLocationCallback(const std::string& gpp_lac_ci_string,
                           const Error& error);
  void PollLocationTask();

  void StartLinkListener();
  void StopLinkListener();

  void ResetCarrierEntitlement();
  void OnEntitlementCheckUpdated(CarrierEntitlement::Result result);

  State state_ = State::kDisabled;
  ModemState modem_state_ = kModemStateUnknown;

  struct LocationInfo {
    std::string mcc;
    std::string mnc;
    std::string lac;
    std::string ci;
  };
  LocationInfo location_info_;

  // Network Operator info object. This object receives updates as we receive
  // information about the network operators from the SIM or OTA. In turn, it
  // sends out updates through its observer interface whenever the identity of
  // the network operator changes, or any other property of the operator
  // changes.
  std::unique_ptr<MobileOperatorInfo> mobile_operator_info_;

  // ///////////////////////////////////////////////////////////////////////////
  // All DBus Properties exposed by the Cellular device.
  const std::string dbus_service_;  // org.*.ModemManager*
  RpcIdentifier dbus_path_;         // ModemManager.Modem
  // Used because we currently expose |dbus_path| as a string property.
  std::string dbus_path_str_;

  Stringmap home_provider_;

  bool scanning_supported_ = false;
  std::string equipment_id_;
  std::string esn_;
  std::string firmware_revision_;
  std::string hardware_revision_;
  std::unique_ptr<DeviceId> device_id_;
  std::string imei_;
  std::string manufacturer_;
  std::string mdn_;
  std::string meid_;
  std::string min_;
  std::string model_id_;
  std::string mm_plugin_;
  uint32_t max_multiplexed_bearers_ = 1;
  bool scanning_ = false;
  bool polling_location_ = false;
  base::CancelableOnceClosure poll_location_task_;

  std::string selected_network_;
  Stringmaps found_networks_;
  uint16_t scan_interval_ = 0;
  Stringmaps apn_list_;
  std::string primary_multiplexed_interface_;

  // Primary SIM properties.
  std::string eid_;  // SIM eID, aka eUICCID
  std::string iccid_;
  std::string imsi_;
  bool sim_present_ = false;

  // vector of SimProperties, ordered by slot.
  std::vector<SimProperties> sim_slot_properties_;
  int primary_sim_slot_ = -1;
  // vector of KeyValueStore dictionaries, emitted as Device.SIMSlotInfo.
  KeyValueStores sim_slot_info_;

  // End of DBus properties.
  // ///////////////////////////////////////////////////////////////////////////

  std::unique_ptr<CellularCapability3gpp> capability_;
  std::optional<InterfaceToProperties> initial_properties_;
  std::unique_ptr<CarrierEntitlement> carrier_entitlement_;

  ProcessManager* process_manager_;

  // The active CellularService instance for this Device. This will always be
  // set to a valid service instance.
  CellularServiceRefPtr service_;
  // When set in tests, |service_| is not created or destroyed by Cellular.
  CellularServiceRefPtr service_for_testing_;

  // User preference to allow or disallow roaming before M92. Used as a default
  // until Chrome ties its roaming toggle to Service.AllowRoaming (b/184375691)
  bool allow_roaming_ = false;

  // If an operator has no home network, then set this flag. This overrides
  // all other roaming preferences, and allows roaming unconditionally.
  bool policy_allow_roaming_ = true;

  bool provider_requires_roaming_ = false;

  // Chrome flags to enable setting the attach APN from the host
  bool use_attach_apn_ = false;

  // Reflects the Device property indicating that the modem is inhibted. The
  // property is not persisted and is reset to false when the modem starts.
  bool inhibited_ = false;

  // Track whether a user initiated scan is in prgoress (initiated via ::Scan)
  bool proposed_scan_in_progress_ = false;

  // Flag indicating that a disconnect has been explicitly requested.
  bool explicit_disconnect_ = false;

  std::unique_ptr<ExternalTask> ppp_task_;
  VirtualDeviceRefPtr ppp_device_;
  bool is_ppp_authenticating_ = false;

  std::unique_ptr<NetlinkSockDiag> socket_destroyer_;

  // Used to keep scanning=true while the Modem is restarting.
  // TODO(b/177588333): Make Modem and/or the MM dbus API more robust.
  base::CancelableOnceClosure scanning_clear_callback_;

  // If a Connect request occurs while the Modem is busy, do not connect
  // immediately, instead set |connect_pending_iccid_|. The connect will occur
  // after a delay once Scanning is set to false.
  std::string connect_pending_iccid_;
  base::CancelableOnceClosure connect_pending_callback_;
  // Used to cancel a pending connect while waiting for Modem registration.
  base::CancelableOnceClosure connect_cancel_callback_;
  // Stores the callback passed in |EntitlementCheck| when an entitlement check
  // is requested to |CarrierEntitlement|.
  base::OnceCallback<void(TetheringManager::EntitlementStatus)>
      entitlement_check_callback_;
  // Legacy device storage identifier, used for removing legacy entry.
  std::string legacy_storage_id_;

  // A Map containing the last connection results. ICCID is used as the key.
  std::unordered_map<std::string, Error::Type>
      last_cellular_connection_results_;

  // A Map to maintain if subscription error was seen before. ICCID is used as
  // the key.
  std::unordered_map<std::string, bool> subscription_error_seen_;

  // The current step of the Stop process.
  std::optional<StopSteps> stop_step_;

  // When set in tests, a connection attempt doesn't attempt link establishment
  bool skip_establish_link_for_testing_ = false;

  std::unique_ptr<RTNLListener> link_listener_;

  base::WeakPtrFactory<Cellular> weak_ptr_factory_{this};
};

}  // namespace shill

#endif  // SHILL_CELLULAR_CELLULAR_H_
