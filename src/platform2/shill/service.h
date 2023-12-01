// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_SERVICE_H_
#define SHILL_SERVICE_H_

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <valarray>
#include <vector>

#include <base/cancelable_callback.h>
#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>
#include <base/strings/string_piece.h>
#include <base/time/time.h>
#include <chromeos/patchpanel/dbus/client.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/adaptor_interfaces.h"
#include "shill/callbacks.h"
#include "shill/data_types.h"
#include "shill/mockable.h"
#include "shill/net/event_history.h"
#include "shill/net/shill_time.h"
#include "shill/network/network.h"
#include "shill/network/network_config.h"
#include "shill/refptr_types.h"
#include "shill/static_ip_parameters.h"
#include "shill/store/pkcs11_slot_getter.h"
#include "shill/store/property_store.h"
#include "shill/technology.h"

namespace shill {

class ControlInterface;
class EapCredentials;
class Error;
class EventDispatcher;
class KeyValueStore;
class Manager;
class Metrics;
class MockManager;
class ServiceAdaptorInterface;
class ServiceMockAdaptor;
class StoreInterface;

// A Service is a uniquely named entity, which the system can
// connect in order to begin sending and receiving network traffic.
// All Services are bound to an Entry, which represents the persistable
// state of the Service.  If the Entry is populated at the time of Service
// creation, that information is used to prime the Service.  If not, the Entry
// becomes populated over time.
class Service : public base::RefCounted<Service> {
 public:
  // Map from traffic source to a valarray containing {rx_bytes, tx_bytes,
  // rx_packets, tx_packets} in that order.
  using TrafficCounterMap =
      std::map<patchpanel::Client::TrafficSource, std::valarray<uint64_t>>;

  // Enum values representing values retrieved from patchpanel.
  enum TrafficCounterVals {
    kRxBytes = 0,
    kTxBytes,
    kRxPackets,
    kTxPackets,
  };

  static const char kCheckPortalAuto[];
  static const char kCheckPortalFalse[];
  static const char kCheckPortalTrue[];

  static constexpr base::StringPiece kErrorDetailsNone = "";

  // TODO(pstew): Storage constants shouldn't need to be public
  // crbug.com/208736
  static const char kStorageAutoConnect[];
  static const char kStorageCheckPortal[];
  static const char kStorageDNSAutoFallback[];
  static const char kStorageError[];
  static const char kStorageGUID[];
  static const char kStorageHasEverConnected[];
  static const char kStorageName[];
  static const char kStorageONCSource[];
  static const char kStoragePriority[];
  static const char kStorageProxyConfig[];
  static const char kStorageSaveCredentials[];
  static const char kStorageType[];
  static const char kStorageUIData[];
  static const char kStorageConnectionId[];
  static const char kStorageLinkMonitorDisabled[];
  static const char kStorageManagedCredentials[];
  static const char kStorageMeteredOverride[];
  // The prefix for traffic counter storage key for the current
  // billing cycles, appended by the source being counted (e.g. CHROME, USER,
  // ARC, etc.)
  static const char kStorageCurrentTrafficCounterPrefix[];
  // The suffixes for traffic counter storage keys.
  static const char kStorageTrafficCounterRxBytesSuffix[];
  static const char kStorageTrafficCounterTxBytesSuffix[];
  static const char kStorageTrafficCounterRxPacketsSuffix[];
  static const char kStorageTrafficCounterTxPacketsSuffix[];
  // An array of the traffic counter storage suffixes in the order that we
  // expect them to be read from patchpanel and stored in the profile.
  static const char* const kStorageTrafficCounterSuffixes[];
  static const char kStorageTrafficCounterResetTime[];
  // The datetime of the last connection attempt.
  static const char kStorageLastManualConnectAttempt[];
  static const char kStorageLastConnected[];
  static const char kStorageLastOnline[];

  static const uint8_t kStrengthMax;
  static const uint8_t kStrengthMin;

  enum ConnectFailure {
    kFailureNone,
    kFailureAAA,
    kFailureActivation,
    kFailureBadPassphrase,
    kFailureBadWEPKey,
    kFailureConnect,
    kFailureDHCP,
    kFailureDNSLookup,
    kFailureEAPAuthentication,
    kFailureEAPLocalTLS,
    kFailureEAPRemoteTLS,
    kFailureHTTPGet,
    kFailureInvalidAPN,
    kFailureIPsecCertAuth,
    kFailureIPsecPSKAuth,
    kFailureInternal,
    kFailureNeedEVDO,
    kFailureNeedHomeNetwork,
    kFailureOTASP,
    kFailureOutOfRange,
    kFailurePPPAuth,
    kFailurePinMissing,
    kFailureSimLocked,
    kFailureNotRegistered,
    kFailureUnknown,
    // WiFi association failure that doesn't correspond to any other failure
    kFailureNotAssociated,
    // WiFi authentication failure that doesn't correspond to any other failure
    kFailureNotAuthenticated,
    kFailureTooManySTAs,
    // The service disconnected. This may happen when the device suspends or
    // switches to a different network. These errors are generally ignored by
    // the client (i.e. Chrome).
    kFailureDisconnect,
    kFailureMax
  };
  enum ConnectState {
    // Unknown state.
    kStateUnknown,
    // Service is not active.
    kStateIdle,
    // Associating with service.
    kStateAssociating,
    // IP provisioning.
    kStateConfiguring,
    // Successfully associated and IP provisioned.
    kStateConnected,
    // Connected but portal detection probes timed out.
    kStateNoConnectivity,
    // HTTP probe returned a 302 with a redirect URL.
    kStateRedirectFound,
    // HTTP probe returned without a 204 or redirect, or HTTPS probe failed.
    kStatePortalSuspected,
    // Failed to connect.
    kStateFailure,
    // Connected to the Internet.
    kStateOnline,
    // In the process of disconnecting.
    kStateDisconnecting
  };

  enum RoamState {
    // Service is not roaming.
    kRoamStateIdle,
    // Service has begun within-ESS reassociation.
    kRoamStateAssociating,
    // IP renewal after reassociation.
    kRoamStateConfiguring,
    // Successfully reassociated and renewed IP.
    kRoamStateConnected,
  };

  enum CryptoAlgorithm { kCryptoNone, kCryptoRc4, kCryptoAes };

  enum UpdateCredentialsReason {
    kReasonCredentialsLoaded,
    kReasonPropertyUpdate,
    kReasonPasspointMatch
  };

  // Enumeration of possible ONC sources.
  enum class ONCSource : size_t {
    kONCSourceUnknown,
    kONCSourceNone,
    kONCSourceUserImport,
    kONCSourceDevicePolicy,
    kONCSourceUserPolicy,
    kONCSourcesNum,  // Number of enum values above. Keep it last.
  };

  enum class TetheringState {
    kUnknown,
    kNotDetected,
    kSuspected,
    kConfirmed,
  };

  static const int kPriorityNone;

  // A constructor for the Service object
  Service(Manager* manager, Technology technology);
  Service(const Service&) = delete;
  Service& operator=(const Service&) = delete;

  // AutoConnect MAY choose to ignore the connection request in some
  // cases. For example, if the corresponding Device only supports one
  // concurrent connection, and another Service is already connected
  // or connecting.
  //
  // AutoConnect MAY issue RPCs immediately. So AutoConnect MUST NOT
  // be called from a D-Bus signal handler context.
  virtual void AutoConnect();
  // Queue up a connection attempt. Child-specific behavior is implemented in
  // OnConnect.
  mockable void Connect(Error* error, const char* reason);
  // Disconnect this Service. If the Service is not active, this call will be a
  // no-op aside from logging an error.
  mockable void Disconnect(Error* error, const char* reason);
  // Disconnect this Service via Disconnect(). Marks the Service as having
  // failed with |failure|.
  mockable void DisconnectWithFailure(ConnectFailure failure,
                                      Error* error,
                                      const char* reason);
  // Connect to this service via Connect(). This function indicates that the
  // connection attempt is user-initiated.
  mockable void UserInitiatedConnect(const char* reason, Error* error);
  // Disconnect this service via Disconnect(). The service will not be eligible
  // for auto-connect until a subsequent call to Connect, or Load.
  mockable void UserInitiatedDisconnect(const char* reason, Error* error);

  // The default implementation returns the error kNotSupported.
  virtual void CompleteCellularActivation(Error* error);

  // The default implementation returns the error kNotSupported.
  virtual std::string GetWiFiPassphrase(Error* error);

  mockable bool IsActive(Error* error) const;

  // Returns whether services of this type should be auto-connect by default.
  virtual bool IsAutoConnectByDefault() const { return false; }

  mockable ConnectState state() const { return state_; }
  // Updates the state of the Service and alerts the manager.  Also
  // clears |failure_| if the new state isn't a failure.
  virtual void SetState(ConnectState state);
  std::string GetStateString() const;

  // Implemented by WiFiService to set the roam state. Other types of services
  // may call this as a result of DHCP renewal, but it's ignored.
  virtual void SetRoamState(RoamState roam_state) {}

  // Set probe URL hint. This function is called when a redirect URL is found
  // during portal detection.
  mockable void SetProbeUrl(const std::string& probe_url_string);

  // Set portal detection failure phase, status (reason), and http status code.
  // This function is called when portal detection failed for the Service.
  mockable void SetPortalDetectionFailure(const std::string& phase,
                                          const std::string& status,
                                          int status_code);

  // Whether or not the most recent failure should be ignored. This will return
  // true if the failure was the result of a user-initiated disconnect, a
  // disconnect on shutdown, or a disconnect due to a suspend.
  mockable bool ShouldIgnoreFailure() const;

  // State utility functions
  static bool IsConnectedState(ConnectState state);
  static bool IsConnectingState(ConnectState state);
  static bool IsPortalledState(ConnectState state);

  mockable bool IsConnected(Error* error = nullptr) const;
  mockable bool IsConnecting() const;
  bool IsDisconnecting() const;
  mockable bool IsPortalled() const;
  mockable bool IsFailed() const;
  mockable bool IsInFailState() const;
  mockable bool IsOnline() const;

  mockable bool link_monitor_disabled() const { return link_monitor_disabled_; }

  mockable ConnectFailure failure() const { return failure_; }
  // Sets the |previous_error_| property based on the current |failure_|, and
  // sets a serial number for this failure.
  mockable void SaveFailure();
  // Records the failure mode and time. Sets the Service state to "Failure".
  mockable void SetFailure(ConnectFailure failure);
  // Records the failure mode and time. Sets the Service state to "Idle".
  // Avoids showing a failure mole in the UI.
  mockable void SetFailureSilent(ConnectFailure failure);

  // Returns a TimeDelta from |failed_time_| or nullopt if unset (no failure).
  std::optional<base::TimeDelta> GetTimeSinceFailed() const;

  void set_failed_time_for_testing(base::Time failed_time) {
    failed_time_ = failed_time;
  }

  void set_previous_error_for_testing(const std::string& error) {
    previous_error_ = error;
  }

  unsigned int serial_number() const { return serial_number_; }
  const std::string& log_name() const { return log_name_; }

  ONCSource Source() const { return source_; }
  int SourcePriority();

  // Returns |serial_number_| as a string for constructing a dbus object path.
  std::string GetDBusObjectPathIdentifier() const;

  // Returns the RpcIdentifier for the ServiceAdaptorInterface.
  mockable const RpcIdentifier& GetRpcIdentifier() const;

  // Returns the unique persistent storage identifier for the service.
  virtual std::string GetStorageIdentifier() const = 0;

  // Returns the identifier within |storage| from which configuration for
  // this service can be loaded.  Returns an empty string if no entry in
  // |storage| can be used.
  virtual std::string GetLoadableStorageIdentifier(
      const StoreInterface& storage) const;

  // Returns whether the service configuration can be loaded from |storage|.
  virtual bool IsLoadableFrom(const StoreInterface& storage) const;

  // Returns true if the service uses 802.1x for key management.
  virtual bool Is8021x() const { return false; }

  // Loads the service from persistent |storage|. Returns true on success.
  virtual bool Load(const StoreInterface* storage);

  // Invoked after Load for migrating storage properties. Ensures migration for
  // services loaded from a Profile. Services not loaded will not get migrated,
  // thus it is best to maintain migration for several releases.
  virtual void MigrateDeprecatedStorage(StoreInterface* storage);

  // Indicate to service that it is no longer persisted to storage.  It
  // should purge any stored profile state (e.g., credentials).  Returns
  // true to indicate that this service should also be unregistered from
  // the manager, false otherwise.
  virtual bool Unload();

  // Attempt to remove the service. On failure, no changes in state will occur.
  virtual void Remove(Error* error);

  // Saves the service to persistent |storage|. Returns true on success.
  virtual bool Save(StoreInterface* storage);

  // Applies all the properties in |args| to this service object's mutable
  // store, except for those in parameters_ignored_for_configure_.
  // Returns an error in |error| if one or more parameter set attempts
  // fails, but will only return the first error.
  mockable void Configure(const KeyValueStore& args, Error* error);

  // Iterate over all the properties in |args| and test for an identical
  // value in this service object's store.  Returns false if one or more
  // keys in |args| do not exist or have different values, true otherwise.
  mockable bool DoPropertiesMatch(const KeyValueStore& args) const;

  // Returns whether portal detection is disabled by configuration on this
  // service. This is the case if any of the following conditions is met:
  //   - Property "CheckPortal" is set to "false".
  //   - Property "CheckPortal" is set to "auto" and portal detection is
  //     disabled for the link technology of this Service.
  //   - The Service has a proxy configuration defined.
  mockable bool IsPortalDetectionDisabled() const;

  // Returns true if the service is persisted to a non-ephemeral profile.
  mockable bool IsRemembered() const;

  // Returns true if the service RPC identifier should be part of the
  // manager's advertised services list, false otherwise.
  virtual bool IsVisible() const { return true; }

  // Returns true if there is a proxy configuration set on this service.
  mockable bool HasProxyConfig() const { return !proxy_config_.empty(); }

  // Returns whether this service has had recent connection issues.
  mockable bool HasRecentConnectionIssues();

  // If the AutoConnect property has not already been marked as saved, set
  // its value to true and mark it saved.
  virtual void EnableAndRetainAutoConnect();

  // Reset |auto_connect_cooldown_| and cancel |reenable_auto_connect_task_|,
  // but don't notify manager on the service update.
  mockable void ResetAutoConnectCooldownTime();

  // Returns the Network attached to this Service, or nullptr if the Service is
  // not connected and has no associated Network.
  Network* attached_network() const { return attached_network_.get(); }
  // Notifies Service that a connecting or connected Network is attached to this
  // Service.
  mockable void SetAttachedNetwork(base::WeakPtr<Network> network);
  // Notifies D-Bus listeners of a IPConfig change event if the new IPConfig is
  // not empty.
  void EmitIPConfigPropertyChange();

  // Returns the virtual device associated with this service. Currently this
  // will return a Device pointer only for a connected VPN service.
  virtual VirtualDeviceRefPtr GetVirtualDevice() const;

  // Examines the EAP credentials for the service and returns true if a
  // connection attempt can be made.
  mockable bool Is8021xConnectable() const;

  // Add an EAP certification id |name| at position |depth| in the stack.
  // Returns true if entry was added, false otherwise.
  mockable bool AddEAPCertification(const std::string& name, size_t depth);
  // Clear all EAP certification elements.
  mockable void ClearEAPCertification();

  // Set PKCS#11 slot getter for |eap_|.
  void SetEapSlotGetter(Pkcs11SlotGetter* slot_getter);

  // The inherited class that needs to send metrics after the service has
  // transitioned to the ready state should override this method.
  // |time_resume_to_ready_milliseconds| holds the elapsed time from when
  // the system was resumed until when the service transitioned to the
  // connected state.  This value is non-zero for the first service transition
  // to the connected state after a resume.
  virtual void SendPostReadyStateMetrics(
      int64_t /*time_resume_to_ready_milliseconds*/) const {}

  // Setter and getter for uplink and downlink speeds for the service.
  // The unit of both link speeds are Kbps.
  mockable void SetUplinkSpeedKbps(uint32_t uplink_speed_kbps);
  uint32_t uplink_speed_kbps() const { return uplink_speed_kbps_; }
  mockable void SetDownlinkSpeedKbps(uint32_t downlink_speed_kbps);
  uint32_t downlink_speed_kbps() const { return downlink_speed_kbps_; }

  bool auto_connect() const { return auto_connect_; }
  void SetAutoConnect(bool connect);

  bool connectable() const { return connectable_; }
  // Sets the connectable property of the service, and broadcast the
  // new value. Does not update the manager.
  // TODO(petkov): Remove this method in favor of SetConnectableFull.
  void SetConnectable(bool connectable);
  // Sets the connectable property of the service, broadcasts the new
  // value, and alerts the manager if necessary.
  void SetConnectableFull(bool connectable);

  mockable bool explicitly_disconnected() const {
    return explicitly_disconnected_;
  }

  bool retain_auto_connect() const { return retain_auto_connect_; }
  // Setter is deliberately omitted; use EnableAndRetainAutoConnect.

  const std::string& friendly_name() const { return friendly_name_; }
  // Sets the kNameProperty and broadcasts the change.
  void SetFriendlyName(const std::string& friendly_name);

  const std::string& guid() const { return guid_; }
  bool SetGuid(const std::string& guid, Error* error);

  bool has_ever_connected() const { return has_ever_connected_; }
  // Sets the has_ever_connected_ property of the service
  // and broadcasts the new value
  void SetHasEverConnected(bool has_ever_connected);

  bool is_in_user_connect() const { return is_in_user_connect_; }

  int32_t priority() const { return priority_; }
  bool SetPriority(const int32_t& priority, Error* error);

  size_t crypto_algorithm() const { return crypto_algorithm_; }
  bool key_rotation() const { return key_rotation_; }
  bool endpoint_auth() const { return endpoint_auth_; }

  mockable void SetStrength(uint8_t strength);

  // uint8_t streams out as a char. Coerce to a larger type, so that
  // it prints as a number.
  uint16_t strength() const { return strength_; }

  mockable Technology technology() const { return technology_; }
  std::string GetTechnologyName() const;

  mockable const EapCredentials* eap() const { return eap_.get(); }
  void SetEapCredentials(EapCredentials* eap);
  std::string GetEapPassphrase(Error* error);

  //  Implements Service.RequestPortalDetection.
  void RequestPortalDetection(Error* error);

  bool save_credentials() const { return save_credentials_; }
  void set_save_credentials(bool save) { save_credentials_ = save; }

  const std::string& error() const { return error_; }
  void set_error(const std::string& error) { error_ = error; }

  const std::string& error_details() const { return error_details_; }
  void SetErrorDetails(base::StringPiece details);

  static const char* ConnectFailureToString(const ConnectFailure& state);
  static const char* ConnectStateToString(const ConnectState& state);

  // Compare two services.  The first element of the result pair is true if
  // Service |a| should be displayed above |b|.  If |compare_connectivity_state|
  // is true, the connectivity state of the service (service->state()) is used
  // as the most significant criteria for comparsion, otherwise the service
  // state is ignored.  Use |tech_order| to rank services if more decisive
  // criteria do not yield a difference.  The second element of the result pair
  // contains a string describing the criterion used for the ultimate
  // comparison.
  static std::pair<bool, const char*> Compare(
      ServiceRefPtr a,
      ServiceRefPtr b,
      bool compare_connectivity_state,
      const std::vector<Technology>& tech_order);

  // Returns a sanitized version of |identifier| for use as a service storage
  // identifier by replacing any character in |identifier| that is not
  // alphanumeric or '_' with '_'.
  static std::string SanitizeStorageIdentifier(std::string identifier);

  // These are defined in service.cc so that we don't have to include profile.h
  // TODO(cmasone): right now, these are here only so that we can get the
  // profile name as a property.  Can we store just the name, and then handle
  // setting the profile for this service via |manager_|?
  const ProfileRefPtr& profile() const;

  // Sets the profile property of this service. Broadcasts the new value if it's
  // not nullptr. If the new value is nullptr, the service will either be set to
  // another profile afterwards or it will not be visible and not monitored
  // anymore.
  void SetProfile(const ProfileRefPtr& p);

  // This is called from tests and shouldn't be called otherwise. Use SetProfile
  // instead.
  void set_profile(const ProfileRefPtr& p);

  // Notification that occurs when a service now has profile data saved
  // on its behalf.  Some service types like WiFi can choose to register
  // themselves at this point.
  virtual void OnProfileConfigured() {}

  // Notification that occurs when a single property has been changed via
  // the RPC adaptor.
  mockable void OnPropertyChanged(base::StringPiece property);

  // Notification that occurs when an EAP credential property has been
  // changed.  Some service subclasses can choose to respond to this
  // event.
  virtual void OnEapCredentialsChanged(UpdateCredentialsReason reason) {}

  // Suspend event handler. Called by Manager before the system
  // suspends. This handler, along with any other suspend handlers,
  // will have Manager::kTerminationActionsTimeoutMilliseconds to
  // execute before the system enters the suspend state. |callback|
  // must be invoked after all synchronous and/or asynchronous actions
  // this function performs complete. Code that needs to run on exit should use
  // Manager::AddTerminationAction, rather than OnBeforeSuspend.
  //
  // The default implementation invokes the |callback| immediately, since
  // there is nothing to be done in the general case.
  virtual void OnBeforeSuspend(ResultCallback callback);

  // Called by the manager once after a resume.
  virtual void OnAfterResume();

  // Called by the manager once when entering dark resume.
  mockable void OnDarkResume();

  // Called by the manager when the default physical service's state has
  // changed.
  virtual void OnDefaultServiceStateChanged(const ServiceRefPtr& parent);

  // Called by the manager to clear remembered state of being explicitly
  // disconnected.
  mockable void ClearExplicitlyDisconnected();

  EapCredentials* mutable_eap() { return eap_.get(); }

  PropertyStore* mutable_store() { return &store_; }
  const PropertyStore& store() const { return store_; }

  // Retrieves |key| from |id| in |storage| to |value|.  If this key does
  // not exist, assign |default_value| to |value|.
  static void LoadString(const StoreInterface* storage,
                         const std::string& id,
                         const std::string& key,
                         const std::string& default_value,
                         std::string* value);

  // Assigns |value| to |key| in |storage| if |value| is non-empty; otherwise,
  // removes |key| from |storage|.
  static void SaveStringOrClear(StoreInterface* storage,
                                const std::string& id,
                                const std::string& key,
                                const std::string& value);

  static void SetNextSerialNumberForTesting(unsigned int next_serial_number);

  // Called via RPC to get a dict containing profile-to-entry_name mappings
  // of all the profile entires which contain configuration applicable to
  // this service.
  std::map<RpcIdentifier, std::string> GetLoadableProfileEntries();

  mockable std::string CalculateState(Error* error);

  std::string CalculateTechnology(Error* error);

  // Return whether this service is suspected or confirmed to be provided by a
  // mobile device, which is likely to be using a metered backhaul for internet
  // connectivity.
  virtual TetheringState GetTethering() const;

  // If the user has explicitly designated this connection to be metered
  // or unmetered, returns that value. Otherwise, returns whether or not the
  // connection is confirmed or inferred to be metered.
  bool IsMetered() const;

  // Initializes the traffic_counter_snapshot_ map to the counter values. The
  // snapshots should never be updated without also refreshing the counters.
  mockable void InitializeTrafficCounterSnapshot(
      const std::vector<patchpanel::Client::TrafficCounter>& counters);
  // Increment the current_traffic_counters_ map by the difference between the
  // counter values and the traffic_counter_snapshot_ values, and then update
  // the snapshots as well in one atomic step.
  mockable void RefreshTrafficCounters(
      const std::vector<patchpanel::Client::TrafficCounter>& counters);
  // Requests traffic counters from patchpanel and returns the result in
  // |callback|.
  mockable void RequestTrafficCounters(
      ResultVariantDictionariesCallback callback);
  // Resets traffic counters for |this|.
  mockable void ResetTrafficCounters(Error* error);

  void set_unreliable(bool unreliable) { unreliable_ = unreliable; }
  bool unreliable() const { return unreliable_; }

  TrafficCounterMap& current_traffic_counters() {
    return current_traffic_counters_;
  }
  TrafficCounterMap& traffic_counter_snapshot() {
    return traffic_counter_snapshot_;
  }

  void increment_portal_detection_count() { portal_detection_count_++; }
  int portal_detection_count() const { return portal_detection_count_; }

  // Read only access to previous error number.  This can f.e. be used to check
  // if SetFailure*() has been called for a service without any additional flags
  // - just check if it has been changed.
  int32_t previous_error_number() const {
    return previous_error_serial_number_;
  }

  // The components of this array are rx_bytes, tx_bytes, rx_packets, tx_packets
  // in that order.
  static const size_t kTrafficCounterArraySize;

 protected:
  friend class base::RefCounted<Service>;

  virtual ~Service();

  // Overridden by child classes to perform technology-specific connection
  // logic.
  virtual void OnConnect(Error* error) = 0;
  // Overridden by child classes to perform technology-specific disconnection
  // logic.
  virtual void OnDisconnect(Error* error, const char* reason) = 0;

  // Returns whether this service is in a state conducive to auto-connect.
  // This should include any tests used for computing connectable(),
  // as well as other critera such as whether the device associated with
  // this service is busy with another connection.
  //
  // If the service is not auto-connectable, |*reason| will be set to
  // point to C-string explaining why the service is not auto-connectable.
  virtual bool IsAutoConnectable(const char** reason) const;

  // Returns minimum auto connect cooldown time for ThrottleFutureAutoConnects.
  // May be overridden for types that require a longer cooldown period.
  virtual base::TimeDelta GetMinAutoConnectCooldownTime() const;

  // Returns maximum auto connect cooldown time for ThrottleFutureAutoConnects.
  // May be overridden for types that require a longer cooldown period.
  virtual base::TimeDelta GetMaxAutoConnectCooldownTime() const;

  // Returns true if a Service can be disconnected, otherwise returns false and
  // sets |error|. By default tests whether the Service is active.
  virtual bool IsDisconnectable(Error* error) const;

  bool GetVisibleProperty(Error* error);

  // HelpRegisterDerived*: Expose a property over RPC, with the name |name|.
  //
  // Reads of the property will be handled by invoking |get|.
  // Writes to the property will be handled by invoking |set|.
  // Clearing the property will be handled by PropertyStore.
  void HelpRegisterDerivedBool(base::StringPiece name,
                               bool (Service::*get)(Error* error),
                               bool (Service::*set)(const bool& value,
                                                    Error* error),
                               void (Service::*clear)(Error* error));
  void HelpRegisterDerivedInt32(base::StringPiece name,
                                int32_t (Service::*get)(Error* error),
                                bool (Service::*set)(const int32_t& value,
                                                     Error* error));
  void HelpRegisterDerivedString(base::StringPiece name,
                                 std::string (Service::*get)(Error* error),
                                 bool (Service::*set)(const std::string& value,
                                                      Error* error));
  void HelpRegisterConstDerivedRpcIdentifier(
      base::StringPiece name, RpcIdentifier (Service::*get)(Error*) const);
  void HelpRegisterConstDerivedStrings(base::StringPiece name,
                                       Strings (Service::*get)(Error* error)
                                           const);
  void HelpRegisterConstDerivedString(base::StringPiece name,
                                      std::string (Service::*get)(Error* error)
                                          const);
  void HelpRegisterConstDerivedUint64(base::StringPiece name,
                                      uint64_t (Service::*get)(Error* error)
                                          const);

  ServiceAdaptorInterface* adaptor() const { return adaptor_.get(); }

  void UnloadEapCredentials();

  // Ignore |parameter| when performing a Configure() operation.
  void IgnoreParameterForConfigure(const std::string& parameter);

  // Update the service's string-based "Error" RPC property based on the
  // failure_ enum.
  void UpdateErrorProperty();

  // RPC setter for the the "AutoConnect" property. Updates the |manager_|.
  // (cf. SetAutoConnect, which does not update the manager.)
  virtual bool SetAutoConnectFull(const bool& connect, Error* error);

  // RPC clear method for the "AutoConnect" property.  Sets the AutoConnect
  // property back to its default value, and clears the retain_auto_connect_
  // property to allow the AutoConnect property to be enabled automatically.
  void ClearAutoConnect(Error* error);

  // Property accessors reserved for subclasses
  const std::string& GetEAPKeyManagement() const;
  virtual void SetEAPKeyManagement(const std::string& key_management);

  EventDispatcher* dispatcher() const;
  Metrics* metrics() const;
  Manager* manager() const { return manager_; }

  // Save the service's auto_connect value, without affecting its auto_connect
  // property itself. (cf. EnableAndRetainAutoConnect)
  void RetainAutoConnect();

  // Disables autoconnect and posts a task to re-enable it after a cooldown.
  // Note that autoconnect could be disabled for other reasons as well.
  void ThrottleFutureAutoConnects();

  // Inform base class of the security properties for the service.
  //
  // NB: When adding a call to this function from a subclass, please check
  // that the semantics of SecurityLevel() are appropriate for the subclass.
  void SetSecurity(CryptoAlgorithm crypt, bool rotation, bool endpoint_auth);

  // Emit property change notifications for all observed properties.
  void NotifyIfVisibilityChanged();

  // True if the properties of this network connection (e.g. user contract)
  // imply it is metered.
  virtual bool IsMeteredByServiceProperties() const;

  // Read only access to previous state for derived classes.  This is e.g. used
  // by WiFiService to keep track of disconnect time.
  ConnectState previous_state() const { return previous_state_; }

  // Compare two services with the same technology. Each technology can override
  // it with its own implementation to sort services with its own criteria.
  // It returns true if |service| is different from |this|. When they are,
  // "decision" is populated with the boolean value of "this > service".
  virtual bool CompareWithSameTechnology(const ServiceRefPtr& service,
                                         bool* decision);

  // Utility function that returns true if a is different from b.  When they
  // are, "decision" is populated with the boolean value of "a > b".
  static bool DecideBetween(int a, int b, bool* decision);

  // Used by VPNService.
  StaticIPParameters* mutable_static_ip_parameters() {
    return &static_ip_parameters_;
  }

  // Service's user friendly name, mapped to the Service Object kNameProperty.
  // Use |log_name_| for logging to avoid logging PII.
  std::string friendly_name_;

  // Name used for logging. It includes |unique_id|, the service type, and other
  // non PII identifiers.
  std::string log_name_;

  static const char kAutoConnBusy[];
  static const char kAutoConnConnected[];
  static const char kAutoConnConnecting[];
  static const char kAutoConnDisconnecting[];
  static const char kAutoConnExplicitDisconnect[];
  static const char kAutoConnNotConnectable[];
  static const char kAutoConnOffline[];
  static const char kAutoConnTechnologyNotAutoConnectable[];
  static const char kAutoConnThrottled[];
  static const char kAutoConnMediumUnavailable[];
  static const char kAutoConnRecentBadPassphraseFailure[];

 private:
  friend class DevicePortalDetectorTest;
  friend class EthernetEapServiceTest;
  friend class EthernetServiceTest;
  friend class MetricsTest;
  friend class ManagerTest;
  friend class ServiceAdaptorInterface;
  friend class ServiceTest;
  friend class StaticIPParametersTest;
  friend class VPNProviderTest;
  friend class VPNServiceTest;
  friend class WiFiServiceTest;
  friend void TestCommonPropertyChanges(ServiceRefPtr, ServiceMockAdaptor*);
  friend void TestCustomSetterNoopChange(ServiceRefPtr, MockManager*);
  friend void TestNamePropertyChange(ServiceRefPtr, ServiceMockAdaptor*);
  FRIEND_TEST(AllMockServiceTest, AutoConnectWithFailures);
  FRIEND_TEST(CellularServiceTest, IsAutoConnectable);
  FRIEND_TEST(CellularServiceTest, IsMeteredByDefault);
  FRIEND_TEST(DeviceTest, AcquireIPConfigWithoutSelectedService);
  FRIEND_TEST(DeviceTest, AcquireIPConfigWithSelectedService);
  FRIEND_TEST(DeviceTest, IPConfigUpdatedFailureWithStatic);
  FRIEND_TEST(DeviceTest, FetchTrafficCounters);
  FRIEND_TEST(ManagerTest, ConnectToBestServices);
  FRIEND_TEST(ManagerTest, RefreshAllTrafficCountersTask);
  FRIEND_TEST(ServiceTest, AutoConnectLogging);
  FRIEND_TEST(ServiceTest, CalculateState);
  FRIEND_TEST(ServiceTest, CalculateTechnology);
  FRIEND_TEST(ServiceTest, Certification);
  FRIEND_TEST(ServiceTest, Compare);
  FRIEND_TEST(ServiceTest, CompareSources);
  FRIEND_TEST(ServiceTest, ComparePreferEthernetOverWifi);
  FRIEND_TEST(ServiceTest, ConfigureEapStringProperty);
  FRIEND_TEST(ServiceTest, ConfigureIgnoredProperty);
  FRIEND_TEST(ServiceTest, Constructor);
  FRIEND_TEST(ServiceTest, GetIPConfigRpcIdentifier);
  FRIEND_TEST(ServiceTest, GetProperties);
  FRIEND_TEST(ServiceTest, IsAutoConnectable);
  FRIEND_TEST(ServiceTest, IsNotMeteredByDefault);
  FRIEND_TEST(ServiceTest, IsPortalDetectionDisabled);
  FRIEND_TEST(ServiceTest, Load);
  FRIEND_TEST(ServiceTest, LoadTrafficCounters);
  FRIEND_TEST(ServiceTest, MeteredOverride);
  FRIEND_TEST(ServiceTest, PortalDetectionFailure);
  FRIEND_TEST(ServiceTest, RecheckPortal);
  FRIEND_TEST(ServiceTest, Save);
  FRIEND_TEST(ServiceTest, SaveAndLoadConnectionTimestamps);
  FRIEND_TEST(ServiceTest, SaveMeteredOverride);
  FRIEND_TEST(ServiceTest, SaveTrafficCounters);
  FRIEND_TEST(ServiceTest, SecurityLevel);
  FRIEND_TEST(ServiceTest, SetCheckPortal);
  FRIEND_TEST(ServiceTest, SetConnectableFull);
  FRIEND_TEST(ServiceTest, SetFriendlyName);
  FRIEND_TEST(ServiceTest, SetProxyConfig);
  FRIEND_TEST(ServiceTest, SetProperty);
  FRIEND_TEST(ServiceTest, State);
  FRIEND_TEST(ServiceTest, StateResetAfterFailure);
  FRIEND_TEST(ServiceTest, TrafficCounters);
  FRIEND_TEST(ServiceTest, UniqueAttributes);
  FRIEND_TEST(ServiceTest, Unload);
  FRIEND_TEST(ServiceTest, UserInitiatedConnectionResult);
  FRIEND_TEST(WiFiProviderTest, GetHiddenSSIDList);
  FRIEND_TEST(WiFiServiceTest, SetPassphraseResetHasEverConnected);
  FRIEND_TEST(WiFiServiceTest, SuspectedCredentialFailure);
  FRIEND_TEST(WiFiServiceTest, SetPassphraseRemovesCachedCredentials);
  FRIEND_TEST(WiFiServiceTest, LoadPassphraseClearCredentials);
  FRIEND_TEST(WiFiTimerTest, ReconnectTimer);
  FRIEND_TEST(WiFiMainTest, EAPEvent);  // For eap_.
  FRIEND_TEST(EthernetEapServiceTest, OnEapCredentialsChanged);

  static const size_t kEAPMaxCertificationElements;
  static const base::TimeDelta kMinAutoConnectCooldownTime;
  static const base::TimeDelta kMaxAutoConnectCooldownTime;
  static const uint64_t kAutoConnectCooldownBackoffFactor;

  static const int kDisconnectsMonitorSeconds;
  static const int kMisconnectsMonitorSeconds;
  static const int kReportDisconnectsThreshold;
  static const int kReportMisconnectsThreshold;
  static const int kMaxDisconnectEventHistory;
  static const int kMaxMisconnectEventHistory;

  bool GetAutoConnect(Error* error);

  std::string GetCheckPortal(Error* error);
  bool SetCheckPortal(const std::string& check_portal, Error* error);

  std::string GetGuid(Error* error);

  virtual RpcIdentifier GetDeviceRpcId(Error* error) const = 0;

  RpcIdentifier GetIPConfigRpcIdentifier(Error* error) const;

  std::string GetNameProperty(Error* error);
  // The base implementation asserts that |name| matches the current Name
  // property value.
  virtual bool SetNameProperty(const std::string& name, Error* error);

  int32_t GetPriority(Error* error);

  std::string GetProfileRpcId(Error* error);
  bool SetProfileRpcId(const std::string& profile, Error* error);

  std::string GetProxyConfig(Error* error);
  bool SetProxyConfig(const std::string& proxy_config, Error* error);

  Strings GetDisconnectsProperty(Error* error) const;
  Strings GetMisconnectsProperty(Error* error) const;

  uint64_t GetTrafficCounterResetTimeProperty(Error* error) const;

  uint64_t GetLastManualConnectAttemptProperty(Error* error) const;
  uint64_t GetLastConnectedProperty(Error* error) const;
  uint64_t GetLastOnlineProperty(Error* error) const;

  void SetLastManualConnectAttemptProperty(const base::Time& value);
  void SetLastConnectedProperty(const base::Time& value);
  void SetLastOnlineProperty(const base::Time& value);

  bool GetMeteredProperty(Error* error);
  bool SetMeteredProperty(const bool& metered, Error* error);
  void ClearMeteredProperty(Error* error);

  std::string GetONCSource(Error* error);
  bool SetONCSource(const std::string& source, Error* error);

  // Try to guess ONC Source in case it is not known.
  ONCSource ParseONCSourceFromUIData();

  void ReEnableAutoConnectTask();
  // Saves settings to current Profile, if we have one. Unlike
  // Manager::PersistService, SaveToProfile never assigns this Service to a
  // Profile.
  void SaveToProfile();

  // Make note of the fact that there was a problem connecting / staying
  // connected if the disconnection did not occur as a clear result of user
  // action.
  void NoteFailureEvent();

  // Report the result of user-initiated connection attempt to UMA stats.
  // Currently only report stats for wifi service.
  void ReportUserInitiatedConnectionResult(ConnectState state);

  // Linearize security parameters (crypto algorithm, key rotation, endpoint
  // authentication) for comparison.
  uint16_t SecurityLevel();

  // Get the storage key for current traffic counters corresponding
  // to |source| and |suffix| (one of kStorageTrafficCounterSuffixes).
  static std::string GetCurrentTrafficCounterKey(
      patchpanel::Client::TrafficSource source, std::string suffix);

  // Refreshes and processes the traffic counters using |counters| and returns
  // the result through |callback|.
  void RequestTrafficCountersCallback(
      ResultVariantDictionariesCallback callback,
      const std::vector<patchpanel::Client::TrafficCounter>& counters);

  // Invokes |static_ipconfig_changed_callback_| to notify the listener of the
  // change of static IP config.
  void NotifyStaticIPConfigChanged();

  // Getter for the SavedIPConfig property in D-Bus API.
  KeyValueStore GetSavedIPConfig(Error* /*error*/);

  // Requests to start portal detection if the Service is connected and
  // portal detection became enabled. Otherwise request to stop portal
  // detection if the Service is connected and portal detection became
  // disabled.
  void OnPortalDetectionConfigurationChange(bool restart,
                                            const std::string& reason);

  // WeakPtrFactory comes first, so that other fields can use it.
  base::WeakPtrFactory<Service> weak_ptr_factory_;

  ConnectState state_;
  ConnectState previous_state_;
  ConnectFailure failure_;
  bool auto_connect_;

  // Denotes whether the value of auto_connect_ property value should be
  // retained, i.e. only be allowed to change via explicit property changes
  // from the UI.
  bool retain_auto_connect_;

  // True if the device was visible on the last call to
  // NotifyIfVisibilityChanged().
  bool was_visible_;

  // Task to run Connect when a disconnection completes and a connection was
  // attempted while disconnecting. In the case that a distinct Connect
  // invocation occurs between disconnect completion and the invocation of this
  // task, this will be canceled to avoid spurious Connect errors.
  base::CancelableOnceClosure pending_connect_task_;

  std::string check_portal_;
  bool connectable_;
  std::string error_;
  std::string error_details_;
  std::string previous_error_;
  int32_t previous_error_serial_number_;
  bool explicitly_disconnected_;
  bool is_in_user_connect_;
  int32_t priority_;
  int32_t ephemeral_priority_ = 0;
  uint8_t crypto_algorithm_;
  bool key_rotation_;
  bool endpoint_auth_;
  std::string probe_url_string_;
  std::string portal_detection_failure_phase_;
  std::string portal_detection_failure_status_;
  int portal_detection_failure_status_code_;

  uint8_t strength_;
  std::string proxy_config_;
  std::string ui_data_;
  std::string guid_;
  bool save_credentials_;
  // If this is nullopt, try to infer whether or not this service is metered
  // by e.g. technology type.
  std::optional<bool> metered_override_;
  std::unique_ptr<EapCredentials> eap_;
  Technology technology_;
  // The time of the most recent failure. Value is null if the service is not
  // currently failed.
  base::Time failed_time_;
  // Whether or not this service has ever reached kStateConnected.
  bool has_ever_connected_;

  EventHistory disconnects_;  // Connection drops.
  EventHistory misconnects_;  // Failures to connect.

  base::CancelableOnceClosure reenable_auto_connect_task_;
  base::TimeDelta auto_connect_cooldown_;

  ProfileRefPtr profile_;
  PropertyStore store_;
  std::set<std::string> parameters_ignored_for_configure_;

  // A unique identifier for the service.
  unsigned int serial_number_;

  // List of subject names reported by remote entity during TLS setup.
  std::vector<std::string> remote_certification_;

  // The Network which is attached to this Service now, if there is any. Service
  // will push static IP configs to the attached network.
  base::WeakPtr<Network> attached_network_;

  std::unique_ptr<ServiceAdaptorInterface> adaptor_;
  StaticIPParameters static_ip_parameters_;
  Manager* manager_;

  // The |serial_number_| for the next Service.
  static unsigned int next_serial_number_;

  // When set to true, will not start link monitor when the connection to this
  // service is established.
  bool link_monitor_disabled_;
  // When set to true, the credentials for this service will be considered
  // valid, and will not require an initial connection to rank it highly for
  // auto-connect.
  bool managed_credentials_;
  // Flag indicating if this service is unreliable (experiencing multiple
  // link monitor failures in a short period of time).
  bool unreliable_;
  // Source of the service (user/policy).
  ONCSource source_;

  // Current traffic counter values.
  TrafficCounterMap current_traffic_counters_;
  // Snapshot of the counter values from the last time they were refreshed.
  TrafficCounterMap traffic_counter_snapshot_;
  // Represents when traffic counters were last reset.
  base::Time traffic_counter_reset_time_;

  // Counts the total number of portal detection attempts for the current active
  // connection.
  int portal_detection_count_ = 0;

  // Uplink and downlink speed for the service in Kbps.
  uint32_t uplink_speed_kbps_ = 0;
  uint32_t downlink_speed_kbps_ = 0;

  // Timestamps of last manual connect attempt, last successful connection and
  // last time online.
  base::Time last_manual_connect_attempt_;
  base::Time last_connected_;
  base::Time last_online_;
};

}  // namespace shill

#endif  // SHILL_SERVICE_H_
