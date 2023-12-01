// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MANAGER_H_
#define SHILL_MANAGER_H_

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/cancelable_callback.h>
#include <base/files/file_path.h>
#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>
#include <base/observer_list.h>
#include <base/strings/string_piece.h>
#include <chromeos/dbus/service_constants.h>
#include <chromeos/patchpanel/dbus/client.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/default_service_observer.h"
#include "shill/device.h"
#include "shill/device_info.h"
#include "shill/event_dispatcher.h"
#include "shill/geolocation_info.h"
#include "shill/hook_table.h"
#include "shill/metrics.h"
#include "shill/mockable.h"
#include "shill/network/network.h"
#include "shill/portal_detector.h"
#include "shill/power_manager.h"
#include "shill/profile.h"
#include "shill/provider_interface.h"
#include "shill/service.h"
#include "shill/store/property_store.h"
#include "shill/supplicant/supplicant_manager.h"
#include "shill/tethering_manager.h"
#include "shill/upstart/upstart.h"

namespace shill {

#if !defined(DISABLE_FLOSS)
class BluetoothManagerInterface;
#endif  // DISABLE_FLOSS
class CellularServiceProvider;
class ControlInterface;
class DefaultProfile;
class Error;
class EthernetEapProvider;
class EthernetProvider;
class EventDispatcher;
class ManagerAdaptorInterface;
class ModemInfo;
class Resolver;
class Throttler;
class VPNProvider;
class WiFiProvider;

// Helper class for storing in memory the set of shill Manager DBUS R or RW
// DBus properties.
// TODO(hugobenichi): simplify access patterns to the Manager properties and
// remove virtual mockable getter functions in Manager.
struct ManagerProperties {
  // Comma separated list of technologies for which portal detection is
  // enabled.
  std::string check_portal_list;
  // URL used for the first HTTP probe sent by PortalDetector on a new network
  // connection.
  std::string portal_http_url;
  // URL used for the first HTTPS probe sent by PortalDetector on a new
  // network connection.
  std::string portal_https_url;
  // Set of fallback URLs used for retrying the HTTP probe when portal
  // detection is not conclusive.
  std::vector<std::string> portal_fallback_http_urls;
  // Set of fallback URLs used for retrying the HTTPS probe when portal
  // detection is not conclusive.
  std::vector<std::string> portal_fallback_https_urls;
  // Whether to ARP for the default gateway in the DHCP client after
  // acquiring a lease.
  bool arp_gateway = true;
  // Whether DHCP client should request for IPv6-only mode on a capable network.
  bool enable_rfc_8925 = false;
  // Comma-separated list of technologies for which auto-connect is disabled.
  std::string no_auto_connect_technologies;
  // Comma-separated list of technologies that should never be enabled.
  std::string prohibited_technologies;
  // Comma-separated list of DNS search paths to be ignored.
  std::string ignored_dns_search_paths;
  // Name of Android VPN package that should be enforced for user traffic.
  // Empty string if the lockdown feature is not enabled.
  std::string always_on_vpn_package;
  // The IPv4 and IPv6 addresses of the DNS Proxy, if applicable. When these
  // values are set, resolv.conf should use these addresses as the name
  // servers.
  std::vector<std::string> dns_proxy_addresses;
  // Maps DNS-over-HTTPS service providers to a list of standard DNS name
  // servers. This member stores the value set via the DBus
  // |DNSProxyDOHProviders| property.
  KeyValueStore dns_proxy_doh_providers;
  // Hostname to be used in DHCP request.
  std::string dhcp_hostname;
  std::optional<bool> ft_enabled;
  bool scan_allow_roam = true;
};

class Manager {
 public:
  Manager(ControlInterface* control_interface,
          EventDispatcher* dispatcher,
          Metrics* metrics,
          const std::string& run_directory,
          const std::string& storage_directory,
          const std::string& user_storage_directory);
  Manager(const Manager&) = delete;
  Manager& operator=(const Manager&) = delete;

  virtual ~Manager();

  void RegisterAsync(base::OnceCallback<void(bool)> completion_callback);

  virtual void SetBlockedDevices(
      const std::vector<std::string>& blockeded_devices);
  virtual void SetAllowedDevices(
      const std::vector<std::string>& allowed_devices);

  // Returns true if |device_name| is either not in the blocked list, or in the
  // allowed list, depending on which list was supplied in startup settings.
  virtual bool DeviceManagementAllowed(const std::string& device_name);

  virtual void Start();
  virtual void Stop();
  bool running() const { return running_; }

  // Requests for Services to be resorted; this method returns immediately
  // without actually performing the sorting.
  void SortServices();

  virtual const ProfileRefPtr& ActiveProfile() const;
  bool IsActiveProfile(const ProfileRefPtr& profile) const;
  virtual bool MoveServiceToProfile(const ServiceRefPtr& to_move,
                                    const ProfileRefPtr& destination);
  virtual bool MatchProfileWithService(const ServiceRefPtr& service);
  ProfileRefPtr LookupProfileByRpcIdentifier(const std::string& profile_rpcid);

  // Called via RPC call on Service (|to_set|) to set the "Profile" property.
  virtual void SetProfileForService(const ServiceRefPtr& to_set,
                                    const std::string& profile,
                                    Error* error);

  virtual void RegisterDevice(const DeviceRefPtr& to_manage);
  virtual void DeregisterDevice(const DeviceRefPtr& to_forget);

  virtual bool HasService(const ServiceRefPtr& service);
  // Register a Service with the Manager. Manager may choose to
  // connect to it immediately.
  virtual void RegisterService(const ServiceRefPtr& to_manage);
  // Deregister a Service from the Manager. Caller is responsible
  // for disconnecting the Service before-hand.
  virtual void DeregisterService(const ServiceRefPtr& to_forget);
  virtual void UpdateService(const ServiceRefPtr& to_update);
  // Called when any service's state changes.  Informs other services
  // (e.g. VPNs) if the default physical service's state has changed.
  virtual void NotifyServiceStateChanged(const ServiceRefPtr& to_update);

  // Persists |to_update| into an appropriate profile.
  virtual void UpdateDevice(const DeviceRefPtr& to_update);

  virtual std::vector<DeviceRefPtr> FilterByTechnology(Technology tech) const;

  RpcIdentifiers EnumerateAvailableServices(Error* error);

  // Return the complete list of services, including those that are not visible.
  RpcIdentifiers EnumerateCompleteServices(Error* error);

  // called via RPC (e.g., from ManagerDBusAdaptor)
  std::map<RpcIdentifier, std::string> GetLoadableProfileEntriesForService(
      const ServiceConstRefPtr& service);
  ServiceRefPtr GetService(const KeyValueStore& args, Error* error);
  ServiceRefPtr ConfigureService(const KeyValueStore& args, Error* error);
  ServiceRefPtr ConfigureServiceForProfile(const std::string& profile_rpcid,
                                           const KeyValueStore& args,
                                           Error* error);
  ServiceRefPtr FindMatchingService(const KeyValueStore& args, Error* error);

  // Return the Device that has selected this Service. If no Device has selected
  // this Service or the Service pointer is null, return nullptr. Note that
  // VirtualDevices which are not managed by Manager will also be included here.
  virtual DeviceRefPtr FindDeviceFromService(
      const ServiceRefPtr& service) const;

  // It the service has an active Network, returns the Network object associated
  // with the Device which has selected this Service. This pointer is owned by
  // Device and thus cannot be held. Returns nullptr if no such Network or the
  // Service pointer is null.
  mockable Network* FindActiveNetworkFromService(
      const ServiceRefPtr& service) const;

  // Return the highest priority service of a physical technology type (i.e. not
  // VPN, ARC, etc), or nullptr if no such service is found.
  virtual ServiceRefPtr GetPrimaryPhysicalService();
  // Return the first service of type |Technology::kEthernet| found in
  // |services_|, or nullptr if no such service is found.
  virtual ServiceRefPtr GetFirstEthernetService();

  // Retrieve geolocation data from the Manager.
  std::map<std::string, std::vector<GeolocationInfo>>
  GetNetworksForGeolocation() const;

  // Called by Device when its geolocation data has been updated.
  virtual void OnDeviceGeolocationInfoUpdated(const DeviceRefPtr& device);

  // Force a wifi scan if applicable, and connect to the best available
  // services.
  // Called by chrome when a user profile is loaded and the user's
  // policy-provided networks are configured.
  void ScanAndConnectToBestServices(Error* error);

  // For WiFi services, connect to the "best" service available,  as determined
  // by sorting all services independent of their current state.
  mockable void ConnectToBestWiFiService();

  // Method to create connectivity report for connected services.
  void CreateConnectivityReport(Error* error);

  // Request portal detection checks on each registered device with a connected
  // Service.
  void RecheckPortal(Error* error);

  // Request WiFi device to be restarted. This is to be solely used to track
  // b/270746800 and should not be invoked otherwise. TODO(b/278765529) Once the
  // issue is is no longer reproducing, this will be removed.
  virtual void RequestWiFiRestart(Error* error);

  virtual void RequestScan(const std::string& technology, Error* error);
  std::string GetTechnologyOrder();
  virtual void SetTechnologyOrder(const std::string& order, Error* error);
  // Set up the profile list starting with a default profile along with
  // an (optional) list of startup profiles.
  void InitializeProfiles();
  // Create a profile.  This does not affect the profile stack.  Returns
  // the RPC path of the created profile in |path|.
  void CreateProfile(const std::string& name, std::string* path, Error* error);
  // Pushes existing profile with name |name| onto stack of managed profiles.
  // Returns the RPC path of the pushed profile in |path|.
  void PushProfile(const std::string& name, std::string* path, Error* error);
  // Insert an existing user profile with name |name| into the stack of
  // managed profiles.  Associate |user_hash| with this profile entry.
  // Returns the RPC path of the pushed profile in |path|.
  void InsertUserProfile(const std::string& name,
                         const std::string& user_hash,
                         std::string* path,
                         Error* error);
  // Pops profile named |name| off the top of the stack of managed profiles.
  void PopProfile(const std::string& name, Error* error);
  // Remove the active profile.
  void PopAnyProfile(Error* error);
  // Remove all user profiles from the stack of managed profiles leaving only
  // default profiles.
  void PopAllUserProfiles(Error* error);
  // Remove the underlying persistent storage for a profile.
  void RemoveProfile(const std::string& name, Error* error);
  // Called by a profile when its properties change.
  void OnProfileChanged(const ProfileRefPtr& profile);
  // Let shill stop managing |interface_name|.
  virtual void ClaimDevice(const std::string& interface_name, Error* error);
  // Let shill manage |interface_name| again.
  virtual void ReleaseDevice(const std::string& interface_name, Error* error);

  // Called by a service to remove its associated configuration.  If |service|
  // is associated with a non-ephemeral profile, this configuration entry
  // will be removed and the manager will search for another matching profile.
  // If the service ends up with no matching profile, it is unloaded (which
  // may also remove the service from the manager's list, e.g. WiFi services
  // that are not visible)..
  virtual void RemoveService(const ServiceRefPtr& service);
  // Handle the event where a profile is about to remove a profile entry.
  // Any Services that are dependent on this storage identifier will need
  // to find new profiles.  Return true if any service has been moved to a new
  // profile.  Any such services will have had the profile group removed from
  // the profile.
  virtual bool HandleProfileEntryDeletion(const ProfileRefPtr& profile,
                                          const std::string& entry_name);
  // Find a registered service that contains a GUID property that
  // matches |guid|.
  virtual ServiceRefPtr GetServiceWithGUID(const std::string& guid,
                                           Error* error);
  // Find a service that has a storage identifier that matches |entry_name|.
  virtual ServiceRefPtr GetServiceWithStorageIdentifier(
      const std::string& entry_name);
  // Find a service that is both the member of |profile| and has a
  // storage identifier that matches |entry_name|.  This function is
  // called by the Profile in order to return a profile entry's properties.
  virtual ServiceRefPtr GetServiceWithStorageIdentifierFromProfile(
      const ProfileRefPtr& profile,
      const std::string& entry_name,
      Error* error);
  // Find a service that has a RpcIdentifier that matches |id|.
  virtual ServiceRefPtr GetServiceWithRpcIdentifier(const RpcIdentifier& id);
  // Create a temporary service for an entry |entry_name| within |profile|.
  // Callers must not register this service with the Manager or connect it
  // since it was never added to the provider's service list.
  virtual ServiceRefPtr CreateTemporaryServiceFromProfile(
      const ProfileRefPtr& profile,
      const std::string& entry_name,
      Error* error);
  // Return a reference to the Service associated with the default connection.
  // If there is no such connection, this function returns a reference to NULL.
  virtual ServiceRefPtr GetDefaultService() const;
  RpcIdentifier GetDefaultServiceRpcIdentifier(Error* error);

  // Set enabled state of all |technology_name| devices to |enabled_state|.
  // Persist the state to storage is |persist| is true.
  void SetEnabledStateForTechnology(const std::string& technology_name,
                                    bool enabled_state,
                                    bool persist,
                                    ResultCallback callback);
  // Return whether a technology is marked as enabled for portal detection.
  virtual bool IsPortalDetectionEnabled(Technology tech);

  // Returns true if profile |a| has been pushed on the Manager's
  // |profiles_| stack before profile |b|.
  virtual bool IsProfileBefore(const ProfileRefPtr& a,
                               const ProfileRefPtr& b) const;

  // Return whether a service belongs to the ephemeral profile.
  virtual bool IsServiceEphemeral(const ServiceConstRefPtr& service) const;

  // Return whether a Technology has any connected Services.
  virtual bool IsTechnologyConnected(Technology technology) const;

  // Return whether the Wake on LAN feature is enabled.
  virtual bool IsWakeOnLanEnabled() const { return is_wake_on_lan_enabled_; }

  // Return whether a technology is disabled for auto-connect.
  virtual bool IsTechnologyAutoConnectDisabled(Technology technology) const;

  // Report whether |technology| is prohibited from being enabled.
  virtual bool IsTechnologyProhibited(Technology technology) const;

  // Called by Profile when a |storage| completes initialization.
  void OnProfileStorageInitialized(Profile* storage);

  // Return a Device with technology |technology| in the enabled state.
  virtual DeviceRefPtr GetEnabledDeviceWithTechnology(
      Technology technology) const;

  // Returns true if at least one connection exists, and false if there's no
  // connected service.
  virtual bool IsConnected() const;
  // Returns true if at least one connection exists that have Internet
  // connectivity, and false if there's no such service.
  virtual bool IsOnline() const;
  std::string CalculateState(Error* error);

  // Recalculate the |connected_state_| string and emit a singal if it has
  // changed.
  void RefreshConnectionState();

  virtual DeviceInfo* device_info() { return &device_info_; }
  virtual ModemInfo* modem_info() { return modem_info_.get(); }
  virtual CellularServiceProvider* cellular_service_provider() {
    return cellular_service_provider_.get();
  }
  PowerManager* power_manager() const { return power_manager_.get(); }
  virtual EthernetProvider* ethernet_provider() {
    return ethernet_provider_.get();
  }
  virtual EthernetEapProvider* ethernet_eap_provider() const {
    return ethernet_eap_provider_.get();
  }
  VPNProvider* vpn_provider() const { return vpn_provider_.get(); }
  WiFiProvider* wifi_provider() const { return wifi_provider_.get(); }
  PropertyStore* mutable_store() { return &store_; }
  virtual const PropertyStore& store() const { return store_; }
  virtual const base::FilePath& run_path() const { return run_path_; }
  const base::FilePath& storage_path() const { return storage_path_; }

  const base::ObserverList<DefaultServiceObserver>& default_service_observers()
      const {
    return default_service_observers_;
  }

  virtual int64_t GetSuspendDurationUsecs() const {
    return power_manager_->suspend_duration_us();
  }

  virtual const ManagerProperties& GetProperties() const { return props_; }
  PortalDetector::ProbingConfiguration GetPortalDetectorProbingConfiguration()
      const;

  // Creates a default DHCP Options object using the DHCP Manager properties.
  mockable DHCPProvider::Options CreateDefaultDHCPOption() const;

  virtual void UpdateEnabledTechnologies();
  virtual void UpdateUninitializedTechnologies();

  // Writes the Service |to_update| to persistent storage. If the Service is
  // ephemeral, it is moved to the current Profile.
  void PersistService(const ServiceRefPtr& to_update);

  // Adds a closure to be executed when ChromeOS suspends or shill terminates.
  // |name| should be unique; otherwise, a previous closure by the same name
  // will be replaced.  |start| will be called when RunTerminationActions() is
  // called.  When an action completed, TerminationActionComplete() must be
  // called.
  void AddTerminationAction(const std::string& name, base::OnceClosure start);

  // Users call this function to report the completion of an action |name|.
  // This function should be called once for each action.
  void TerminationActionComplete(const std::string& name);

  // Removes the action associtated with |name|.
  void RemoveTerminationAction(const std::string& name);

  // Runs the termination actions and notifies the metrics framework
  // that the termination actions started running, only if any termination
  // actions have been registered. If all actions complete within
  // |kTerminationActionsTimeoutMilliseconds|, |done_callback| is called with a
  // value of Error::kSuccess. Otherwise, it is called with
  // Error::kOperationTimeout.
  //
  // Returns true, if termination actions were run.
  bool RunTerminationActionsAndNotifyMetrics(ResultCallback done_callback);

  // Add/remove observers to subscribe to default Service notifications.
  void AddDefaultServiceObserver(DefaultServiceObserver* observer);
  void RemoveDefaultServiceObserver(DefaultServiceObserver* observer);

  // Decides whether Ethernet-like devices are treated as unknown devices
  // if they do not indicate a driver name.
  virtual void SetIgnoreUnknownEthernet(bool ignore);
  virtual bool ignore_unknown_ethernet() const {
    return ignore_unknown_ethernet_;
  }

  // Returns true iff |power_manager_| exists and is suspending (i.e.
  // power_manager->suspending() is true), false otherwise.
  virtual bool IsSuspending();

  void set_suppress_autoconnect(bool val) { suppress_autoconnect_ = val; }
  bool suppress_autoconnect() const { return suppress_autoconnect_; }

  RpcIdentifiers EnumerateDevices(Error* error);

  bool SetNetworkThrottlingStatus(ResultCallback callback,
                                  bool enabled,
                                  uint32_t upload_rate_kbits,
                                  uint32_t download_rate_kbits);

  // Returns the interface names associated with 'real' devices
  // on the system e.g. eth0, wlan0.
  virtual std::vector<std::string> GetDeviceInterfaceNames();

  bool GetFTEnabled(Error* error);
  bool scan_allow_roam() const { return props_.scan_allow_roam; }

  ControlInterface* control_interface() const { return control_interface_; }
  EventDispatcher* dispatcher() const { return dispatcher_; }
  Metrics* metrics() const { return metrics_; }
  SupplicantManager* supplicant_manager() const {
    return supplicant_manager_.get();
  }
  void set_patchpanel_client_for_testing(
      std::unique_ptr<patchpanel::Client> patchpanel_client) {
    patchpanel_client_ = std::move(patchpanel_client);
  }
  patchpanel::Client* patchpanel_client() { return patchpanel_client_.get(); }

  // Assigns the IP address(es) of the dns-proxy service.
  bool SetDNSProxyAddresses(const std::vector<std::string>& addrs,
                            Error* error);

  // Clears the IP address of the dns-proxy service.
  void ClearDNSProxyAddresses();

  // Assigns the DNS-over-HTTPS service providers for use by the dns-proxy
  // service.
  bool SetDNSProxyDOHProviders(const KeyValueStore& providers, Error* error);

  // Creates a set of Passpoint credentials from |properties| in the profile
  // referenced by |profile_id|.
  bool AddPasspointCredentials(const std::string& profile_rpcid,
                               const KeyValueStore& properties,
                               Error* error);

  // Removes all Passpoint credentials that matches all property of |properties|
  // in the profile referenced by |profile_id|.
  bool RemovePasspointCredentials(const std::string& profile_rpcid,
                                  const KeyValueStore& properties,
                                  Error* error);

  // Enable or disable a local only hotspot session.
  void SetLOHSEnabled(base::OnceCallback<void(std::string result)> callback,
                      bool enabled);

  // Getter and setter for the |LOHSConfig| property to be used for a local only
  // hotspot session.
  KeyValueStore GetLOHSConfig(Error* error);
  bool SetLOHSConfig(const KeyValueStore& properties, Error* error);

  TetheringManager* tethering_manager() const {
    return tethering_manager_.get();
  }

#if !defined(DISABLE_FLOSS)
  BluetoothManagerInterface* bluetooth_manager() const {
    return bluetooth_manager_.get();
  }
#endif  // DISABLE_FLOSS

  // Emit TetheringStatus dbus property change signal.
  mockable void TetheringStatusChanged();

 private:
  friend class ArcVpnDriverTest;
  friend class CellularTest;
  friend class DeviceInfoTest;
  friend class DeviceTest;
  friend class HotspotDeviceTest;
  friend class L2TPIPsecDriverTest;
  friend class ManagerAdaptorInterface;
  friend class ManagerTest;
  friend class ModemInfoTest;
  friend class ModemManagerTest;
  friend class OpenVPNDriverTest;
  friend class ServiceTest;
  friend class TetheringManagerTest;
  friend class VPNServiceTest;
  friend class WiFiObjectTest;
  friend class DaemonTaskTest;

  FRIEND_TEST(CellularCapability3gppTest, TerminationAction);
  FRIEND_TEST(CellularCapability3gppTest, TerminationActionRemovedByStopModem);
  FRIEND_TEST(CellularTest, LinkEventWontDestroyService);
  FRIEND_TEST(DefaultProfileTest, LoadManagerDefaultProperties);
  FRIEND_TEST(DefaultProfileTest, LoadManagerProperties);
  FRIEND_TEST(DefaultProfileTest, Save);
  FRIEND_TEST(DeviceInfoTest, CreateDeviceEthernet);
  FRIEND_TEST(DeviceTest, StartProhibited);
  FRIEND_TEST(ManagerTest, AvailableTechnologies);
  FRIEND_TEST(ManagerTest, ClaimBlockedDevice);
  FRIEND_TEST(ManagerTest, ClaimDevice);
  FRIEND_TEST(ManagerTest, ConnectedTechnologies);
  FRIEND_TEST(ManagerTest, ScanAndConnectToBestServices);
  FRIEND_TEST(ManagerTest, CreateConnectivityReport);
  FRIEND_TEST(ManagerTest, DefaultTechnology);
  FRIEND_TEST(ManagerTest, DefaultServiceStateChange);
  FRIEND_TEST(ManagerTest, DevicePresenceStatusCheck);
  FRIEND_TEST(ManagerTest, DeviceRegistrationAndStart);
  FRIEND_TEST(ManagerTest, DeviceRegistrationTriggersThrottler);
  FRIEND_TEST(ManagerTest, EnumerateProfiles);
  FRIEND_TEST(ManagerTest, EnumerateServiceInnerDevices);
  FRIEND_TEST(ManagerTest, InitializeProfilesInformsProviders);
  FRIEND_TEST(ManagerTest, InitializeProfilesHandlesDefaults);
  FRIEND_TEST(ManagerTest, IsTechnologyAutoConnectDisabled);
  FRIEND_TEST(ManagerTest, IsTechnologyProhibited);
  FRIEND_TEST(ManagerTest, IsWifiIdle);
  FRIEND_TEST(ManagerTest, LinkMonitorEnabled);
  FRIEND_TEST(ManagerTest, MoveService);
  FRIEND_TEST(ManagerTest, UpdateDefaultServices);
  FRIEND_TEST(ManagerTest, UpdateDefaultServicesDNSProxy);
  FRIEND_TEST(ManagerTest,
              UpdateDefaultServicesWithDefaultServiceCallbacksRemoved);
  FRIEND_TEST(ManagerTest, RefreshAllTrafficCountersTask);
  FRIEND_TEST(ManagerTest, RegisterKnownService);
  FRIEND_TEST(ManagerTest, RegisterUnknownService);
  FRIEND_TEST(ManagerTest, ReleaseBlockedDevice);
  FRIEND_TEST(ManagerTest, RequestWiFiRestart);
  FRIEND_TEST(ManagerTest, RunTerminationActions);
  FRIEND_TEST(ManagerTest, ServiceRegistration);
  FRIEND_TEST(ManagerTest, SetAlwaysOnVpnPackage);
  FRIEND_TEST(ManagerTest, SetCheckPortalListProp);
  FRIEND_TEST(ManagerTest, SortServicesWithConnection);
  FRIEND_TEST(ManagerTest, SetDNSProxyAddresses);
  FRIEND_TEST(ManagerTest, TetheringLoadAndUnloadConfiguration);
  FRIEND_TEST(ServiceTest, IsAutoConnectable);
  FRIEND_TEST(ThirdPartyVpnDriverTest, SetParameters);
  FRIEND_TEST(VPNProviderTest, SetDefaultRoutingPolicy);
  FRIEND_TEST(WiFiServiceTest, ConnectTaskFT);
  FRIEND_TEST(WiFiMainTest, ScanAllowRoam);
  FRIEND_TEST(WiFiMainTest, UpdateGeolocationObjects);
  FRIEND_TEST(DaemonTaskTest, SupplicantAppearsAfterStop);

  void AutoConnect();
  // Ensure always-on VPN follows the current configuration, ie: hardware
  // connectivity is available and the correct VPN service is running.
  void ApplyAlwaysOnVpn(const ServiceRefPtr& physical_service);
  // Update always-on VPN configuration with the one contained in |profile|.
  void UpdateAlwaysOnVpnWith(const ProfileRefPtr& profile);
  // Set the always-on VPN configuration and start or stop VPN lockdown if
  // needed.
  // TODO(b/188864779) Generalize to support both setups of always-on VPNService
  // and legacy ARC++ always-on VPN package name property.
  void SetAlwaysOnVpn(const std::string& mode, VPNServiceRefPtr service);
  // Connect the always-on VPN and maintain the previous connection attempts
  // count.
  void ConnectAlwaysOnVpn();
  // Reset the connection backoff to its initial state.  Used on a successful
  // attempt or a physical network change for instance.
  void ResetAlwaysOnVpnBackoff();
  bool IsServiceAlwaysOnVpn(const ServiceConstRefPtr& service) const;
  std::vector<std::string> AvailableTechnologies(Error* error);
  std::vector<std::string> ConnectedTechnologies(Error* error);
  std::string DefaultTechnology(Error* error);
  std::vector<std::string> EnabledTechnologies(Error* error);
  std::vector<std::string> UninitializedTechnologies(Error* error);
  RpcIdentifiers EnumerateProfiles(Error* error);
  RpcIdentifiers EnumerateWatchedServices(Error* error);
  RpcIdentifier GetActiveProfileRpcIdentifier(Error* error);
  std::string GetCheckPortalList(Error* error);
  std::string GetIgnoredDNSSearchPaths(Error* error);
  std::string GetPortalFallbackHttpUrls(Error* error);
  std::string GetPortalFallbackHttpsUrls(Error* error);
  ServiceRefPtr GetServiceInner(const KeyValueStore& args, Error* error);
  // TODO(b/188864779) Migrate to a Profile property and migrate the storage
  // from Chrome to shill.
  bool SetAlwaysOnVpnPackage(const std::string& package_name, Error* error);
  bool SetCheckPortalList(const std::string& portal_list, Error* error);
  bool SetIgnoredDNSSearchPaths(const std::string& ignored_paths, Error* error);
  bool SetPortalFallbackHttpUrls(const std::string& urls, Error* error);
  bool SetPortalFallbackHttpsUrls(const std::string& urls, Error* error);
  // Emit a kDefaultServiceProperty property-changed D-Bus signal if the default
  // Service has changed. Returns true only if the default Service did actually
  // change.
  bool EmitDefaultService();
  bool IsTechnologyInList(const std::string& technology_list,
                          Technology tech) const;
  void EmitDeviceProperties();
  bool SetDisableWiFiVHT(const bool& disable_wifi_vht, Error* error);
  bool GetDisableWiFiVHT(Error* error);

  bool SetFTEnabled(const bool& ft_enabled, Error* error);
  bool SetProhibitedTechnologies(const std::string& prohibited_technologies,
                                 Error* error);
  std::string GetProhibitedTechnologies(Error* error);
  void OnTechnologyProhibited(Technology technology, const Error& error);

  void UseDNSProxy(const std::vector<std::string>& proxy_addrs);

  KeyValueStore GetDNSProxyDOHProviders(Error* error);

  // Unload a service while iterating through |services_|.  Returns true if
  // service was erased (which means the caller loop should not increment
  // |service_iterator|), false otherwise (meaning the caller should
  // increment |service_iterator|).
  bool UnloadService(std::vector<ServiceRefPtr>::iterator* service_iterator);

  // Load Manager default properties from |profile|.
  void LoadProperties(const scoped_refptr<DefaultProfile>& profile);

  // Configure the device with profile data from all current profiles.
  void LoadDeviceFromProfiles(const DeviceRefPtr& device);

  void HelpRegisterConstDerivedRpcIdentifier(
      base::StringPiece name, RpcIdentifier (Manager::*get)(Error*));
  void HelpRegisterConstDerivedRpcIdentifiers(
      base::StringPiece name, RpcIdentifiers (Manager::*get)(Error*));
  void HelpRegisterDerivedString(base::StringPiece name,
                                 std::string (Manager::*get)(Error* error),
                                 bool (Manager::*set)(const std::string&,
                                                      Error*));
  void HelpRegisterConstDerivedStrings(base::StringPiece name,
                                       Strings (Manager::*get)(Error*));
  void HelpRegisterDerivedKeyValueStore(
      base::StringPiece name,
      KeyValueStore (Manager::*get)(Error* error),
      bool (Manager::*set)(const KeyValueStore& value, Error* error));
  void HelpRegisterDerivedBool(base::StringPiece name,
                               bool (Manager::*get)(Error* error),
                               bool (Manager::*set)(const bool& value,
                                                    Error* error));

  bool HasProfile(const Profile::Identifier& ident);
  void PushProfileInternal(const Profile::Identifier& ident,
                           std::string* path,
                           Error* error);
  void PopProfileInternal();
  void OnProfilesChanged();

  void SortServicesTask();
  void DeviceStatusCheckTask();
  void DevicePresenceStatusCheck();

  // Sets the profile of |service| to |profile|, without notifying its
  // previous profile.  Configures a |service| with |args|, then saves
  // the resulting configuration to |profile|.  This method is useful
  // when copying a service configuration from one profile to another,
  // or writing a newly created service config to a specific profile.
  static void SetupServiceInProfile(ServiceRefPtr service,
                                    ProfileRefPtr profile,
                                    const KeyValueStore& args,
                                    Error* error);

  // For either WiFi or all other technologies available, connect to the "best"
  // service available, as determined by sorting all services independent of
  // their current state.
  void ConnectToBestServicesForTechnologies(bool is_wifi);

  void UpdateDefaultServices(const ServiceRefPtr& logical_service,
                             const ServiceRefPtr& physical_service);

  // Runs the termination actions.  If all actions complete within
  // |kTerminationActionsTimeoutMilliseconds|, |done_callback| is called with a
  // value of Error::kSuccess.  Otherwise, it is called with
  // Error::kOperationTimeout.
  void RunTerminationActions(ResultCallback done_callback);

  // Called when the system is about to be suspended.  Each call will be
  // followed by a call to OnSuspendDone().
  void OnSuspendImminent();

  // Called when the system has completed a suspend attempt (possibly without
  // actually suspending, in the event of the user canceling the attempt).
  void OnSuspendDone();

  // Called when the system is entering a dark resume phase (and hence a dark
  // suspend is imminent).
  void OnDarkSuspendImminent();

  void OnSuspendActionsComplete(const Error& error);
  void OnDarkResumeActionsComplete(const Error& error);

  // Return true if wifi device is enabled with no existing connection (pending
  // or connected).
  bool IsWifiIdle();

  // For unit testing.
  void set_metrics(Metrics* metrics) { metrics_ = metrics; }
  void UpdateProviderMapping();

  // Used by tests to set a mock PowerManager.  Takes ownership of
  // power_manager.
  void set_power_manager(PowerManager* power_manager) {
    power_manager_.reset(power_manager);
  }

  DeviceRefPtr GetDeviceConnectedToService(ServiceRefPtr service);

  void DeregisterDeviceByLinkName(const std::string& link_name);

  std::string GetAlwaysOnVpnPackage(Error* error);

  // Initializes patchpanel_client_ if it has not already been initialized.
  void InitializePatchpanelClient();

  void RefreshAllTrafficCountersCallback(
      const std::vector<patchpanel::Client::TrafficCounter>& counters);
  void RefreshAllTrafficCountersTask();

  // Returns the names of all of the claimed devices by ClaimDevice().
  std::vector<std::string> ClaimedDevices(Error* error);

  EventDispatcher* dispatcher_;
  ControlInterface* control_interface_;
  Metrics* metrics_;

  const base::FilePath run_path_;
  const base::FilePath storage_path_;
  const base::FilePath user_storage_path_;
  base::FilePath user_profile_list_path_;  // Changed in tests.
  std::unique_ptr<ManagerAdaptorInterface> adaptor_;
  DeviceInfo device_info_;
  std::unique_ptr<ModemInfo> modem_info_;
  std::unique_ptr<CellularServiceProvider> cellular_service_provider_;
  std::unique_ptr<EthernetProvider> ethernet_provider_;
  std::unique_ptr<EthernetEapProvider> ethernet_eap_provider_;
  std::unique_ptr<VPNProvider> vpn_provider_;
  std::unique_ptr<WiFiProvider> wifi_provider_;
  std::unique_ptr<SupplicantManager> supplicant_manager_;
  // For communication with patchpanel.
  std::unique_ptr<patchpanel::Client> patchpanel_client_;

  // Entity that calls kernel commands ('tc') to throttle network bandwidth.
  std::unique_ptr<Throttler> throttler_;

  // Hold pointer to singleton Resolver instance for testing purposes.
  Resolver* resolver_;
  bool running_;
  std::vector<DeviceRefPtr> devices_;
  // We store Services in a vector, because we want to keep them sorted.
  // Services that are connected appear first in the vector.  See
  // Service::Compare() for details of the sorting criteria.
  std::vector<ServiceRefPtr> services_;
  // Last known default physical service (i.e. not a VPN).  Used to figure
  // out when to send the DefaultServiceChanged notification.
  ServiceRefPtr last_default_physical_service_;
  bool last_default_physical_service_online_;
  // Current always-on VPN operating mode.
  std::string always_on_vpn_mode_;
  // Reference to the VPN service managed by always-on VPN.  It may reference
  // nothing if there's no service configured, otherwise it heads to a
  // VPNService.
  VPNServiceRefPtr always_on_vpn_service_;
  // Count of always-on VPN service connection attempts since the last reset.
  uint32_t always_on_vpn_connect_attempts_;
  // Task to connect always-on VPN service.
  base::CancelableOnceClosure always_on_vpn_connect_task_;
  // Map of technologies to Provider instances.  These pointers are owned
  // by the respective scoped_reptr objects that are held over the lifetime
  // of the Manager object.
  std::map<Technology, ProviderInterface*> providers_;
  // List of startup profile names to push on the profile stack on startup.
  std::vector<ProfileRefPtr> profiles_;
  ProfileRefPtr ephemeral_profile_;
  std::unique_ptr<PowerManager> power_manager_;
  std::unique_ptr<Upstart> upstart_;
#if !defined(DISABLE_FLOSS)
  std::unique_ptr<BluetoothManagerInterface> bluetooth_manager_;
#endif  // DISABLE_FLOSS

  // The priority order of technologies
  std::vector<Technology> technology_order_;

  // This is the last Service RPC Identifier for which we emitted a
  // "DefaultService" signal for.
  RpcIdentifier default_service_rpc_identifier_;

  // Properties to be get/set via PropertyStore calls.
  ManagerProperties props_;
  PropertyStore store_;

  base::CancelableOnceClosure sort_services_task_;

  // Task for periodically checking various device status.
  base::CancelableOnceClosure device_status_check_task_;

  // Task for initializing patchpanel connection.
  base::CancelableOnceClosure init_patchpanel_client_task_;

  // Task for periodically refreshing traffic counters.
  base::CancelableOnceClosure refresh_traffic_counter_task_;

  // Whether we're currently waiting on a traffic counter fetch from patchpanel.
  bool pending_traffic_counter_request_;

  // Actions to take when shill is terminating.
  HookTable termination_actions_;

  // Whether Wake on LAN should be enabled for all Ethernet devices.
  bool is_wake_on_lan_enabled_;

  // Whether to ignore Ethernet-like devices that don't have an assigned driver.
  bool ignore_unknown_ethernet_;

  // List of DefaultServiceObservers registered with AddDefaultServiceObserver.
  base::ObserverList<DefaultServiceObserver> default_service_observers_;

  // Stores the most recent copy of geolocation information for each
  // device the manager is keeping track of.
  std::map<DeviceConstRefPtr, std::vector<GeolocationInfo>>
      device_geolocation_info_;

  // Stores the state of the highest ranked connected service.
  std::string connection_state_;

  // Stores the most recent state of all watched services by serial number.
  std::map<unsigned int, Service::ConnectState> watched_service_states_;

  // When true, suppresses autoconnects in Manager::AutoConnect.
  bool suppress_autoconnect_;

  // Whether any of the services is in connected state or not.
  bool is_connected_state_;

  // Set to true if there is a user session, which is inferred based on calls
  // to Manager::InsertUserProfile() and Manager::PopAllUserProfiles().
  bool has_user_session_;

  // List of blocked devices specified from command line.
  std::vector<std::string> blocked_devices_;

  // List of allowed devices specified from command line.
  std::vector<std::string> allowed_devices_;

  // List of devices claimed by other processes via ClaimerInterface D-Bus API.
  std::set<std::string> claimed_devices_;

  // List of supported vpn types;
  std::string supported_vpn_;

  // Bandwidth throttling variables. Default values are overridden by
  // SetNetworkThrottlingStatus, called from the client.
  bool network_throttling_enabled_;
  uint32_t download_rate_kbits_;
  uint32_t upload_rate_kbits_;

  // Tethering manager to manage tethering related state machine, properties
  // and session.
  std::unique_ptr<TetheringManager> tethering_manager_;

  base::WeakPtrFactory<Manager> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_MANAGER_H_
