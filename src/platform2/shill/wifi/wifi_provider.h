// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_WIFI_WIFI_PROVIDER_H_
#define SHILL_WIFI_WIFI_PROVIDER_H_

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <base/observer_list.h>
#include <base/observer_list_types.h>

#include "shill/data_types.h"
#include "shill/mockable.h"
#include "shill/net/netlink_manager.h"
#include "shill/net/netlink_message.h"
#include "shill/net/nl80211_message.h"
#include "shill/provider_interface.h"
#include "shill/refptr_types.h"
#include "shill/wifi/local_device.h"
#include "shill/wifi/wifi_rf.h"

namespace shill {

class ByteString;
class Error;
class KeyValueStore;
class Manager;
class Metrics;
class WiFiEndpoint;
class WiFiPhy;
class WiFiService;
class WiFiSecurity;

// This enum indicates information source for the regulatory information:
// - kCurrent - value currently set in WiFi core (obtained from Netlink
//   notifications,
// - kCellular - value indicated by the Cellular (based on country/MCC of the
//   serving operator).
enum class RegulatorySource {
  kCurrent,
  kCellular,
};

// The WiFi Provider is the holder of all WiFi Services.  It holds both
// visible (created due to an Endpoint becoming visible) and invisible
// (created due to user or storage configuration) Services.
class WiFiProvider : public ProviderInterface {
 public:
  // Describes the priority of the network computed during the a match between
  // a set of Passpoint credentials and a BSS.
  enum MatchPriority : uint64_t {
    // Network that belongs to the Passpoint service provider.
    kHome,
    // Network that belongs to a partner of the service provider.
    kRoaming,
    // Network not identified by supplicant.
    kUnknown
  };

  // A PasspointMatch represents a match between a set of Passpoint credentials
  // and an endpoint found during a scan. It helps to identify which service is
  // connectable based on the contained set of credentials, and what kind of
  // network it will provide.
  struct PasspointMatch {
    PasspointMatch();
    PasspointMatch(const PasspointCredentialsRefPtr& cred_in,
                   const WiFiEndpointRefPtr& endp_in,
                   MatchPriority prio_in);
    // Set of Passpoint credentials that matched.
    PasspointCredentialsRefPtr credentials;
    // BSS that matched.
    WiFiEndpointRefPtr endpoint;
    // Priority of the network computed during the match.
    MatchPriority priority;
  };

  // Observer that helps to follow the changes on the set of Passpoint
  // credentials.
  class PasspointCredentialsObserver : public base::CheckedObserver {
   public:
    // Called when a set of Passpoint credentials was added.
    virtual void OnPasspointCredentialsAdded(
        const PasspointCredentialsRefPtr& creds) = 0;
    // Called when a set of Passpoint credentials was removed.
    virtual void OnPasspointCredentialsRemoved(
        const PasspointCredentialsRefPtr& creds) = 0;
  };

  explicit WiFiProvider(Manager* manager);
  WiFiProvider(const WiFiProvider&) = delete;
  WiFiProvider& operator=(const WiFiProvider&) = delete;

  ~WiFiProvider() override;

  // Called by Manager as a part of the Provider interface.  The attributes
  // used for matching services for the WiFi provider are the SSID, mode and
  // security parameters.
  void CreateServicesFromProfile(const ProfileRefPtr& profile) override;
  ServiceRefPtr FindSimilarService(const KeyValueStore& args,
                                   Error* error) const override;
  ServiceRefPtr GetService(const KeyValueStore& args, Error* error) override;
  ServiceRefPtr CreateTemporaryService(const KeyValueStore& args,
                                       Error* error) override;
  ServiceRefPtr CreateTemporaryServiceFromProfile(const ProfileRefPtr& profile,
                                                  const std::string& entry_name,
                                                  Error* error) override;
  void Start() override;
  void Stop() override;

  // Find a Service this Endpoint should be associated with.
  virtual WiFiServiceRefPtr FindServiceForEndpoint(
      const WiFiEndpointConstRefPtr& endpoint);

  // Find or create a Service for |endpoint| to be associated with.  This
  // method first calls FindServiceForEndpoint, and failing this, creates
  // a new Service.  It then associates |endpoint| with this service.
  // Returns true if |endpoint| is associated to a service that already matched
  // with passpoint credentials.
  virtual bool OnEndpointAdded(const WiFiEndpointConstRefPtr& endpoint);

  // Called by a Device when it removes an Endpoint.  If the Provider
  // forgets a service as a result, it returns a reference to the
  // forgotten service, otherwise it returns a null reference.
  virtual WiFiServiceRefPtr OnEndpointRemoved(
      const WiFiEndpointConstRefPtr& endpoint);

  // Called by a Device when it receives notification that an Endpoint
  // has changed.  Ensure the updated endpoint still matches its
  // associated service.  If necessary re-assign the endpoint to a new
  // service, otherwise notify the associated service of the update to
  // the endpoint.
  virtual void OnEndpointUpdated(const WiFiEndpointConstRefPtr& endpoint);

  // Called by a WiFiService when it is unloaded and no longer visible.
  // |credentials| contains the set of Passpoint credentials of the service,
  // if any.
  virtual bool OnServiceUnloaded(const WiFiServiceRefPtr& service,
                                 const PasspointCredentialsRefPtr& credentials);

  // Get the list of SSIDs for hidden WiFi services we are aware of.
  virtual ByteArrays GetHiddenSSIDList();

  // Performs some "provider_of_wifi" storage updates.
  virtual void UpdateStorage(Profile* profile);

  // Report the number of auto connectable services available to uma
  // metrics.
  void ReportAutoConnectableServices();

  // Returns number of services available for auto-connect.
  virtual int NumAutoConnectableServices();

  // Reset autoconnect cooldown time for all services.
  mockable void ResetServicesAutoConnectCooldownTime();

  // Returns a list of ByteStrings representing the SSIDs of WiFi services
  // configured for auto-connect.
  std::vector<ByteString> GetSsidsConfiguredForAutoConnect();

  // Load to the provider all the Passpoint credentials available in |Profile|
  // and push the credentials to the WiFi device.
  void LoadCredentialsFromProfile(const ProfileRefPtr& profile);

  // Unload from the provider all the Passpoint credentials provided
  // by |profile| and remove them from the WiFi device.
  void UnloadCredentialsFromProfile(const ProfileRefPtr& profile);

  // Adds a new set of credentials to the provider and pushes it to the WiFi
  // device.
  virtual void AddCredentials(const PasspointCredentialsRefPtr& credentials);

  // Removes the set of credentials referenced by |credentials| from the
  // provider, the WiFi device and invalidates all the services populated with
  // the set of credentials.
  virtual bool ForgetCredentials(const PasspointCredentialsRefPtr& credentials);

  // Removes all credentials that match with |properties| from the provider,
  // the WiFi device and invalidates all the services populated with the set
  // of credentials.
  virtual bool ForgetCredentials(const KeyValueStore& properties);

  // Get the list of Passpoint credentials known by the provider.
  virtual std::vector<PasspointCredentialsRefPtr> GetCredentials();

  // Get the set of Passpoint credentials referenced by |id|.
  virtual PasspointCredentialsRefPtr FindCredentials(const std::string& id);

  // Called by the Wi-Fi device when an interworking selection found
  // connectable endpoint using Passpoint credentials.
  virtual void OnPasspointCredentialsMatches(
      const std::vector<PasspointMatch>& matches);

  // Add an observer to follow the changes on Passpoint credentials.
  virtual void AddPasspointCredentialsObserver(
      PasspointCredentialsObserver* observer);

  // Remove an observer from the Passpoint credentials observer list.
  virtual void RemovePasspointCredentialsObserver(
      PasspointCredentialsObserver* observer);

  // Return the WiFiPhy object at phy_index. Returns a nulltr if there is no
  // WiFiPhy at phy_index.
  mockable const WiFiPhy* GetPhyAtIndex(uint32_t phy_index);

  // Return all the WiFiPhy objects.
  mockable std::vector<const WiFiPhy*> GetPhys() const;

  // Register a WiFi device object to a WiFiPhy object. This method asserts that
  // there is a WiFiPhy object at the given phy_index, so it is expected that
  // the caller checks this condition before calling.
  mockable void RegisterDeviceToPhy(WiFiConstRefPtr device, uint32_t phy_index);

  // Deregister a WiFi device from it's associated WiFiPhy object. This function
  // is a no-op if the WiFi device is not currently registered to the WiFiPhy
  // at phy_index.
  mockable void DeregisterDeviceFromPhy(WiFiConstRefPtr device,
                                        uint32_t phy_index);

  // Helper that indicates to WiFiPhy at |phy_index| that PHY dump has ended.
  void PhyDumpComplete(uint32_t phy_index);

  // Handle a NL80211_CMD_NEW_WIPHY. Creates a WiFiPhy object if there isn't one
  // at the phy index, and forwards the message to the WiFiPhy.
  mockable void OnNewWiphy(const Nl80211Message& nl80211_message);
  // Notification about regulatory region change (at the moment this is signaled
  // by WiFi).
  mockable void RegionChanged(const std::string& country);

  bool disable_vht() const { return disable_vht_; }
  void set_disable_vht(bool disable_vht) { disable_vht_ = disable_vht; }
  bool has_passpoint_credentials() const { return !credentials_by_id_.empty(); }

  // Create a WiFi hotspot device with MAC address |mac_address|. |callback| is
  // called when interface event happens. The required WiFi band |band| and
  // security |security| are used in the WiFiPhy search to find the first
  // WiFiPhy which meets all the criteria.
  mockable HotspotDeviceRefPtr
  CreateHotspotDevice(const std::string& mac_address,
                      WiFiBand band,
                      WiFiSecurity security,
                      LocalDevice::EventCallback callback);

  // Delete the WiFi LocalDevice |device|.
  mockable void DeleteLocalDevice(LocalDeviceRefPtr device);

  // Returns regulatory domain (country alpha 2 code).
  const std::string& country(RegulatorySource source) {
    return country_[source];
  }
  // This function should be called to pass information about current country
  // (for regulatory purposes).  The |source| indicates source of the
  // information (see RegulatorySource above).
  void NotifyCountry(const std::string& country, RegulatorySource source);

  // This is an explicit request to update regulatory region and refresh PHY
  // information afterwards.
  mockable void UpdateRegAndPhyInfo(base::OnceClosure callback);

  // Sets the regulatory domain to the "world" domain.
  mockable void ResetRegDomain();

 protected:
  FRIEND_TEST(WiFiProviderTest, DeregisterWiFiLocalDevice);
  FRIEND_TEST(WiFiProviderTest, GetUniqueLocalDeviceName);
  FRIEND_TEST(WiFiProviderTest, RegisterWiFiLocalDevice);
  FRIEND_TEST(WiFiProviderTest2, UpdatePhyInfo_Success);

  // Register a WiFi local device object to WiFiProvider and a WiFiPhy object.
  // This method asserts that there is a WiFiPhy object at the given phy_index,
  // so it is expected that the caller checks this condition before calling.
  void RegisterLocalDevice(LocalDeviceRefPtr device);

  // Deregister a WiFi local device from WiFiProvider and it's associated
  // WiFiPhy object. This function is a no-op if the WiFi device is not
  // currently registered to the WiFiPhy at phy_index.
  void DeregisterLocalDevice(LocalDeviceConstRefPtr device);

  // Generate an interface name which is not in used with prefix |iface_prefix|.
  std::string GetUniqueLocalDeviceName(const std::string& iface_prefix);

 private:
  friend class WiFiProviderTest;

  using EndpointServiceMap = std::map<const WiFiEndpoint*, WiFiServiceRefPtr>;
  using PasspointCredentialsMap =
      std::map<const std::string, PasspointCredentialsRefPtr>;

  // Add a service to the service_ vector and register it with the Manager.
  WiFiServiceRefPtr AddService(const std::vector<uint8_t>& ssid,
                               const std::string& mode,
                               const std::string& security_class,
                               const WiFiSecurity& security,
                               bool is_hidden);

  // Find a service given its properties.
  WiFiServiceRefPtr FindService(const std::vector<uint8_t>& ssid,
                                const std::string& mode,
                                const std::string& security_class,
                                const WiFiSecurity& security) const;

  // Returns a WiFiServiceRefPtr for unit tests and for down-casting to a
  // ServiceRefPtr in GetService().
  WiFiServiceRefPtr GetWiFiService(const KeyValueStore& args, Error* error);

  // Disassociate the service from its WiFi device and remove it from the
  // services_ vector.
  void ForgetService(const WiFiServiceRefPtr& service);

  // Removes the set of credentials referenced by |credentials| from both the
  // provider and the WiFi device.
  bool RemoveCredentials(const PasspointCredentialsRefPtr& credentials);

  // Deletes certificate(s) and key(s) tied to |credentials|. If there are
  // other active credentials using the same certificates or keys, this method
  // will do nothing.
  void DeleteUnusedCertificateAndKey(
      const PasspointCredentialsRefPtr& credentials);

  void ReportRememberedNetworkCount();
  void ReportServiceSourceMetrics();

  // Requests the phy at phy_index. If the value kAllPhys is provided, then
  // request a dump of all phys.
  void GetPhyInfo(uint32_t phy_index);

  // Callback invoked when broadcasted netlink messages are received. Handles
  // NL80211_CMD_DEL_WIPHY by deleting the relevant WiFiPhy object. If we
  // receive any other NL80211 message which includes a phy index value, then
  // we request phy info for that phy index.
  void HandleNetlinkBroadcast(const shill::NetlinkMessage& message);

  // Set regulatory domain to the country based on information obtained from
  // |source|.  See RegulatorySource above.
  mockable void SetRegDomain(RegulatorySource source);
  // Utility function handling timeout for setting of regulatory domain.
  void PhyUpdateTimeout();
  // Utility function used to detect the end of PHY info dump and responsible
  // for calling the callback passed in UpdateRegAndPhy().
  void OnGetPhyInfoAuxMessage(NetlinkManager::AuxiliaryMessageType type,
                              const NetlinkMessage* raw_message);

  Metrics* metrics() const;

  // Sort the internal list of services.
  void SortServices();

  Manager* manager_;
  NetlinkManager* netlink_manager_;

  std::vector<WiFiServiceRefPtr> services_;
  EndpointServiceMap service_by_endpoint_;
  PasspointCredentialsMap credentials_by_id_;
  base::ObserverList<PasspointCredentialsObserver> credentials_observers_;
  base::WeakPtrFactory<WiFiProvider> weak_ptr_factory_while_started_;
  std::map<uint32_t, std::unique_ptr<WiFiPhy>> wifi_phys_;
  shill::NetlinkManager::NetlinkMessageHandler broadcast_handler_;
  // Holds reference pointers to all WiFi Local devices with the link name as
  // the map key.
  std::map<std::string, LocalDeviceRefPtr> local_devices_;
  // Regulatory information: ISO 3166 alpha2 country code (e.g. "US") if known.
  // Indexed by the source of information - see enum RegulatorySource.
  std::map<RegulatorySource, std::string> country_;
  // Callbacks used during process of region/phy update (initiated by
  // a UpdateRegAndPhy() function).
  base::CancelableOnceClosure phy_update_timeout_cb_;
  base::OnceClosure phy_info_ready_cb_;

  bool running_;

  // Disable 802.11ac Very High Throughput (VHT) connections.
  bool disable_vht_;
};

}  // namespace shill

#endif  // SHILL_WIFI_WIFI_PROVIDER_H_
