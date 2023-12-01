// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_WIFI_PASSPOINT_CREDENTIALS_H_
#define SHILL_WIFI_PASSPOINT_CREDENTIALS_H_

#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include <base/memory/ref_counted.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/data_types.h"
#include "shill/eap_credentials.h"
#include "shill/error.h"
#include "shill/metrics.h"
#include "shill/profile.h"
#include "shill/refptr_types.h"
#include "shill/store/key_value_store.h"
#include "shill/store/pkcs11_slot_getter.h"

namespace shill {

class EapCredentials;
class Error;
class KeyValueStore;
class StoreInterface;

// A PasspointCredentials contains a set of criteria used to match a Wi-Fi
// network without identifying it using its SSID. It also contains the EAP
// credentials required to successfully authenticate to that network.
class PasspointCredentials : public base::RefCounted<PasspointCredentials> {
 public:
  // Passpoint storage type and value
  static constexpr char kStorageType[] = "Type";
  static constexpr char kTypePasspoint[] = "passpoint";

  explicit PasspointCredentials(std::string id);
  PasspointCredentials(const PasspointCredentials&) = delete;
  PasspointCredentials& operator=(const PasspointCredentials&) = delete;

  virtual ~PasspointCredentials();

  // Set the profile that owns this set of credentials.
  void SetProfile(const ProfileRefPtr& profile) { profile_ = profile; }

  // Set supplicant D-Bus identifier.
  void SetSupplicantId(const RpcIdentifier& id) { supplicant_id_ = id; }

  // Populate the wpa_supplicant D-Bus parameter map |properties| with the
  // parameters contained in |this| and return true if successful.
  virtual bool ToSupplicantProperties(KeyValueStore* properties) const;

  // Loads the set of credentials from |storage|. Requires the credentials
  // identifier |id_| to be set before calling this.
  void Load(const StoreInterface* storage);

  // Saves the set of credentials to |storage|. Returns true on success.
  bool Save(StoreInterface* storage);

  // Set PKCS#11 slot getter for |eap_|.
  void SetEapSlotGetter(Pkcs11SlotGetter* slot_getter);

  // Creates a set of Passpoint credentials from a dictionary. The content of
  // the dictionary is validated (including EAP credentials) according to
  // the requirements of Passpoint specifications. Returns the valid
  // PasspointCredentials object and Metrics::kPasspointProvisioningSuccess, or
  // nullptr and the relevant metric error value in case of failure.
  static std::pair<PasspointCredentialsRefPtr,
                   Metrics::PasspointProvisioningResult>
  CreatePasspointCredentials(const KeyValueStore& args, Error* error);

  // Records UMA Passpoint metrics describing a newly provisioned
  // PasspointCredentials object.
  static void RecordProvisioningEvent(
      Metrics* metrics,
      Metrics::PasspointProvisioningResult result,
      const PasspointCredentialsRefPtr creds);

  // Get the first fully qualified domain name (FQDN) from the FQDNs stored in
  // |domains_|.
  std::string GetFQDN();

  // Get the provisioning source for the credentials. For ARC provisioned
  // credentials, this function returns the App package name inside ARC.
  std::string GetOrigin();

  const std::string& id() const { return id_; }
  const std::vector<std::string>& domains() const { return domains_; }
  const std::string& realm() const { return realm_; }
  const std::vector<uint64_t>& home_ois() const { return home_ois_; }
  const std::vector<uint64_t>& required_home_ois() const {
    return required_home_ois_;
  }
  const std::vector<uint64_t>& roaming_consortia() const {
    return roaming_consortia_;
  }
  const EapCredentials& eap() const { return eap_; }
  bool metered_override() const { return metered_override_; }
  const std::string android_package_name() const {
    return android_package_name_;
  }
  const std::string& friendly_name() const { return friendly_name_; }
  int64_t expiration_time_milliseconds() const {
    return expiration_time_milliseconds_;
  }
  const ProfileRefPtr& profile() const { return profile_; }
  const RpcIdentifier& supplicant_id() const { return supplicant_id_; }

 private:
  friend class WiFiProviderTest;
  FRIEND_TEST(PasspointCredentialsTest, ToSupplicantProperties);
  FRIEND_TEST(PasspointCredentialsTest, EncodeOI);
  FRIEND_TEST(PasspointCredentialsTest, EncodeOIList);

  // Storage keys
  static constexpr char kStorageDomains[] = "Domains";
  static constexpr char kStorageRealm[] = "Realm";
  static constexpr char kStorageHomeOIs[] = "HomeOIs";
  static constexpr char kStorageRequiredHomeOIs[] = "RequiredHomeOIs";
  static constexpr char kStorageRoamingConsortia[] = "RoamingConsortia";
  static constexpr char kStorageMeteredOverride[] = "MeteredOverride";
  static constexpr char kStorageAndroidPackageName[] = "AndroidPackageName";
  static constexpr char kStorageFriendlyName[] = "FriendlyName";
  static constexpr char kStorageExpirationTimeMilliseconds[] =
      "ExpirationTimeMilliseconds";

  PasspointCredentials(const std::string& id,
                       const std::vector<std::string>& domains,
                       const std::string& realm,
                       const std::vector<uint64_t>& home_ois,
                       const std::vector<uint64_t>& required_home_ois,
                       const std::vector<uint64_t>& rc,
                       bool metered_override,
                       const std::string& android_package_name,
                       const std::string& friendly_name,
                       uint64_t expiration_time_milliseconds);

  // Create a unique identifier for the set of credentials.
  static std::string GenerateIdentifier();

  // Encode an Organisation Identifier to an hexadecimal string.
  static std::string EncodeOI(uint64_t oi);

  // Encode an Organisation Identifier list to a string of hexadecimal values
  // separated by a ','.
  static std::string EncodeOIList(const std::vector<uint64_t>& ois);

  friend std::ostream& operator<<(std::ostream& os,
                                  const PasspointCredentials& creds);

  // Home service provider FQDNs.
  std::vector<std::string> domains_;
  // Home Realm for Interworking.
  std::string realm_;
  // Organizational identifiers identifying the home service provider of which
  // the provider is a member. When at least one of these OI matches an OI
  // advertised by a Passpoint operator, an authentication with that hotspot
  // is possible and it is identified as a "home" network.
  std::vector<uint64_t> home_ois_;
  // Organizational idendifiers for home networks that must be matched to
  // connect to a network.
  std::vector<uint64_t> required_home_ois_;
  // Roaming consortium OI(s) used to determine which access points support
  // authentication with this credential. When one of the following OIs matches
  // an OI advertised by the access point, an authentication is possible and
  // the hotspot is identified as a "roaming" network.
  std::vector<uint64_t> roaming_consortia_;
  // Set of EAP credentials (TLS or TTLS only) used to connect to a network
  // that matched these credentials.
  EapCredentials eap_;
  // Tells weither we should consider the network as metered and override
  // the service value.
  bool metered_override_;
  // Package name of the application that provided the credentials, if any.
  std::string android_package_name_;
  // Human readable name for the set of credentials.
  std::string friendly_name_;
  // Time before the expiration of the set of credentials, in milliseconds since
  // January 1, 1970, 00:00:00 GMT. The min value of int64_t means the field is
  // unset.
  int64_t expiration_time_milliseconds_;

  // Credentials unique identifier.
  std::string id_;
  // Owner of the set of credentials.
  ProfileRefPtr profile_;
  // D-Bus object path that idenfies the set of credentials on supplicant
  // interface. The field contains a real object path when the set of
  // credentials lives in supplicant.
  RpcIdentifier supplicant_id_;
};

}  // namespace shill

#endif  // SHILL_WIFI_PASSPOINT_CREDENTIALS_H_
