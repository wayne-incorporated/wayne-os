// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/passpoint_credentials.h"

#include <cstddef>
#include <limits>
#include <set>
#include <string>
#include <vector>

#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <chromeos/dbus/shill/dbus-constants.h>
#include <uuid/uuid.h>

#include "shill/data_types.h"
#include "shill/dbus/dbus_control.h"
#include "shill/eap_credentials.h"
#include "shill/error.h"
#include "shill/metrics.h"
#include "shill/profile.h"
#include "shill/refptr_types.h"
#include "shill/store/key_value_store.h"
#include "shill/store/pkcs11_slot_getter.h"
#include "shill/store/store_interface.h"
#include "shill/supplicant/wpa_supplicant.h"

namespace shill {

namespace {

// Retrieve the list of OIs encoded as decimal strings from the given DBus
// property dictionary |args| (as a shill's KeyValueStore), convert them to
// uint64 values and add them to |parsed_ois|. If a string-to-number conversion
// error happens, populate |error| and return false.
bool ParsePasspointOiList(const KeyValueStore& args,
                          const std::string& property,
                          std::vector<uint64_t>* parsed_ois,
                          Error* error) {
  const auto raw_ois = args.Lookup<std::vector<std::string>>(property, {});
  for (const auto& raw_oi : raw_ois) {
    uint64_t oi;
    if (!base::StringToUint64(raw_oi, &oi)) {
      Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                            "invalid " + property + " list: \"" + raw_oi +
                                "\" was not a valid decimal string");
      parsed_ois->clear();
      return false;
    }
    parsed_ois->push_back(oi);
  }
  return true;
}

}  // namespace

// Size of an UUID string.
constexpr size_t kUUIDStringLength = 37;

// OUI and OUI-36 expected hex string length for supplicant.
constexpr size_t kOUIHexLength = 6;
constexpr size_t kOUI36HexLength = 10;

PasspointCredentials::PasspointCredentials(std::string id) : id_(id) {}

PasspointCredentials::~PasspointCredentials() = default;

PasspointCredentials::PasspointCredentials(
    const std::string& id,
    const std::vector<std::string>& domains,
    const std::string& realm,
    const std::vector<uint64_t>& home_ois,
    const std::vector<uint64_t>& required_home_ois,
    const std::vector<uint64_t>& roaming_consortia,
    bool metered_override,
    const std::string& android_package_name,
    const std::string& friendly_name,
    uint64_t expiration_time_milliseconds)
    : domains_(domains),
      realm_(realm),
      home_ois_(home_ois),
      required_home_ois_(required_home_ois),
      roaming_consortia_(roaming_consortia),
      metered_override_(metered_override),
      android_package_name_(android_package_name),
      friendly_name_(friendly_name),
      expiration_time_milliseconds_(expiration_time_milliseconds),
      id_(id),
      profile_(nullptr),
      supplicant_id_(DBusControl::NullRpcIdentifier()) {}

bool PasspointCredentials::ToSupplicantProperties(
    KeyValueStore* properties) const {
  CHECK(properties);
  // A set of passpoint credentials is validated at insertion time in Shill,
  // it is expected to be valid now.
  CHECK(!domains_.empty() && !domains_[0].empty());
  CHECK(!realm_.empty());

  properties->Set<std::vector<std::string>>(
      WPASupplicant::kCredentialsPropertyDomain, domains_);
  properties->Set<std::string>(WPASupplicant::kCredentialsPropertyRealm,
                               realm_);

  if (!required_home_ois_.empty()) {
    properties->Set<std::string>(
        WPASupplicant::kCredentialsPropertyRequiredHomeOIs,
        EncodeOIList(required_home_ois_));
  }

  if (!home_ois_.empty()) {
    properties->Set<std::string>(WPASupplicant::kCredentialsPropertyHomeOIs,
                                 EncodeOIList(home_ois_));
  }

  if (!roaming_consortia_.empty()) {
    properties->Set<std::string>(
        WPASupplicant::kCredentialsPropertyRoamingConsortiums,
        EncodeOIList(roaming_consortia_));
  }

  // Supplicant requires the EAP method for interworking selection.
  properties->Set<std::string>(WPASupplicant::kNetworkPropertyEapEap,
                               eap_.method());
  // Supplicant requires the credentials to perform matches using the realm
  // (see b/225170348).
  if (eap_.method() == kEapMethodTLS) {
    properties->Set<std::string>(WPASupplicant::kNetworkPropertyEapCertId,
                                 eap_.cert_id());
    properties->Set<std::string>(WPASupplicant::kNetworkPropertyEapKeyId,
                                 eap_.key_id());
    properties->Set<std::string>(WPASupplicant::kCredentialsPropertyUsername,
                                 eap_.identity());
  } else if (eap_.method() == kEapMethodTTLS) {
    properties->Set<std::string>(WPASupplicant::kCredentialsPropertyUsername,
                                 eap_.identity());
    properties->Set<std::string>(WPASupplicant::kCredentialsPropertyPassword,
                                 eap_.password());
  } else {
    LOG(ERROR) << "Passpoint credentials does not support EAP method '"
               << eap_.method() << "'";
    properties->Clear();
    return false;
  }

  return true;
}

void PasspointCredentials::Load(const StoreInterface* storage) {
  CHECK(storage);
  CHECK(!id_.empty());

  storage->GetStringList(id_, kStorageDomains, &domains_);
  storage->GetString(id_, kStorageRealm, &realm_);
  storage->GetUint64List(id_, kStorageHomeOIs, &home_ois_);
  storage->GetUint64List(id_, kStorageRequiredHomeOIs, &required_home_ois_);
  storage->GetUint64List(id_, kStorageRoamingConsortia, &roaming_consortia_);
  storage->GetBool(id_, kStorageMeteredOverride, &metered_override_);
  storage->GetString(id_, kStorageAndroidPackageName, &android_package_name_);
  storage->GetString(id_, kStorageFriendlyName, &friendly_name_);
  storage->GetInt64(id_, kStorageExpirationTimeMilliseconds,
                    &expiration_time_milliseconds_);
  eap_.Load(storage, id_);
}

bool PasspointCredentials::Save(StoreInterface* storage) {
  CHECK(storage);
  CHECK(!id_.empty());

  // The credentials identifier is unique, we can use it as storage identifier.
  storage->SetString(id_, kStorageType, kTypePasspoint);
  storage->SetStringList(id_, kStorageDomains, domains_);
  storage->SetString(id_, kStorageRealm, realm_);
  storage->SetUint64List(id_, kStorageHomeOIs, home_ois_);
  storage->SetUint64List(id_, kStorageRequiredHomeOIs, required_home_ois_);
  storage->SetUint64List(id_, kStorageRoamingConsortia, roaming_consortia_);
  storage->SetBool(id_, kStorageMeteredOverride, metered_override_);
  storage->SetString(id_, kStorageAndroidPackageName, android_package_name_);
  storage->SetString(id_, kStorageFriendlyName, friendly_name_);
  storage->SetInt64(id_, kStorageExpirationTimeMilliseconds,
                    expiration_time_milliseconds_);
  eap_.Save(storage, id_, /*save_credentials=*/true);

  return true;
}

void PasspointCredentials::SetEapSlotGetter(Pkcs11SlotGetter* slot_getter) {
  eap_.SetEapSlotGetter(slot_getter);
}

std::string PasspointCredentials::GenerateIdentifier() {
  uuid_t uuid_bytes;
  uuid_generate_random(uuid_bytes);
  std::string uuid(kUUIDStringLength, '\0');
  uuid_unparse(uuid_bytes, &uuid[0]);
  // Remove the null terminator from the string.
  uuid.resize(kUUIDStringLength - 1);
  return uuid;
}

std::pair<PasspointCredentialsRefPtr, Metrics::PasspointProvisioningResult>
PasspointCredentials::CreatePasspointCredentials(const KeyValueStore& args,
                                                 Error* error) {
  std::vector<std::string> domains;
  std::string realm;
  std::vector<uint64_t> home_ois, required_home_ois, roaming_consortia;
  bool metered_override;
  std::string android_package_name;
  std::string friendly_name;
  // "Expiration time" value where there is no expiration time.
  const std::string kNoExpirationTime =
      base::NumberToString(std::numeric_limits<int64_t>::min());
  int64_t expiration_time_milliseconds = std::numeric_limits<int64_t>::min();

  domains = args.Lookup<std::vector<std::string>>(
      kPasspointCredentialsDomainsProperty, std::vector<std::string>());
  if (domains.empty()) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kInvalidArguments,
        "at least one FQDN is required in " +
            std::string(kPasspointCredentialsDomainsProperty));
    return {nullptr, Metrics::kPasspointProvisioningNoOrInvalidFqdn};
  }
  for (const auto& domain : domains) {
    if (!EapCredentials::ValidDomainSuffixMatch(domain)) {
      Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                            "domain '" + domain + "' is not a valid FQDN");
      return {nullptr, Metrics::kPasspointProvisioningNoOrInvalidFqdn};
    }
  }

  if (!args.Contains<std::string>(kPasspointCredentialsRealmProperty)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          std::string(kPasspointCredentialsRealmProperty) +
                              " property is mandatory");
    return {nullptr, Metrics::kPasspointProvisioningNoOrInvalidRealm};
  }
  realm = args.Get<std::string>(kPasspointCredentialsRealmProperty);
  if (!EapCredentials::ValidDomainSuffixMatch(realm)) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "realm '" + realm + "' is not a valid FQDN");
    return {nullptr, Metrics::kPasspointProvisioningNoOrInvalidRealm};
  }

  if (!ParsePasspointOiList(args, kPasspointCredentialsHomeOIsProperty,
                            &home_ois, error)) {
    return {nullptr,
            Metrics::kPasspointProvisioningInvalidOrganizationIdentifier};
  }

  if (!ParsePasspointOiList(args, kPasspointCredentialsRequiredHomeOIsProperty,
                            &required_home_ois, error)) {
    return {nullptr,
            Metrics::kPasspointProvisioningInvalidOrganizationIdentifier};
  }

  if (!ParsePasspointOiList(args, kPasspointCredentialsRoamingConsortiaProperty,
                            &roaming_consortia, error)) {
    return {nullptr,
            Metrics::kPasspointProvisioningInvalidOrganizationIdentifier};
  }

  metered_override =
      args.Lookup<bool>(kPasspointCredentialsMeteredOverrideProperty, false);
  android_package_name = args.Lookup<std::string>(
      kPasspointCredentialsAndroidPackageNameProperty, std::string());
  friendly_name = args.Lookup<std::string>(
      kPasspointCredentialsFriendlyNameProperty, std::string());
  const auto value = args.Lookup<std::string>(
      kPasspointCredentialsExpirationTimeMillisecondsProperty,
      kNoExpirationTime);
  if (!base::StringToInt64(value, &expiration_time_milliseconds)) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kInvalidArguments,
        "invalid " +
            std::string(
                kPasspointCredentialsExpirationTimeMillisecondsProperty) +
            ": \"" + value + "\" was not a valid decimal string");
    return {nullptr, Metrics::kPasspointProvisioningInvalidExpirationTime};
  }

  // Create the set of credentials with a unique identifier.
  std::string id = GenerateIdentifier();
  PasspointCredentialsRefPtr creds = new PasspointCredentials(
      id, domains, realm, home_ois, required_home_ois, roaming_consortia,
      metered_override, android_package_name, friendly_name,
      expiration_time_milliseconds);

  // Load EAP credentials from the set of properties.
  creds->eap_.Load(args);

  // Server authentication: if the caller specify a CA certificate, disable
  // system CAs. Otherwise, enable system CAs usage and verify that the
  // alternative name match list is specified or that the domain suffix match
  // list is specified.
  if (!creds->eap_.ca_cert_pem().empty()) {
    creds->eap_.set_use_system_cas(false);
  } else {
    creds->eap_.set_use_system_cas(true);
    if (creds->eap_.subject_alternative_name_match_list().empty() &&
        creds->eap_.domain_suffix_match_list().empty()) {
      Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                            "EAP credentials with no CA certificate must have "
                            "a Subject Alternative Name match list or a Domain "
                            "Suffix match list");
      return {nullptr, Metrics::kPasspointProvisioningInvalidEapProperties};
    }
  }

  // Check the set of credentials is consistent.
  if (!creds->eap().IsConnectable()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "EAP credendials not connectable");
    return {nullptr, Metrics::kPasspointProvisioningInvalidEapProperties};
  }

  // Our Passpoint implementation only supports EAP TLS or TTLS. SIM based EAP
  // methods are not supported on ChromeOS yet.
  std::string method = creds->eap().method();
  if (method != kEapMethodTLS && method != kEapMethodTTLS) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kInvalidArguments,
        "EAP method '" + method + "' is not supported by Passpoint");
    return {nullptr, Metrics::kPasspointProvisioningInvalidEapMethod};
  }

  // Passpoint supported Non-EAP inner methods. Refer to
  // Credential/UsernamePassword/EAPMethod/InnerEAPType in Hotspot 2.0 Release 2
  // Technical Specification Section 9.1 for more info.
  static const std::set<std::string> supported_ttls_inner_methods = {
      kEapPhase2AuthTTLSMSCHAPV2, kEapPhase2AuthTTLSMSCHAP,
      kEapPhase2AuthTTLSPAP};

  std::string inner_method = creds->eap().inner_method();
  if (method == kEapMethodTTLS &&
      supported_ttls_inner_methods.find(inner_method) ==
          supported_ttls_inner_methods.end()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                          "TTLS inner EAP method '" + inner_method +
                              "' is not supported by Passpoint");
    return {nullptr, Metrics::kPasspointProvisioningInvalidEapProperties};
  }

  return {creds, Metrics::kPasspointProvisioningSuccess};
}

// static
void PasspointCredentials::RecordProvisioningEvent(
    Metrics* metrics,
    Metrics::PasspointProvisioningResult result,
    const PasspointCredentialsRefPtr creds) {
  metrics->SendEnumToUMA(Metrics::kMetricPasspointProvisioningResult, result);
  if (!creds) {
    return;
  }
  // TODO(b/207730857) Update |kMetricPasspointSecurity| metrics reporting when
  // EAP-SIM support is added.
  auto security = Metrics::kPasspointSecurityUnknown;
  if (creds->eap().method() == kEapMethodTLS) {
    security = Metrics::kPasspointSecurityTLS;
  } else if (creds->eap().method() == kEapMethodTTLS) {
    if (creds->eap().inner_method() == kEapPhase2AuthTTLSPAP) {
      security = Metrics::kPasspointSecurityTTLSPAP;
    } else if (creds->eap().inner_method() == kEapPhase2AuthTTLSMSCHAP) {
      security = Metrics::kPasspointSecurityTTLSMSCHAP;
    } else if (creds->eap().inner_method() == kEapPhase2AuthTTLSMSCHAPV2) {
      security = Metrics::kPasspointSecurityTTLSMSCHAPV2;
    } else {
      security = Metrics::kPasspointSecurityTTLSUnknown;
    }
  }
  metrics->SendEnumToUMA(Metrics::kMetricPasspointSecurity, security);
  // TODO(b/207361432) Update |kMetricPasspointOrigin| metrics when more origins
  // are added.
  metrics->SendEnumToUMA(Metrics::kMetricPasspointOrigin,
                         Metrics::kPasspointOriginAndroid);
  metrics->SendEnumToUMA(Metrics::kMetricPasspointMeteredness,
                         creds->metered_override()
                             ? Metrics::kPasspointMetered
                             : Metrics::kPasspointNotMetered);
  metrics->SendSparseToUMA(Metrics::kMetricPasspointDomains,
                           creds->domains().size());
  metrics->SendSparseToUMA(Metrics::kMetricPasspointHomeOis,
                           creds->home_ois().size());
  metrics->SendSparseToUMA(Metrics::kMetricPasspointRequiredHomeOis,
                           creds->required_home_ois().size());
  metrics->SendSparseToUMA(Metrics::kMetricPasspointRoamingOis,
                           creds->roaming_consortia().size());
}

std::string PasspointCredentials::GetFQDN() {
  if (domains_.empty())
    return std::string();

  return domains_[0];
}

std::string PasspointCredentials::GetOrigin() {
  return android_package_name_;
}

// static
std::string PasspointCredentials::EncodeOI(uint64_t oi) {
  static const char kHexChars[] = "0123456789ABCDEF";
  // Each input byte creates two output hex characters.
  static const size_t size = sizeof(uint64_t) * 2;

  std::string ret(size, '0');
  size_t i = size;
  // wpa_supplicant expects an even number of char as a byte is filled by two
  // of them.
  do {
    ret[--i] = kHexChars[oi & 0x0f];
    ret[--i] = kHexChars[(oi & 0xf0) >> 4];
    oi = oi >> 8;
  } while (oi > 0);

  // Quoting IEEE802.11-2020 §9.4.1.31:
  // "The Organization Identifier field contains a public unique identifier
  // assigned by the IEEE Registration Authority as a 24-bit OUI, a 24-bit CID,
  // or a 36-bit OUI-36.
  // The length of the Organization Identifier field is the minimum number of
  // octets required to contain the entire IEEE-assigned identifier. Thus, the
  // Organization Identifier field is 3 octets in length if the IEEE-assigned
  // identifier is an OUI or CID, or 5 octets in length if the IEEE-assigned
  // identifier is an OUI-36."
  // Pad 00s to have the expected OI length. This is necessary as ChromeOS OI
  // value is taken from Android which unfortunately does not have the necessary
  // length field.
  // This padding fix is not technically correct, but is the best possible fix
  // for ChromeOS given the missing OI length information. The matching fails
  // when an entity owning an OUI value of "000xxx" (hex representation) creates
  // their own OUI-36-based OI for Passpoint "0000xxxyyy". When this happens,
  // ChromeOS uses "xxxyyy" as their OI value eventhough "0000xxxyyy" is needed.
  size_t len = size - i;
  if (len <= kOUIHexLength) {
    i = size - kOUIHexLength;
  } else if (len <= kOUI36HexLength) {
    i = size - kOUI36HexLength;
  }

  return ret.substr(i);
}

// static
std::string PasspointCredentials::EncodeOIList(
    const std::vector<uint64_t>& ois) {
  std::vector<std::string> strings;
  for (const auto& oi : ois) {
    strings.push_back(EncodeOI(oi));
  }
  return base::JoinString(strings, ",");
}

std::ostream& operator<<(std::ostream& os, const PasspointCredentials& creds) {
  os << "PasspointCredentials[id: " << creds.id()
     << ", friendly_name: " << creds.friendly_name() << "]";
  return os;
}

}  // namespace shill
