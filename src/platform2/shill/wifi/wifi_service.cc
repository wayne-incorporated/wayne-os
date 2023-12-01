// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/wifi_service.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <map>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/logging.h>
#include <base/containers/contains.h>
#include <base/notreached.h>
#include <base/rand_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <chromeos/dbus/service_constants.h>

#include "shill/adaptor_interfaces.h"
#include "shill/certificate_file.h"
#include "shill/dbus/dbus_control.h"
#include "shill/device.h"
#include "shill/eap_credentials.h"
#include "shill/error.h"
#include "shill/event_dispatcher.h"
#include "shill/logging.h"
#include "shill/manager.h"
#include "shill/metrics.h"
#include "shill/net/ieee80211.h"
#include "shill/store/property_accessor.h"
#include "shill/store/store_interface.h"
#include "shill/supplicant/wpa_supplicant.h"
#include "shill/wifi/passpoint_credentials.h"
#include "shill/wifi/wifi.h"
#include "shill/wifi/wifi_endpoint.h"
#include "shill/wifi/wifi_provider.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kService;
static std::string ObjectID(const WiFiService* w) {
  return w->log_name();
}
}  // namespace Logging

namespace {
// Deprecated to migrate from ROT47 to plaintext.
// TODO(crbug.com/1084279) Remove after migration is complete.
const char kStorageDeprecatedPassphrase[] = "Passphrase";

constexpr auto kMinDisconnectOffset = base::Hours(4);

static const std::map<WiFiService::RandomizationPolicy, std::string>
    RandomizationPolicyMap = {
        {WiFiService::RandomizationPolicy::Hardware,
         kWifiRandomMacPolicyHardware},
        {WiFiService::RandomizationPolicy::FullRandom,
         kWifiRandomMacPolicyFullRandom},
        {WiFiService::RandomizationPolicy::OUIRandom,
         kWifiRandomMacPolicyOUIRandom},
        {WiFiService::RandomizationPolicy::PersistentRandom,
         kWifiRandomMacPolicyPersistentRandom},
        {WiFiService::RandomizationPolicy::NonPersistentRandom,
         kWifiRandomMacPolicyNonPersistentRandom},
};

static const std::map<WiFiService::RandomizationPolicy, int32_t>
    RandomizationPolicyToSupplicantPolicy = {
        {WiFiService::RandomizationPolicy::Hardware,
         WPASupplicant::kMACAddrPolicyHardware},
        {WiFiService::RandomizationPolicy::FullRandom,
         WPASupplicant::kMACAddrPolicyFullRandom},
        {WiFiService::RandomizationPolicy::OUIRandom,
         WPASupplicant::kMACAddrPolicyOUIRandom},
        {WiFiService::RandomizationPolicy::PersistentRandom,
         WPASupplicant::kMACAddrPolicyPersistentRandom},
        {WiFiService::RandomizationPolicy::NonPersistentRandom,
         WPASupplicant::kMACAddrPolicyPersistentRandom},
};

// List of SSIDs served by endpoints that do not support randomization,
// available by courtesy of Android (go/veaub).
static constexpr std::array<const char*, 5> SSIDsExcludedFromRandomization = {
    "ACWiFi", "AA-Inflight", "gogoinflight", "DeltaWiFi", "DeltaWiFi.com"};

// The default Passpoint match score is (for now) set to the best network
// priority. A (not Passpoint) network should have a score equivalent to a
// "home" Passpoint network.
constexpr uint64_t kDefaultMatchPriority = WiFiProvider::MatchPriority::kHome;

// Returns true if every element of |bytes| is zero, false otherwise.
bool IsZero(const ByteArray& bytes) {
  for (const auto& byte : bytes) {
    if (byte != 0) {
      return false;
    }
  }
  return true;
}

enum class BSSIDAllowlistPolicy {
  kNoneAllowed,
  kAllAllowed,
  kMatchOnlyAllowed,
};

BSSIDAllowlistPolicy GetBSSIDAllowlistPolicy(
    const std::set<ByteArray>& allowlist) {
  if (allowlist.size() == 0) {
    // An empty list means nothing is restricted and everything is allowed.
    return BSSIDAllowlistPolicy::kAllAllowed;
  }
  if (allowlist.size() == 1 && IsZero(*allowlist.begin())) {
    // Special case where a single element of zeroes means don't connect to
    // any AP.
    return BSSIDAllowlistPolicy::kNoneAllowed;
  }
  return BSSIDAllowlistPolicy::kMatchOnlyAllowed;
}

}  // namespace

const char WiFiService::kAnyDeviceAddress[] = "any";
const int WiFiService::kSuspectedCredentialFailureThreshold = 3;

const char WiFiService::kStorageMACAddress[] = "WiFi.MACAddress";
const char WiFiService::kStorageMACPolicy[] = "WiFi.MACPolicy";
const char WiFiService::kStoragePortalDetected[] = "WiFi.PortalDetected";
const char WiFiService::kStorageLeaseExpiry[] = "WiFi.LeaseExpiry";
const char WiFiService::kStorageDisconnectTime[] = "WiFi.DisconnectTime";
const char WiFiService::kStorageCredentialPassphrase[] = "WiFi.Passphrase";
const char WiFiService::kStorageHiddenSSID[] = "WiFi.HiddenSSID";
const char WiFiService::kStorageMode[] = "WiFi.Mode";
const char WiFiService::kStorageSecurityClass[] = "WiFi.SecurityClass";
const char WiFiService::kStorageSecurity[] = "WiFi.Security";
const char WiFiService::kStorageSSID[] = "SSID";
const char WiFiService::kStoragePasspointCredentials[] =
    "WiFi.PasspointCredentialsId";
const char WiFiService::kStoragePasspointMatchPriority[] =
    "WiFi.PasspointMatchPriority";
const char WiFiService::kStorageBSSIDAllowlist[] = "WiFi.BSSIDAllowlist";
const char WiFiService::kStorageBSSIDRequested[] = "WiFi.BSSIDRequested";

bool WiFiService::logged_signal_warning = false;
// Clock for time-related events.
std::unique_ptr<base::Clock> WiFiService::clock_ =
    std::make_unique<base::DefaultClock>();

WiFiService::WiFiService(Manager* manager,
                         WiFiProvider* provider,
                         const std::vector<uint8_t>& ssid,
                         const std::string& mode,
                         const std::string& security_class,
                         const WiFiSecurity& security,
                         bool hidden_ssid)
    : Service(manager, Technology::kWiFi),
      need_passphrase_(false),
      security_class_(security_class),
      security_(security),
      mode_(mode),
      hidden_ssid_(hidden_ssid),
      frequency_(0),
      ap_physical_mode_(Metrics::kWiFiNetworkPhyModeUndef),
      raw_signal_strength_(0),
      cipher_8021x_(kCryptoNone),
      suspected_credential_failures_(0),
      ssid_(ssid),
      expecting_disconnect_(false),
      certificate_file_(new CertificateFile()),
      provider_(provider),
      roam_state_(kRoamStateIdle),
      is_rekey_in_progress_(false),
      match_priority_(kDefaultMatchPriority),
      session_tag_(kSessionTagInvalid) {
  std::string ssid_string(reinterpret_cast<const char*>(ssid_.data()),
                          ssid_.size());
  WiFi::SanitizeSSID(&ssid_string);

  CHECK(IsValidSecurityClass(security_class_)) << base::StringPrintf(
      "Security \"%s\" is not a SecurityClass", security_class_.c_str());
  log_name_ =
      "wifi_" + security_class_ + "_" + base::NumberToString(serial_number());
  friendly_name_ = ssid_string;

  PropertyStore* store = this->mutable_store();
  store->RegisterConstString(kModeProperty, &mode_);
  HelpRegisterWriteOnlyDerivedString(kPassphraseProperty,
                                     &WiFiService::SetPassphrase,
                                     &WiFiService::ClearPassphrase, nullptr);
  store->RegisterBool(kPassphraseRequiredProperty, &need_passphrase_);
  HelpRegisterConstDerivedString(kSecurityProperty, &WiFiService::GetSecurity);
  HelpRegisterConstDerivedString(kSecurityClassProperty,
                                 &WiFiService::GetSecurityClass);

  HelpRegisterDerivedString(kWifiRandomMACPolicy, &WiFiService::GetMACPolicy,
                            &WiFiService::SetMACPolicy);

  store->RegisterBool(kWifiHiddenSsid, &hidden_ssid_);
  store->RegisterConstUint16(kWifiFrequency, &frequency_);
  store->RegisterConstUint16s(kWifiFrequencyListProperty, &frequency_list_);
  store->RegisterConstUint16(kWifiPhyMode, &ap_physical_mode_);
  store->RegisterConstString(kWifiBSsid, &bssid_);
  store->RegisterConstString(kCountryProperty, &country_code_);
  store->RegisterConstStringmap(kWifiVendorInformationProperty,
                                &vendor_information_);
  HelpRegisterConstDerivedString(kWifiRoamStateProperty,
                                 &WiFiService::CalculateRoamState);
  store->RegisterConstBool(kWifiRekeyInProgressProperty,
                           &is_rekey_in_progress_);
  hex_ssid_ = base::HexEncode(ssid_.data(), ssid_.size());
  store->RegisterConstString(kWifiHexSsid, &hex_ssid_);

  HelpRegisterConstDerivedString(kPasspointFQDNProperty,
                                 &WiFiService::GetPasspointFQDN);
  HelpRegisterConstDerivedString(kPasspointProvisioningSourceProperty,
                                 &WiFiService::GetPasspointOrigin);
  HelpRegisterConstDerivedString(kPasspointIDProperty,
                                 &WiFiService::GetPasspointID);
  HelpRegisterConstDerivedString(kPasspointMatchTypeProperty,
                                 &WiFiService::GetPasspointMatchType);
  HelpRegisterConstDerivedInt32(kWifiSignalStrengthRssiProperty,
                                &WiFiService::GetSignalLevel);

  HelpRegisterDerivedStrings(kWifiBSSIDAllowlist,
                             &WiFiService::GetBSSIDAllowlist,
                             &WiFiService::SetBSSIDAllowlist);
  HelpRegisterDerivedString(kWifiBSSIDRequested,
                            &WiFiService::GetBSSIDRequested,
                            &WiFiService::SetBSSIDRequested);

  SetEapCredentials(new EapCredentials());
  SetSecurityProperties();

  // Until we know better (at Profile load time), use the generic name.
  storage_identifier_ = GetDefaultStorageIdentifier();
  UpdateConnectable();
  UpdateSecurity();

  // Now that |this| is a fully constructed WiFiService, synchronize observers
  // with our current state, and emit the appropriate change notifications.
  // (Initial observer state may have been set in our base class.)
  NotifyIfVisibilityChanged();

  IgnoreParameterForConfigure(kModeProperty);
  IgnoreParameterForConfigure(kSSIDProperty);
  IgnoreParameterForConfigure(kSecurityProperty);
  IgnoreParameterForConfigure(kSecurityClassProperty);
  IgnoreParameterForConfigure(kWifiHexSsid);

  InitializeCustomMetrics();

  // Log the |log_name| to |friendly_name| mapping for debugging purposes.
  // The latter will be tagged for scrubbing.
  SLOG(this, 1) << "Constructed WiFi service " << log_name() << ": "
                << WiFi::LogSSID(friendly_name());
}

WiFiService::~WiFiService() = default;

bool WiFiService::IsAutoConnectable(const char** reason) const {
  // Only auto-connect to Services which have visible and connectable Endpoints.
  // (Needed because hidden Services may remain registered with
  // Manager even without visible Endpoints.)
  if (!HasBSSIDConnectableEndpoints()) {
    *reason = Service::kAutoConnMediumUnavailable;
    return false;
  }

  CHECK(wifi_) << "We have endpoints but no WiFi device is selected?";

  if (!Service::IsAutoConnectable(reason)) {
    return false;
  }

  // Do not preempt an existing connection (whether pending, or
  // connected, and whether to this service, or another).
  if (!wifi_->IsIdle()) {
    *reason = kAutoConnBusy;
    return false;
  }

  return true;
}

std::string WiFiService::GetWiFiPassphrase(Error* error) {
  if (Is8021x() || passphrase_.empty()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kNotSupported,
                          "Service doesn't have a passphrase.");
    return std::string();
  }

  return passphrase_;
}

std::string WiFiService::GetPasspointMatchType(Error* error) {
  if (!parent_credentials_)
    return std::string();

  switch (match_priority_) {
    case WiFiProvider::MatchPriority::kHome:
      return kPasspointMatchTypeHome;
    case WiFiProvider::MatchPriority::kRoaming:
      return kPasspointMatchTypeRoaming;
    default:
      return kPasspointMatchTypeUnknown;
  }
}

std::string WiFiService::GetPasspointFQDN(Error* error) {
  if (!parent_credentials_)
    return std::string();

  return parent_credentials_->GetFQDN();
}

std::string WiFiService::GetPasspointOrigin(Error* error) {
  if (!parent_credentials_)
    return std::string();

  return parent_credentials_->GetOrigin();
}

std::string WiFiService::GetPasspointID(Error* error) {
  if (!parent_credentials_)
    return std::string();

  return parent_credentials_->id();
}

void WiFiService::SetEAPKeyManagement(const std::string& key_management) {
  // TODO(b/226138492): Chrome is setting key management only for dynamic WEP.
  // Clean this up when support for it is removed.
  Service::SetEAPKeyManagement(key_management);
  UpdateSecurity();
}

void WiFiService::SetSecurityProperties() {
  if (!security_.IsValid()) {
    // If the SecurityClass is a singleton (Wep/None) then we know already the
    // Security so let's use this.
    if (security_class() == kSecurityClassNone) {
      security_ = WiFiSecurity::kNone;
    } else if (security_class() == kSecurityClassWep) {
      security_ = WiFiSecurity::kWep;
    }
  }
  // TODO(quiche): determine if it is okay to set EAP.KeyManagement for
  // a service that is not 802.1x.
  // TODO(b/226138492): do most of this in
  // WiFiService::GetSupplicantConfigurationParameters() instead? For the most
  // part, we don't want KeyMgmt to be user-configurable, and we don't really
  // want to rely on Storage values.
  if (Is8021x()) {
    // Passphrases are not mandatory for 802.1X.
    need_passphrase_ = false;
  } else if (security_class() == kSecurityClassPsk) {
#if !defined(DISABLE_WPA3_SAE)
    // WPA/WPA2-PSK or WPA3-SAE.
    SetEAPKeyManagement(
        base::StringPrintf("%s %s %s", WPASupplicant::kKeyManagementWPAPSK,
                           WPASupplicant::kKeyManagementWPAPSKSHA256,
                           WPASupplicant::kKeyManagementSAE));
#else
    // WPA/WPA2-PSK.
    SetEAPKeyManagement(
        base::StringPrintf("%s %s", WPASupplicant::kKeyManagementWPAPSK,
                           WPASupplicant::kKeyManagementWPAPSKSHA256));
#endif  // DISABLE_WPA3_SAE
  } else if (security_class() == kSecurityClassNone ||
             security_class() == kSecurityClassWep) {
    SetEAPKeyManagement(WPASupplicant::kKeyManagementNone);
  } else {
    LOG(ERROR) << "Unsupported security class " << security_class_;
  }
}

void WiFiService::AddEndpoint(const WiFiEndpointConstRefPtr& endpoint) {
  DCHECK(endpoint->ssid() == ssid());
  DCHECK(IsSecurityMatch(endpoint->security_mode()));

  endpoints_.insert(endpoint);
  // When Security is not set (e.g. we see endpoints for some network that user
  // has not visited/configured/..., we create Service for it and add endpoints
  // to it) then we keep Security property flexible and update on every new
  // endpoint found.  Once user connects it becomes frozen (but this logic is
  // handled in WiFiSecurity::Combine() function.  Note that we do nothing in
  // RemoveEndpoint() - that is intentional, until we connect we want to have
  // the largest possible set of endpoints belonging to given network.
  auto new_security = security_.Combine(endpoint->security_mode());
  if (security_.IsFrozen() && new_security.mode() != security_.mode()) {
    auto mode = Metrics::kWirelessSecurityChangeMax;
    // In the initial phase we allow all security changes after initial
    // connection just to have some information about how disruptive it would
    // be to block them.
    switch (new_security.mode()) {
      case WiFiSecurity::kWpaWpa2:
        if (security_ == WiFiSecurity::kWpa2) {
          mode = Metrics::kWirelessSecurityChangeWpa2ToWpa12;
        }
        break;
      case WiFiSecurity::kWpaAll:
        if (security_ == WiFiSecurity::kWpa3) {
          mode = Metrics::kWirelessSecurityChangeWpa3ToWpa123;
        } else if (security_ == WiFiSecurity::kWpa2Wpa3) {
          mode = Metrics::kWirelessSecurityChangeWpa23ToWpa123;
        } else if (security_ == WiFiSecurity::kWpaWpa2) {
          mode = Metrics::kWirelessSecurityChangeWpa12ToWpa123;
        }
        break;
      case WiFiSecurity::kWpa2Wpa3:
        if (security_ == WiFiSecurity::kWpa3) {
          mode = Metrics::kWirelessSecurityChangeWpa3ToWpa23;
        }
        break;
      case WiFiSecurity::kWpaWpa2Enterprise:
        if (security_ == WiFiSecurity::kWpa2Enterprise) {
          mode = Metrics::kWirelessSecurityChangeEAPWpa2ToWpa12;
        }
        break;
      case WiFiSecurity::kWpaAllEnterprise:
        if (security_ == WiFiSecurity::kWpa3Enterprise) {
          mode = Metrics::kWirelessSecurityChangeEAPWpa3ToWpa123;
        } else if (security_ == WiFiSecurity::kWpa2Wpa3Enterprise) {
          mode = Metrics::kWirelessSecurityChangeEAPWpa23ToWpa123;
        } else if (security_ == WiFiSecurity::kWpaWpa2Enterprise) {
          mode = Metrics::kWirelessSecurityChangeEAPWpa12ToWpa123;
        }
        break;
      case WiFiSecurity::kWpa2Wpa3Enterprise:
        if (security_ == WiFiSecurity::kWpa3Enterprise) {
          mode = Metrics::kWirelessSecurityChangeEAPWpa3ToWpa23;
        }
        break;
      default:
        break;
    }
    if (mode != Metrics::kWirelessSecurityChangeMax) {
      metrics()->SendEnumToUMA(Metrics::kMetricWirelessSecurityChange, mode,
                               Metrics::kWirelessSecurityChangeMax);
    }
  }
  security_ = new_security;

  UpdateFromEndpoints();
}

void WiFiService::RemoveEndpoint(const WiFiEndpointConstRefPtr& endpoint) {
  auto i = endpoints_.find(endpoint);
  DCHECK(i != endpoints_.end());
  if (i == endpoints_.end()) {
    LOG(WARNING) << "In " << __func__ << "(): "
                 << "ignoring non-existent endpoint "
                 << endpoint->bssid_string();
    return;
  }
  endpoints_.erase(i);
  if (current_endpoint_ == endpoint) {
    current_endpoint_ = nullptr;
  }
  UpdateFromEndpoints();
}

void WiFiService::NotifyCurrentEndpoint(
    const WiFiEndpointConstRefPtr& endpoint) {
  DCHECK(!endpoint || (endpoints_.find(endpoint) != endpoints_.end()));
  DCHECK(!endpoint || IsSecurityMatch(endpoint->security_mode()));
  current_endpoint_ = endpoint;
  UpdateFromEndpoints();
}

void WiFiService::NotifyEndpointUpdated(
    const WiFiEndpointConstRefPtr& endpoint) {
  DCHECK(endpoints_.find(endpoint) != endpoints_.end());
  UpdateFromEndpoints();
}

std::string WiFiService::GetStorageIdentifier() const {
  return storage_identifier_;
}

bool WiFiService::SetPassphrase(const std::string& passphrase, Error* error) {
  if (security_class() == kSecurityClassWep) {
    ValidateWEPPassphrase(passphrase, error);
  } else if (security_class() == kSecurityClassPsk) {
    ValidateWPAPassphrase(passphrase, error);
  } else {
    error->Populate(Error::kIllegalOperation);
  }

  if (!error->IsSuccess()) {
    LOG(ERROR) << "Passphrase could not be set on service: " << log_name()
               << " error: " << error->message();
    return false;
  }

  return SetPassphraseInternal(passphrase, Service::kReasonPropertyUpdate);
}

bool WiFiService::SetPassphraseInternal(
    const std::string& passphrase, Service::UpdateCredentialsReason reason) {
  if (passphrase_ == passphrase) {
    // After a user logs in, Chrome may reconfigure a Service with the
    // same credentials as before login. When that occurs, we don't
    // want to bump the user off the network. Hence, we MUST return
    // early. (See crbug.com/231456#c17)
    return false;
  }
  passphrase_ = passphrase;
  OnCredentialChange(reason);
  return true;
}

// ClearPassphrase is separate from SetPassphrase, because the default
// value for |passphrase_| would not pass validation.
void WiFiService::ClearPassphrase(Error* /*error*/) {
  passphrase_.clear();
  ClearCachedCredentials();
  UpdateConnectable();
}

void WiFiService::SetSupplicantMACPolicy(KeyValueStore& kv) const {
  kv.Set(WPASupplicant::kNetworkPropertyMACAddrPolicy,
         RandomizationPolicyToSupplicantPolicy.at(random_mac_policy_));
}

std::string WiFiService::GetMACPolicy(Error* /*error*/) {
  return RandomizationPolicyMap.at(random_mac_policy_);
}

bool WiFiService::SetMACPolicyInternal(const std::string& policy,
                                       Error* error,
                                       bool only_property) {
  SLOG(this, 2) << __func__;
  auto ret = std::find_if(
      RandomizationPolicyMap.begin(), RandomizationPolicyMap.end(),
      [policy](const std::pair<RandomizationPolicy, std::string>& it) {
        return it.second == policy;
      });
  if (ret == RandomizationPolicyMap.end()) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kInvalidArguments,
        base::StringPrintf("Invalid random MAC address policy: %s.",
                           policy.c_str()));
    return false;
  }

  if (ret->first != RandomizationPolicy::Hardware) {
    // There might be no wifi_ during Load(), but then random_mac_supported()
    // has already been checked.
    if (wifi_ && !wifi_->random_mac_supported()) {
      Error::PopulateAndLog(
          FROM_HERE, error, Error::kIllegalOperation,
          "MAC Address randomization not supported by hardware.");
      return false;
    }
    // Some airline providers use aged APs that do not support locally
    // generated bit. Prevent address randomization in such cases.
    if (base::Contains(SSIDsExcludedFromRandomization, friendly_name_)) {
      Error::PopulateAndLog(
          FROM_HERE, error, Error::kNotSupported,
          "MAC Address randomization not supported for this SSID.");
      return false;
    }
  }
  random_mac_policy_ = ret->first;
  if (!only_property) {
    current_mac_policy_ = random_mac_policy_;
  }
  return true;
}

bool WiFiService::SetMACPolicy(const std::string& policy, Error* error) {
  return SetMACPolicyInternal(policy, error, true);
}

Service::Service::TetheringState WiFiService::GetTethering() const {
  if (IsConnected() && attached_network() &&
      attached_network()->IsConnectedViaTether()) {
    return TetheringState::kConfirmed;
  }

  // Only perform BSSID tests if there is exactly one matching endpoint,
  // so we ignore campuses that may use locally administered BSSIDs.
  if (endpoints_.size() == 1 &&
      (*endpoints_.begin())->has_tethering_signature()) {
    return TetheringState::kSuspected;
  }

  return TetheringState::kNotDetected;
}

std::string WiFiService::GetLoadableStorageIdentifier(
    const StoreInterface& storage) const {
  std::set<std::string> groups =
      storage.GetGroupsWithProperties(GetStorageProperties());
  if (groups.empty()) {
    LOG(WARNING) << "Configuration for service " << log_name()
                 << " is not available in the persistent store";
    return "";
  }
  if (groups.size() > 1) {
    LOG(WARNING) << "More than one configuration for service " << log_name()
                 << " is available; choosing the first.";
  }
  return *groups.begin();
}

bool WiFiService::IsLoadableFrom(const StoreInterface& storage) const {
  return !storage.GetGroupsWithProperties(GetStorageProperties()).empty();
}

bool WiFiService::IsVisible() const {
  // WiFi Services should be displayed only if they are in range of endpoints
  // that have shown up in a scan and whose BSSID are allowlisted, or if the
  // service is actively being connected.
  return HasBSSIDConnectableEndpoints() || IsConnected() || IsConnecting();
}

bool WiFiService::Load(const StoreInterface* storage) {
  std::string id = GetLoadableStorageIdentifier(*storage);
  if (id.empty()) {
    return false;
  }

  // Set our storage identifier to match the storage name in the Profile.
  storage_identifier_ = id;

  // Load properties common to all Services.
  if (!Service::Load(storage)) {
    return false;
  }

  // Load properties specific to WiFi services.
  storage->GetBool(id, kStorageHiddenSSID, &hidden_ssid_);

  // MAC address-related load is done inside its object.
  if (!mac_address_.Load(storage, id)) {
    LOG(ERROR) << "Failed to load MAC Address. Using Random address instead.";
    // Make sure address is cleared.
    mac_address_.Clear();
    // Address will be re-randomized at next UpdateMACAddress().
    // The error has been handled here, do not return false;
  }
  storage->GetBool(id, kStoragePortalDetected, &was_portal_detected_);

  std::string mac_policy;
  Error error;
  if (storage->GetString(id, kStorageMACPolicy, &mac_policy)) {
    // Loaded random MAC policy is also a current one so that during connection
    // in UpdateMACAddress we do not falsely detect policy change.
    if (!SetMACPolicyInternal(mac_policy, &error, false)) {
      return false;
    }
  }

  uint64_t delta;
  if (storage->GetUint64(id, kStorageLeaseExpiry, &delta)) {
    dhcp4_lease_expiry_.FromDeltaSinceWindowsEpoch(base::Microseconds(delta));
  }
  if (storage->GetUint64(id, kStorageDisconnectTime, &delta)) {
    disconnect_time_.FromDeltaSinceWindowsEpoch(base::Microseconds(delta));
  }

  // NB: mode, security and ssid parameters are never read in from
  // Load() as they are provided from the scan.

  std::string passphrase;
  if (storage->GetCryptedString(id, kStorageDeprecatedPassphrase,
                                kStorageCredentialPassphrase, &passphrase)) {
    if (SetPassphraseInternal(passphrase, Service::kReasonCredentialsLoaded)) {
      SLOG(this, 2) << "Loaded passphrase in WiFiService::Load.";
    }
  }

  std::string security_str;
  if (storage->GetString(id, kStorageSecurity, &security_str)) {
    WiFiSecurity security(security_str);
    if (security_.IsValid() && security_ != security) {
      SLOG(this, 2) << "Overwriting Security property: " << security_ << " <- "
                    << security_str;
    }
    security_ = security;
    security_.Freeze();
  }

  expecting_disconnect_ = false;

  // Passpoint might not be present.
  std::string credentials_id;
  if (storage->GetString(id, WiFiService::kStoragePasspointCredentials,
                         &credentials_id)) {
    PasspointCredentialsRefPtr creds =
        provider_->FindCredentials(credentials_id);
    if (!creds) {
      LOG(ERROR) << "Failed to load Passpoint credentials " << credentials_id;
      return false;
    }
    parent_credentials_ = creds;
  }
  storage->GetUint64(id, WiFiService::kStoragePasspointMatchPriority,
                     &match_priority_);

  Error bssid_allowlist_error;
  std::vector<std::string> bssid_allowlist;
  storage->GetStringList(id, kStorageBSSIDAllowlist, &bssid_allowlist);
  SetBSSIDAllowlist(bssid_allowlist, &bssid_allowlist_error);

  if (!bssid_allowlist_error.IsSuccess()) {
    LOG(ERROR) << "Failed to load BSSID allowlist: ["
               << base::JoinString(bssid_allowlist, ", ") << "]";
    return false;
  }

  std::string bssid_requested;
  if (storage->GetString(id, kStorageBSSIDRequested, &bssid_requested)) {
    bssid_requested_ = bssid_requested;
  }

  return true;
}

void WiFiService::MigrateDeprecatedStorage(StoreInterface* storage) {
  Service::MigrateDeprecatedStorage(storage);

  const std::string id = GetStorageIdentifier();
  CHECK(storage->ContainsGroup(id));

  // Deprecated keys that have not been loaded from storage since at least M84.
  // TODO(crbug.com/1120161): Remove code after M89.
  storage->DeleteKey(id, "WiFi.Security");
  storage->DeleteKey(id, "WiFi.FTEnabled");

  // Save the plaintext passphrase in M86+. TODO: Remove code after M89.
  storage->SetString(id, kStorageCredentialPassphrase, passphrase_);

  // M85 key to delete after M89:
  // kStorageDeprecatedPassphrase (crbug.com/1084279)
}

bool WiFiService::Save(StoreInterface* storage) {
  // Save properties common to all Services.
  if (!Service::Save(storage)) {
    return false;
  }

  // Save properties specific to WiFi services.
  const std::string id = GetStorageIdentifier();
  storage->SetBool(id, kStorageHiddenSSID, hidden_ssid_);
  storage->SetString(id, kStorageMode, mode_);
  // MAC Address-related data is saved by its object.
  mac_address_.Save(storage, id);
  storage->SetBool(id, kStoragePortalDetected, was_portal_detected_);
  storage->SetString(id, kStorageMACPolicy,
                     RandomizationPolicyMap.at(random_mac_policy_));
  storage->SetUint64(
      id, kStorageLeaseExpiry,
      dhcp4_lease_expiry_.ToDeltaSinceWindowsEpoch().InMicroseconds());
  storage->SetUint64(
      id, kStorageDisconnectTime,
      disconnect_time_.ToDeltaSinceWindowsEpoch().InMicroseconds());
  // This saves both the plaintext and rot47 versions of the passphrase.
  // TODO(crbug.com/1084279): Save just the plaintext passphrase after M89.
  storage->SetCryptedString(id, kStorageDeprecatedPassphrase,
                            kStorageCredentialPassphrase, passphrase_);
  storage->SetString(id, kStorageSecurityClass, security_class());
  if (security_.IsValid() && security_.IsFrozen()) {
    storage->SetString(id, kStorageSecurity, security_.ToString());
  }
  storage->SetString(id, kStorageSSID, hex_ssid_);
  if (parent_credentials_) {
    storage->SetString(id, kStoragePasspointCredentials,
                       parent_credentials_->id());
  }
  storage->SetUint64(id, kStoragePasspointMatchPriority, match_priority_);

  Error unused_error;
  storage->SetStringList(id, kStorageBSSIDAllowlist,
                         GetBSSIDAllowlist(&unused_error));
  storage->SetString(id, kStorageBSSIDRequested, bssid_requested_);

  return true;
}

bool WiFiService::Unload() {
  // Expect the service to be disconnected if is currently connected or
  // in the process of connecting.
  if (IsConnected() || IsConnecting()) {
    expecting_disconnect_ = true;
  } else {
    expecting_disconnect_ = false;
  }
  Service::Unload();
  if (wifi_) {
    wifi_->DestroyServiceLease(*this);
  }
  hidden_ssid_ = false;
  ResetSuspectedCredentialFailures();
  Error unused_error;
  ClearPassphrase(&unused_error);
  mac_address_.Clear();
  random_mac_policy_ = RandomizationPolicy::Hardware;
  current_mac_policy_ = RandomizationPolicy::Hardware;
  match_priority_ = kDefaultMatchPriority;
  PasspointCredentialsRefPtr creds = parent_credentials_;
  parent_credentials_ = nullptr;
  bssid_allowlist_.clear();
  bssid_requested_.clear();
  return provider_->OnServiceUnloaded(this, creds);
}

void WiFiService::SetState(ConnectState state) {
  Service::SetState(state);
  // In case we're pretty much sure we are dealing with a Captive Portal,
  // remember this fact, so that we won't reshuffle MAC address later.
  if (state == kStateRedirectFound) {
    was_portal_detected_ = true;
  } else if (state == kStateConnected) {
    // Now that we are connected let's check if we have a DHCP lease ...
    dhcp4_lease_expiry_ = base::Time();
    if (wifi_) {
      // ... and get its expiry so that next time we attempt to connect we know
      // if the lease is still (potentially) valid and don't regenerate MAC
      // address for this network.
      std::optional<base::TimeDelta> lease_time =
          wifi_->GetPrimaryNetwork()->TimeToNextDHCPLeaseRenewal();
      if (lease_time.has_value()) {
        dhcp4_lease_expiry_ = clock_->Now() + lease_time.value();
      } else {
        LOG(WARNING) << "Failed to get lease time";
      }
    }
  }
  if (IsConnectedState(previous_state()) && !IsConnectedState(state)) {
    disconnect_time_ = clock_->Now();
  }
  SetRoamState(Service::kRoamStateIdle);
  NotifyIfVisibilityChanged();
}

bool WiFiService::IsSecurityMatch(WiFiSecurity::Mode mode) const {
  if (security_.IsValid()) {
    return security_.Combine(mode).IsValid();
  }

  return ComputeSecurityClass(mode) == security_class();
}

bool WiFiService::IsSecurityMatch(const std::string& sec_class) const {
  return sec_class == security_class();
}

void WiFiService::AddSuspectedCredentialFailure() {
  ++suspected_credential_failures_;
}

bool WiFiService::CheckSuspectedCredentialFailure() {
  if (!has_ever_connected()) {
    return true;
  }
  return suspected_credential_failures_ >= kSuspectedCredentialFailureThreshold;
}

bool WiFiService::AddAndCheckSuspectedCredentialFailure() {
  AddSuspectedCredentialFailure();
  return CheckSuspectedCredentialFailure();
}

void WiFiService::ResetSuspectedCredentialFailures() {
  suspected_credential_failures_ = 0;
}

void WiFiService::InitializeCustomMetrics() const {
  SLOG(this, 2) << __func__ << " for " << log_name();
  auto histogram = metrics()->GetFullMetricName(
      Metrics::kMetricTimeToJoinMillisecondsSuffix, technology());
  metrics()->AddServiceStateTransitionTimer(
      *this, histogram, Service::kStateAssociating, Service::kStateConfiguring);
}

void WiFiService::SendPostReadyStateMetrics(
    int64_t time_resume_to_ready_milliseconds) const {
  metrics()->SendEnumToUMA(
      metrics()->GetFullMetricName(Metrics::kMetricNetworkChannelSuffix,
                                   technology()),
      Metrics::WiFiFrequencyToChannel(frequency_),
      Metrics::kMetricNetworkChannelMax);

  uint16_t ap_phy = ap_physical_mode_;
  if (ap_phy >= Metrics::kWiFiNetworkPhyModeMax) {
    LOG(WARNING) << "Invalid AP PHY mode " << ap_phy;
    ap_phy = Metrics::kWiFiNetworkPhyModeUndef;
  }
  metrics()->SendEnumToUMA(
      metrics()->GetFullMetricName(Metrics::kMetricNetworkPhyModeSuffix,
                                   technology()),
      static_cast<Metrics::WiFiNetworkPhyMode>(ap_phy),
      Metrics::kWiFiNetworkPhyModeMax);

  Metrics::WirelessSecurity security_uma;
  if (security_.IsValid()) {
    security_uma = Metrics::WiFiSecurityToEnum(security_);
  } else {
    LOG(WARNING) << "Invalid Security property in ready state.";
    security_uma = Metrics::WiFiSecurityClassToEnum(security_class_);
  }
  if (security_uma == Metrics::kWirelessSecurityUnknown) {
    LOG(WARNING) << "Unknown Security property in ready state.";
  }
  // Special case for Dynamic WEP, let's report it separately for the initial
  // phase of FGSec deployment. TODO(b/226138492): Remove this afterwards.
  if (security_ == WiFiSecurity::kWep && Is8021x()) {
    security_uma = Metrics::kWirelessSecurityWepEnterprise;
  }
  metrics()->SendEnumToUMA(
      metrics()->GetFullMetricName(Metrics::kMetricNetworkSecuritySuffix,
                                   technology()),
      security_uma, Metrics::kMetricNetworkSecurityMax);

  if (Is8021x()) {
    eap()->OutputConnectionMetrics(metrics(), technology());
  }

  // We invert the sign of the signal strength value, since UMA histograms
  // cannot represent negative numbers (it stores them but cannot display
  // them), and dBm values of interest start at 0 and go negative from there.
  metrics()->SendToUMA(
      metrics()->GetFullMetricName(Metrics::kMetricNetworkSignalStrengthSuffix,
                                   technology()),
      -raw_signal_strength_, Metrics::kMetricNetworkSignalStrengthMin,
      Metrics::kMetricNetworkSignalStrengthMax,
      Metrics::kMetricNetworkSignalStrengthNumBuckets);

  if (time_resume_to_ready_milliseconds > 0) {
    metrics()->SendToUMA(
        metrics()->GetFullMetricName(
            Metrics::kMetricTimeResumeToReadyMillisecondsSuffix, technology()),
        time_resume_to_ready_milliseconds,
        Metrics::kTimerHistogramMillisecondsMin,
        Metrics::kTimerHistogramMillisecondsMax,
        Metrics::kTimerHistogramNumBuckets);
  }
}

// private methods
void WiFiService::HelpRegisterConstDerivedString(
    base::StringPiece name, std::string (WiFiService::*get)(Error*)) {
  mutable_store()->RegisterDerivedString(
      name, StringAccessor(new CustomAccessor<WiFiService, std::string>(
                this, get, nullptr)));
}

void WiFiService::HelpRegisterDerivedString(
    base::StringPiece name,
    std::string (WiFiService::*get)(Error* error),
    bool (WiFiService::*set)(const std::string&, Error*)) {
  mutable_store()->RegisterDerivedString(
      name, StringAccessor(
                new CustomAccessor<WiFiService, std::string>(this, get, set)));
}

void WiFiService::HelpRegisterDerivedStrings(
    base::StringPiece name,
    Strings (WiFiService::*get)(Error* error),
    bool (WiFiService::*set)(const Strings&, Error*)) {
  mutable_store()->RegisterDerivedStrings(
      name, StringsAccessor(
                new CustomAccessor<WiFiService, Strings>(this, get, set)));
}

void WiFiService::HelpRegisterWriteOnlyDerivedString(
    base::StringPiece name,
    bool (WiFiService::*set)(const std::string&, Error*),
    void (WiFiService::*clear)(Error* error),
    const std::string* default_value) {
  mutable_store()->RegisterDerivedString(
      name,
      StringAccessor(new CustomWriteOnlyAccessor<WiFiService, std::string>(
          this, set, clear, default_value)));
}

void WiFiService::HelpRegisterDerivedUint16(
    base::StringPiece name,
    uint16_t (WiFiService::*get)(Error* error),
    bool (WiFiService::*set)(const uint16_t& value, Error* error),
    void (WiFiService::*clear)(Error* error)) {
  mutable_store()->RegisterDerivedUint16(
      name, Uint16Accessor(new CustomAccessor<WiFiService, uint16_t>(
                this, get, set, clear)));
}

void WiFiService::HelpRegisterConstDerivedInt32(
    base::StringPiece name, int32_t (WiFiService::*get)(Error* error)) {
  mutable_store()->RegisterDerivedInt32(
      name, Int32Accessor(
                new CustomAccessor<WiFiService, int32_t>(this, get, nullptr)));
}

void WiFiService::OnConnect(Error* error) {
  WiFiRefPtr wifi = wifi_;
  if (!wifi) {
    // If this is a hidden service before it has been found in a scan, we
    // may need to late-bind to any available WiFi Device.  We don't actually
    // set |wifi_| in this case since we do not yet see any endpoints.  This
    // will mean this service is not disconnectable until an endpoint is
    // found.
    wifi = ChooseDevice();
    if (!wifi) {
      LOG(ERROR) << "Can't connect to: " << log_name()
                 << ": Cannot find a WiFi device.";
      Error::PopulateAndLog(FROM_HERE, error, Error::kOperationFailed,
                            Error::GetDefaultMessage(Error::kOperationFailed));
      return;
    }
  }

  if (wifi->IsCurrentService(this)) {
    LOG(WARNING) << "Can't connect to: " << log_name()
                 << ": IsCurrentService, but not connected. State: "
                 << GetStateString();
    Error::PopulateAndLog(FROM_HERE, error, Error::kInProgress,
                          Error::GetDefaultMessage(Error::kInProgress));
    return;
  }

  // Report number of BSSes available for this service.
  metrics()->SendToUMA(Metrics::kMetricWifiAvailableBSSes, endpoints_.size());

  if (Is8021x()) {
    // If EAP key management is not set, set to a default.
    if (GetEAPKeyManagement().empty())
      SetEAPKeyManagement(
          std::string(WPASupplicant::kKeyManagementWPAEAP) + " " +
          std::string(WPASupplicant::kKeyManagementWPAEAPSHA256));
    ClearEAPCertification();
  }

  security_.Freeze();

  expecting_disconnect_ = false;
  wifi->ConnectTo(this, error);
}

Metrics::WiFiConnectionAttemptInfo WiFiService::ConnectionAttemptInfo() const {
  int ap_oui = 0xFFFFFFFF;
  auto bssid_bytes = Device::MakeHardwareAddressFromString(bssid());
  if (bssid_bytes.empty()) {
    // Log an error but still emit the event (with OUI=0xFFFFFFFF) since the
    // rest of the data is still useful.
    LOG(ERROR) << "Invalid AP BSSID";
  } else {
    ap_oui = (bssid_bytes[0] << 16) | (bssid_bytes[1] << 8) | (bssid_bytes[2]);
  }

  Metrics::WiFiConnectionAttemptInfo info;
  info.type = Metrics::kAttemptTypeUnknown;  // TODO(b/203692510)
  info.mode = static_cast<Metrics::WiFiNetworkPhyMode>(ap_physical_mode());
  info.security = Metrics::WiFiSecurityToEnum(security());
  info.eap_inner = Metrics::EapInnerProtocolStringToEnum(eap()->inner_method());
  info.eap_outer = Metrics::EapOuterProtocolStringToEnum(eap()->method());
  info.band = Metrics::WiFiChannelToFrequencyRange(
      Metrics::WiFiFrequencyToChannel(frequency()));
  info.channel = Metrics::WiFiFrequencyToChannel(frequency());
  info.rssi = SignalLevel();
  info.ssid = friendly_name_;
  info.bssid = bssid();
  info.provisioning_mode = Metrics::kProvisionUnknown;  // TODO(b/203692510)
  info.ssid_hidden = hidden_ssid();
  info.ap_oui = ap_oui;
  if ((false)) {
    if (current_endpoint_) {
      info.ap_features =
          Metrics::ConvertEndPointFeatures(current_endpoint_.get());
    }
  }

  return info;
}

void WiFiService::ValidateTagState(SessionTagExpectedState expected_state,
                                   const char* uma_suffix) const {
  Metrics::WiFiSessionTagState uma_tag_state =
      Metrics::kWiFiSessionTagStateExpected;
  switch (expected_state) {
    case kSessionTagExpectedValid:
      if (session_tag_ == kSessionTagInvalid) {
        uma_tag_state = Metrics::kWiFiSessionTagStateUnexpected;
      }
      break;
    case kSessionTagExpectedUnset:
      if (session_tag_ != kSessionTagInvalid) {
        uma_tag_state = Metrics::kWiFiSessionTagStateUnexpected;
      }
      break;
  }
  if (uma_tag_state != Metrics::kWiFiSessionTagStateExpected) {
    SLOG(this, kSessionTagMinimumLogVerbosity)
        << __func__ << ": " << uma_suffix << ": Found an "
        << (expected_state == kSessionTagExpectedValid ? "invalid" : "existing")
        << " session tag.";
  }
  metrics()->SendEnumToUMA(
      base::StringPrintf("%s.%s", Metrics::kWiFiSessionTagStateMetricPrefix,
                         uma_suffix),
      uma_tag_state, Metrics::kWiFiSessionTagStateMax);
}

void WiFiService::EmitConnectionAttemptEvent() {
  ValidateTagState(kSessionTagExpectedUnset,
                   Metrics::kWiFiSessionTagConnectionAttemptSuffix);

  // When we attempt to connect to an AP, we generate a session tag that will be
  // used to mark the structured metrics events that belong to the same session.
  // We use a random number as a tag to guarantee uniqueness of the tag so that
  // the server-side pipeline can differentiate events that belong to different
  // sessions.
  session_tag_ = base::RandUint64();
  metrics()->NotifyWiFiConnectionAttempt(ConnectionAttemptInfo(), session_tag_);
}

void WiFiService::EmitConnectionAttemptResultEvent(
    Service::ConnectFailure failure) {
  ValidateTagState(kSessionTagExpectedValid,
                   Metrics::kWiFiSessionTagConnectionAttemptResultSuffix);

  auto service_error = Metrics::ConnectFailureToServiceErrorEnum(failure);
  metrics()->NotifyWiFiConnectionAttemptResult(service_error, session_tag_);
  if (parent_credentials_) {
    metrics()->SendEnumToUMA(Metrics::kMetricPasspointConnectionResult,
                             service_error);
  }
  if (failure != Service::kFailureNone) {
    // If the connection attempt was not successful there won't be a
    // corresponding disconnection event. Reset the session tag.
    session_tag_ = kSessionTagInvalid;
  }
}

void WiFiService::EmitDisconnectionEvent(
    Metrics::WiFiDisconnectionType type,
    IEEE_80211::WiFiReasonCode disconnect_reason) {
  ValidateTagState(kSessionTagExpectedValid,
                   Metrics::kWiFiSessionTagDisconnectionSuffix);

  metrics()->NotifyWiFiDisconnection(type, disconnect_reason, session_tag_);
  // No more events in the session now that we've disconnected, reset the tag.
  session_tag_ = kSessionTagInvalid;
}

void WiFiService::EmitLinkQualityTriggerEvent(
    Metrics::WiFiLinkQualityTrigger trigger) const {
  ValidateTagState(kSessionTagExpectedValid,
                   Metrics::kWiFiSessionTagLinkQualityTriggerSuffix);
  metrics()->NotifyWiFiLinkQualityTrigger(trigger, session_tag_);
}

void WiFiService::EmitLinkQualityReportEvent(
    const Metrics::WiFiLinkQualityReport& report) const {
  ValidateTagState(kSessionTagExpectedValid,
                   Metrics::kWiFiSessionTagLinkQualityReportSuffix);
  metrics()->NotifyWiFiLinkQualityReport(report, session_tag_);
}

WiFiService::UpdateMACAddressRet WiFiService::UpdateMACAddress() {
  UpdateMACAddressRet ret{std::string(),
                          current_mac_policy_ != random_mac_policy_};
  bool rotating = false;

  current_mac_policy_ = random_mac_policy_;

  switch (random_mac_policy_) {
    case RandomizationPolicy::PersistentRandom:
      // For persistent policy we can rotate only in open networks and when
      // there was no captive portal detected.
      rotating = security_ == WiFiSecurity::kNone && !was_portal_detected_;
      break;
    case RandomizationPolicy::NonPersistentRandom:
      // For forced non-persistent policy we always rotate.
      rotating = true;
      break;
    default:
      // Other modes do not require explicit address to be set.
      return ret;
  }

  const auto now = clock_->Now();
  // If we get here then we need to have MAC set - make sure it is.
  bool change = ret.policy_change || !mac_address_.is_set();
  // For rotating MAC check its expiration and lease/disconnect times.
  if (!change && rotating) {
    change = mac_address_.IsExpired(now) ||
             (!dhcp4_lease_expiry_.is_null() && now > dhcp4_lease_expiry_ &&
              now > disconnect_time_ + kMinDisconnectOffset);
  }

  if (change) {
    mac_address_.Randomize();
    if (rotating) {
      mac_address_.set_expiration_time(now +
                                       MACAddress::kDefaultExpirationTime);
    } else {
      mac_address_.set_expiration_time(MACAddress::kNotExpiring);
    }
    ret.mac = mac_address_.ToString();
  }

  return ret;
}

KeyValueStore WiFiService::GetSupplicantConfigurationParameters() const {
  KeyValueStore params;

  params.Set<uint32_t>(WPASupplicant::kNetworkPropertyMode,
                       WiFiEndpoint::ModeStringToUint(mode_));

  if (Is8021x()) {
    eap()->PopulateSupplicantProperties(certificate_file_.get(), &params);
  } else if (security_class() == kSecurityClassPsk) {
    // NB: WPA3-SAE uses RSN protocol.
    std::string psk_proto;
    if (security().IsValid()) {
      if (security() == WiFiSecurity::kWpa) {
        psk_proto = WPASupplicant::kSecurityModeWPA;
      } else if (security() == WiFiSecurity::kWpaWpa2 ||
                 security() == WiFiSecurity::kWpaAll) {
        psk_proto = base::StringPrintf("%s %s", WPASupplicant::kSecurityModeWPA,
                                       WPASupplicant::kSecurityModeRSN);
      } else {  // WPA2 and WPA3 use RSN.
        psk_proto = WPASupplicant::kSecurityModeRSN;
      }
    } else {
      psk_proto = base::StringPrintf("%s %s", WPASupplicant::kSecurityModeWPA,
                                     WPASupplicant::kSecurityModeRSN);
    }

    params.Set<std::string>(WPASupplicant::kPropertySecurityProtocol,
                            psk_proto);
    std::vector<uint8_t> passphrase_bytes;
    Error error;
    ParseWPAPassphrase(passphrase_, &passphrase_bytes, &error);
    if (!error.IsSuccess()) {
      LOG(ERROR) << "Invalid passphrase";
    } else if (!passphrase_bytes.empty()) {
      params.Set<std::vector<uint8_t>>(WPASupplicant::kPropertyPreSharedKey,
                                       passphrase_bytes);
    } else {
      params.Set<std::string>(WPASupplicant::kPropertyPreSharedKey,
                              passphrase_);
    }
  } else if (security_class() == kSecurityClassWep) {
    params.Set<std::string>(WPASupplicant::kPropertyAuthAlg,
                            WPASupplicant::kSecurityAuthAlg);
    Error unused_error;
    int key_index;
    std::vector<uint8_t> password_bytes;
    ParseWEPPassphrase(passphrase_, &key_index, &password_bytes, &unused_error);
    params.Set<std::vector<uint8_t>>(
        WPASupplicant::kPropertyWEPKey + base::NumberToString(key_index),
        password_bytes);
    params.Set<uint32_t>(WPASupplicant::kPropertyWEPTxKeyIndex, key_index);
  } else if (security_class() == kSecurityClassNone) {
    // Nothing special to do here.
  } else {
    NOTIMPLEMENTED() << "Unsupported security method " << security_class();
  }

  // TODO(b/226138492): This was potentially loaded from (old) storage -- we
  // usually want to derive this exclusively from Security or SecurityClass, but
  // in rare cases (only 802.1X-WEP, AFAIK?) we want to allow Chrome to set it
  // manually.  Take a second look at this when Dynamic WEP gets removed.
  auto key_mgmt = key_management();
  if (manager()->GetFTEnabled(nullptr)) {
    // Append the FT analog for each non-FT key management method.
    bool ft_eap = false;
    bool ft_psk = false;
    for (const auto& mgmt :
         base::SplitString(key_mgmt, base::kWhitespaceASCII,
                           base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY)) {
      std::string ft_mgmt;
      if (mgmt == WPASupplicant::kKeyManagementWPAPSK ||
          mgmt == WPASupplicant::kKeyManagementWPAPSKSHA256) {
        // FT is already SHA256, so it matches both PSK and PSK-SHA256.
        if (ft_psk)
          continue;  // Already added this once.
        ft_mgmt = WPASupplicant::kKeyManagementFTPSK;
        ft_psk = true;
      } else if (mgmt == WPASupplicant::kKeyManagementWPAEAP ||
                 mgmt == WPASupplicant::kKeyManagementWPAEAPSHA256) {
        // FT is already SHA256, so it matches both EAP and EAP-SHA256.
        if (ft_eap)
          continue;  // Already added this once.
        ft_mgmt = WPASupplicant::kKeyManagementFTEAP;
        ft_eap = true;
      } else if (mgmt == WPASupplicant::kKeyManagementSAE) {
        ft_mgmt = WPASupplicant::kKeyManagementFTSAE;
      } else if (mgmt != WPASupplicant::kKeyManagementNone) {
        LOG(ERROR) << "Unrecognized key management protocol " << mgmt;
        continue;
      }
      key_mgmt += base::StringPrintf(" %s", ft_mgmt.c_str());
    }
  }
  params.Set<std::string>(WPASupplicant::kNetworkPropertyEapKeyManagement,
                          key_mgmt);

  params.Set<std::vector<uint8_t>>(WPASupplicant::kNetworkPropertySSID, ssid_);

  SLOG(this, 2) << "Sending MAC policy: "
                << RandomizationPolicyMap.at(random_mac_policy_)
                << " to supplicant.";
  SetSupplicantMACPolicy(params);
  switch (random_mac_policy_) {
    case RandomizationPolicy::PersistentRandom:
    // Fall through. For non-persistent policy we use the same WPA supplicant
    // policy as in persistent case, just supply MAC that is non-persistent.
    case RandomizationPolicy::NonPersistentRandom:
      params.Set(WPASupplicant::kNetworkPropertyMACAddrValue,
                 mac_address_.ToString());
      break;
    default:
      break;  // No address needs filling in for other policies.
  }

  // BSSID allowlist
  Error unused_error;
  Strings bssid_allowlist = GetBSSIDAllowlistConst(&unused_error);
  if (!bssid_allowlist.empty()) {
    params.Set<std::string>(WPASupplicant::kNetworkPropertyBSSIDAccept,
                            base::JoinString(bssid_allowlist, " "));
  }

  if (!bssid_requested_.empty()) {
    params.Set<std::string>(WPASupplicant::kNetworkPropertyBSSID,
                            bssid_requested_);
  }

  return params;
}

void WiFiService::OnDisconnect(Error* error, const char* /*reason*/) {
  wifi_->DisconnectFrom(this);
}

bool WiFiService::IsDisconnectable(Error* error) const {
  if (!Service::IsDisconnectable(error))
    return false;

  if (!wifi_) {
    CHECK(!IsConnected())
        << "WiFi device does not exist. Cannot disconnect service "
        << log_name();
    // If we are connecting to a hidden service, but have not yet found
    // any endpoints, we could end up with a disconnect request without
    // a wifi_ reference.
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kOperationFailed,
        base::StringPrintf(
            "WiFi endpoints do not (yet) exist. Cannot disconnect service %s",
            log_name().c_str()));
    return false;
  }
  if (!wifi_->IsPendingService(this) && !wifi_->IsCurrentService(this)) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kOperationFailed,
        base::StringPrintf("WiFi Service not pending or current: %s",
                           log_name().c_str()));
    return false;
  }
  return true;
}

bool WiFiService::IsMeteredByServiceProperties() const {
  if (!parent_credentials_) {
    return false;
  }

  // A Wi-Fi network provided by a set of Passpoint credentials may be metered.
  return parent_credentials_->metered_override();
}

RpcIdentifier WiFiService::GetDeviceRpcId(Error* error) const {
  if (!wifi_) {
    error->Populate(Error::kNotFound, "Not associated with a device");
    return DBusControl::NullRpcIdentifier();
  }
  return wifi_->GetRpcIdentifier();
}

// It's possible to have a WPA3 Service on a system that doesn't support it. To
// avoid disruption upon making a bad Connect decision, we rule out
// incompatible Services here.
bool WiFiService::IsWPA3Connectable() const {
  if (!wifi_) {
    return false;
  }

  if (wifi_->SupportsWPA3()) {
    return true;
  }

  // PSK property means WPA2 compatibility. If any endpoint supports WPA2/3
  // transitional, then we assume the network will be connectable.
  for (const auto& endpoint : endpoints_) {
    if (endpoint->has_psk_property() && IsBSSIDConnectable(endpoint)) {
      return true;
    }
  }

  return false;
}

bool WiFiService::HasOnlyWPA3Endpoints() const {
  if (security_ == WiFiSecurity::kWpa3) {
    return true;
  }
  if (security_ == WiFiSecurity::kWpaAll ||
      security_ == WiFiSecurity::kWpa2Wpa3) {
    return base::ranges::all_of(endpoints_, [](auto ep) {
      return ep->security_mode() == WiFiSecurity::kWpa3;
    });
  }
  return false;
}

void WiFiService::UpdateConnectable() {
  bool is_connectable = false;
  if (security_class() == kSecurityClassNone) {
    DCHECK(passphrase_.empty());
    need_passphrase_ = false;
    is_connectable = true;
  } else if (Is8021x()) {
    is_connectable = Is8021xConnectable();
  } else if (security_class() == kSecurityClassWep ||
             security_class() == kSecurityClassPsk) {
    need_passphrase_ = passphrase_.empty();
    is_connectable = !need_passphrase_;
    if (is_connectable && HasOnlyWPA3Endpoints()) {
      is_connectable = IsWPA3Connectable();
    }
  }
  SetConnectable(is_connectable);
}

void WiFiService::UpdateFromEndpoints() {
  const WiFiEndpoint* representative_endpoint = nullptr;

  if (current_endpoint_) {
    representative_endpoint = current_endpoint_.get();
  } else {
    int16_t best_signal = WiFiService::SignalLevelMin;
    for (const auto& endpoint : endpoints_) {
      if (endpoint->signal_strength() >= best_signal) {
        best_signal = endpoint->signal_strength();
        representative_endpoint = endpoint.get();
      }
    }
  }

  WiFiRefPtr wifi;
  if (representative_endpoint) {
    wifi = representative_endpoint->device();
    if (((current_endpoint_ == representative_endpoint) &&
         (bssid_ != representative_endpoint->bssid_string() ||
          frequency_ != representative_endpoint->frequency())) ||
        abs(representative_endpoint->signal_strength() - raw_signal_strength_) >
            10) {
      LOG(INFO) << "Rep endpoint updated for " << log_name() << ". "
                << "sig: " << representative_endpoint->signal_strength() << ", "
                << "sec: " << representative_endpoint->security_mode() << ", "
                << "freq: " << representative_endpoint->frequency();
    }
  } else if (IsConnected() || IsConnecting()) {
    LOG(WARNING) << "Service " << log_name()
                 << " will disconnect due to no remaining endpoints.";
  }

  SetWiFi(wifi);

  std::set<uint16_t> frequency_set;
  for (const auto& endpoint : endpoints_) {
    frequency_set.insert(endpoint->frequency());
  }
  frequency_list_.assign(frequency_set.begin(), frequency_set.end());

  if (Is8021x())
    cipher_8021x_ = ComputeCipher8021x(endpoints_);

  uint16_t frequency = 0;
  int16_t signal = WiFiService::SignalLevelMin;
  std::string bssid;
  std::string country_code;
  Stringmap vendor_information;
  uint16_t ap_physical_mode = Metrics::kWiFiNetworkPhyModeUndef;
  int16_t prev_raw_signal_strength = raw_signal_strength_;
  // Represent "unknown raw signal strength" as 0.
  raw_signal_strength_ = 0;
  if (representative_endpoint) {
    frequency = representative_endpoint->frequency();
    signal = representative_endpoint->signal_strength();
    raw_signal_strength_ = signal;
    bssid = representative_endpoint->bssid_string();
    country_code = representative_endpoint->country_code();
    vendor_information = representative_endpoint->GetVendorInformation();
    ap_physical_mode = representative_endpoint->physical_mode();
  }

  if (frequency_ != frequency) {
    frequency_ = frequency;
    adaptor()->EmitUint16Changed(kWifiFrequency, frequency_);
  }
  if (bssid_ != bssid) {
    bssid_ = bssid;
    adaptor()->EmitStringChanged(kWifiBSsid, bssid_);
  }
  if (country_code_ != country_code) {
    country_code_ = country_code;
    adaptor()->EmitStringChanged(kCountryProperty, country_code_);
  }
  if (vendor_information_ != vendor_information) {
    vendor_information_ = vendor_information;
    adaptor()->EmitStringmapChanged(kWifiVendorInformationProperty,
                                    vendor_information_);
  }
  if (ap_physical_mode_ != ap_physical_mode) {
    ap_physical_mode_ = ap_physical_mode;
    adaptor()->EmitUint16Changed(kWifiPhyMode, ap_physical_mode_);
  }
  adaptor()->EmitUint16sChanged(kWifiFrequencyListProperty, frequency_list_);
  if (prev_raw_signal_strength != raw_signal_strength_) {
    adaptor()->EmitIntChanged(kWifiSignalStrengthRssiProperty, SignalLevel());
    SetStrength(SignalToStrength(signal));
  }

  // Either cipher_8021x_ or security_ may have changed. Recomputing is
  // harmless.
  UpdateSecurity();
  // WPA2/3 info may change this.
  UpdateConnectable();

  NotifyIfVisibilityChanged();
}

bool WiFiService::IsAESCapable() const {
  // AES can be used if security is WPA2+ or ...
  if (security_ == WiFiSecurity::kWpa2 ||
      security_ == WiFiSecurity::kWpa2Wpa3 ||
      security_ == WiFiSecurity::kWpa3) {
    return true;
  }
  // ... security is equal to a mixed mode including WPA and none of the
  // endpoints is in pure WPA mode.
  if (security_ == WiFiSecurity::kWpaWpa2 ||
      security_ == WiFiSecurity::kWpaAll) {
    return !base::Contains(endpoints_, WiFiSecurity::kWpa,
                           [](auto ep) { return ep->security_mode(); });
  }
  return false;
}

void WiFiService::UpdateSecurity() {
  CryptoAlgorithm algorithm = kCryptoNone;
  bool key_rotation = false;
  bool endpoint_auth = false;

  if (security_class() == kSecurityClassNone) {
    // initial values apply
  } else if (security_class() == kSecurityClassWep) {
    algorithm = kCryptoRc4;
    key_rotation = Is8021x();
    endpoint_auth = Is8021x();
  } else if (IsAESCapable()) {
    algorithm = kCryptoAes;
    key_rotation = true;
    endpoint_auth = false;
  } else if (security_class() == kSecurityClassPsk) {
    algorithm = kCryptoRc4;
    key_rotation = true;
    endpoint_auth = false;
  } else if (security_class() == kSecurityClass8021x) {
    algorithm = cipher_8021x_;
    key_rotation = true;
    endpoint_auth = true;
  }
  SetSecurity(algorithm, key_rotation, endpoint_auth);
}

// static
Service::CryptoAlgorithm WiFiService::ComputeCipher8021x(
    const std::set<WiFiEndpointConstRefPtr>& endpoints) {
  if (endpoints.empty())
    return kCryptoNone;  // Will update after scan results.

  // Find weakest cipher (across endpoints) of the strongest ciphers
  // (per endpoint).
  Service::CryptoAlgorithm cipher = Service::kCryptoAes;
  for (const auto& endpoint : endpoints) {
    Service::CryptoAlgorithm endpoint_cipher;
    if (endpoint->has_rsn_property()) {
      endpoint_cipher = Service::kCryptoAes;
    } else if (endpoint->has_wpa_property()) {
      endpoint_cipher = Service::kCryptoRc4;
    } else {
      // We could be in the Dynamic WEP case here. But that's okay,
      // because |cipher_8021x_| is not defined in that case.
      endpoint_cipher = Service::kCryptoNone;
    }
    cipher = std::min(cipher, endpoint_cipher);
  }
  return cipher;
}

// static
void WiFiService::ValidateWEPPassphrase(const std::string& passphrase,
                                        Error* error) {
  ParseWEPPassphrase(passphrase, nullptr, nullptr, error);
}

// static
void WiFiService::ValidateWPAPassphrase(const std::string& passphrase,
                                        Error* error) {
  ParseWPAPassphrase(passphrase, nullptr, error);
}

// static
void WiFiService::ParseWEPPassphrase(const std::string& passphrase,
                                     int* key_index,
                                     std::vector<uint8_t>* password_bytes,
                                     Error* error) {
  unsigned int length = passphrase.length();
  int key_index_local;
  std::string password_text;
  bool is_hex = false;

  switch (length) {
    case IEEE_80211::kWEP40AsciiLen:
    case IEEE_80211::kWEP104AsciiLen:
      key_index_local = 0;
      password_text = passphrase;
      break;
    case IEEE_80211::kWEP40AsciiLen + 2:
    case IEEE_80211::kWEP104AsciiLen + 2:
      if (CheckWEPKeyIndex(passphrase, error)) {
        base::StringToInt(passphrase.substr(0, 1), &key_index_local);
        password_text = passphrase.substr(2);
      }
      break;
    case IEEE_80211::kWEP40HexLen:
    case IEEE_80211::kWEP104HexLen:
      if (CheckWEPIsHex(passphrase, error)) {
        key_index_local = 0;
        password_text = passphrase;
        is_hex = true;
      }
      break;
    case IEEE_80211::kWEP40HexLen + 2:
    case IEEE_80211::kWEP104HexLen + 2:
      if (CheckWEPKeyIndex(passphrase, error) &&
          CheckWEPIsHex(passphrase.substr(2), error)) {
        base::StringToInt(passphrase.substr(0, 1), &key_index_local);
        password_text = passphrase.substr(2);
        is_hex = true;
      } else if (CheckWEPPrefix(passphrase, error) &&
                 CheckWEPIsHex(passphrase.substr(2), error)) {
        key_index_local = 0;
        password_text = passphrase.substr(2);
        is_hex = true;
      }
      break;
    case IEEE_80211::kWEP40HexLen + 4:
    case IEEE_80211::kWEP104HexLen + 4:
      if (CheckWEPKeyIndex(passphrase, error) &&
          CheckWEPPrefix(passphrase.substr(2), error) &&
          CheckWEPIsHex(passphrase.substr(4), error)) {
        base::StringToInt(passphrase.substr(0, 1), &key_index_local);
        password_text = passphrase.substr(4);
        is_hex = true;
      }
      break;
    default:
      error->Populate(Error::kInvalidPassphrase);
      break;
  }

  if (error->IsSuccess()) {
    if (key_index)
      *key_index = key_index_local;
    if (password_bytes) {
      if (is_hex)
        base::HexStringToBytes(password_text, password_bytes);
      else
        password_bytes->insert(password_bytes->end(), password_text.begin(),
                               password_text.end());
    }
  }
}

// static
void WiFiService::ParseWPAPassphrase(const std::string& passphrase,
                                     std::vector<uint8_t>* passphrase_bytes,
                                     Error* error) {
  unsigned int length = passphrase.length();
  std::vector<uint8_t> temp_bytes;

  // ASCII passphrase. No conversions needed.
  if (length >= IEEE_80211::kWPAAsciiMinLen &&
      length <= IEEE_80211::kWPAAsciiMaxLen) {
    return;
  }

  if (length != IEEE_80211::kWPAHexLen) {
    LOG(ERROR) << "InvalidPassphrase: Incorrect WPA hex Passphrase length: "
               << length;
    error->Populate(Error::kInvalidPassphrase);
    return;
  }

  if (!base::HexStringToBytes(passphrase, &temp_bytes)) {
    LOG(ERROR) << "InvalidPassphrase: Failed to parse WPA hex passphrase";
    error->Populate(Error::kInvalidPassphrase);
    return;
  }

  if (passphrase_bytes) {
    base::HexStringToBytes(passphrase, passphrase_bytes);
  }
}

// static
bool WiFiService::CheckWEPIsHex(const std::string& passphrase, Error* error) {
  std::vector<uint8_t> passphrase_bytes;
  if (!base::HexStringToBytes(passphrase, &passphrase_bytes)) {
    error->Populate(Error::kInvalidPassphrase);
    LOG(ERROR) << "InvalidPassphrase: WEP Key is not Hex";
    return false;
  }
  return true;
}

// static
bool WiFiService::CheckWEPKeyIndex(const std::string& passphrase,
                                   Error* error) {
  std::string wepPrefix = passphrase.substr(0, 2);
  if ((wepPrefix != "0:" && wepPrefix != "1:" && wepPrefix != "2:" &&
       wepPrefix != "3:")) {
    error->Populate(Error::kInvalidPassphrase);
    LOG(ERROR) << "InvalidPassphrase: Invalid WEP Key Index: " << wepPrefix;
    return false;
  }
  return true;
}

// static
bool WiFiService::CheckWEPPrefix(const std::string& passphrase, Error* error) {
  if (!base::StartsWith(passphrase, "0x",
                        base::CompareCase::INSENSITIVE_ASCII)) {
    error->Populate(Error::kInvalidPassphrase);
    LOG(ERROR) << "InvalidPassphrase: Incorrect WEP Prefix: "
               << passphrase.substr(0, 2);
    return false;
  }
  return true;
}

// static
std::string WiFiService::ComputeSecurityClass(const WiFiSecurity& security) {
  if (security.IsPsk()) {
    return kSecurityClassPsk;
  }
  if (security.IsEnterprise()) {
    return kSecurityClass8021x;
  }
  return security.ToString();  // "none" or "wep"
}

int16_t WiFiService::SignalLevel() const {
  // If we have any endpoints at all then UpdateFromEndpoints has
  // already set raw_signal_strength_ to the best signal level we
  // have. If we don't have any endpoints then return -32768 dBm
  // on the theory that the service probably exists somewhere in
  // the world but is too far away to hear.
  return HasEndpoints() ? raw_signal_strength_ : WiFiService::SignalLevelMin;
}

int32_t WiFiService::GetSignalLevel(Error* /*error*/) {
  return SignalLevel();
}

// static
bool WiFiService::IsValidMode(const std::string& mode) {
  return mode == kModeManaged;
}

// static
bool WiFiService::IsValidSecurityClass(const std::string& security_class) {
  return security_class == kSecurityClassNone ||
         security_class == kSecurityClassWep ||
         security_class == kSecurityClassPsk ||
         security_class == kSecurityClass8021x;
}

// static
uint8_t WiFiService::SignalToStrength(int16_t signal_dbm) {
  int16_t strength;
  if (signal_dbm > 0) {
    if (!logged_signal_warning) {
      LOG(WARNING) << "Signal strength is suspiciously high. "
                   << "Assuming value " << signal_dbm << " is not in dBm.";
      logged_signal_warning = true;
    }
  }

  // The signal strength in dBm and relation with signal quality is non linear.
  // The signal strength can typically vary from -20 to -90 dBm.
  // The UI maps signal strength [0-100] vs RSSI(in dBm) is as follows:
  // [100-75] -> 4 Bars in UI for Signal Strength -44 to -55 dBm
  // [75-50]  -> 3 Bars in UI for Signal Strength -55 to -66 dBm
  // [50-25]  -> 2 Bars in UI for Signal Strength -66 to -77 dBm
  // [25-0]   -> 1 Bar in UI for Signal Strength -77 to -88 dBm
  // This can be converted to eq.: y = 25x/11 + 200
  // Ref: b/170208961 doc: http://go/cros-wifi-signalstrength
  if (signal_dbm > -44) {
    strength = kStrengthMax;
  } else if (signal_dbm < -88) {
    strength = kStrengthMin;
  } else {
    strength = (25 * signal_dbm) / 11 + 200;
  }
  return strength;
}

KeyValueStore WiFiService::GetStorageProperties() const {
  KeyValueStore args;
  args.Set<std::string>(kStorageType, kTypeWifi);
  args.Set<std::string>(kStorageSSID, hex_ssid_);
  args.Set<std::string>(kStorageMode, mode_);
  args.Set<std::string>(kStorageSecurityClass, security_class());
  return args;
}

std::string WiFiService::GetDefaultStorageIdentifier() const {
  return base::ToLowerASCII(base::StringPrintf(
      "%s_%s_%s_%s_%s", kTypeWifi, kAnyDeviceAddress, hex_ssid_.c_str(),
      mode_.c_str(), security_class().c_str()));
}

std::string WiFiService::GetSecurity(Error* /*error*/) {
  return security_.ToString();
}

std::string WiFiService::GetSecurityClass(Error* /*error*/) {
  return security_class();
}

void WiFiService::ClearCachedCredentials() {
  if (wifi_) {
    wifi_->ClearCachedCredentials(this);
  }
}

void WiFiService::OnEapCredentialsChanged(
    Service::UpdateCredentialsReason reason) {
  if (Is8021x()) {
    OnCredentialChange(reason);
  }
}

void WiFiService::OnCredentialChange(Service::UpdateCredentialsReason reason) {
  ClearCachedCredentials();
  // Credential changes due to a property update are new and have not
  // necessarily been used for a successful connection.
  if (reason == kReasonPropertyUpdate)
    SetHasEverConnected(false);
  UpdateConnectable();
  ResetSuspectedCredentialFailures();
}

void WiFiService::OnProfileConfigured() {
  if (profile() || !hidden_ssid()) {
    return;
  }
  // This situation occurs when a hidden WiFi service created via GetService
  // has been persisted to a profile in Manager::ConfigureService().  Now
  // that configuration is saved, we must join the service with its profile,
  // which will make this SSID eligible for directed probes during scans.
  manager()->RegisterService(this);
}

void WiFiService::OnPasspointMatch(
    const PasspointCredentialsRefPtr& credentials, uint64_t priority) {
  parent_credentials_ = credentials;
  match_priority_ = priority;

  mutable_eap()->Load(parent_credentials_->eap());
  OnEapCredentialsChanged(Service::kReasonPasspointMatch);
  EnableAndRetainAutoConnect();
}

bool WiFiService::Is8021x() const {
  // Special case for Dynamic WEP + 802.1x.
  if (security_class() == kSecurityClassWep &&
      GetEAPKeyManagement() == WPASupplicant::kKeyManagementIeee8021X) {
    return true;
  }
  if (security().IsValid()) {
    return security().IsEnterprise();
  }

  return security_class() == kSecurityClass8021x;
}

WiFiRefPtr WiFiService::ChooseDevice() {
  DeviceRefPtr device =
      manager()->GetEnabledDeviceWithTechnology(Technology::kWiFi);
  CHECK(!device || device->technology() == Technology::kWiFi)
      << "Unexpected device technology: " << device->technology();
  return static_cast<WiFi*>(device.get());
}

void WiFiService::ResetWiFi() {
  SetWiFi(nullptr);
}

void WiFiService::SetWiFi(const WiFiRefPtr& new_wifi) {
  if (wifi_ == new_wifi) {
    return;
  }
  if (wifi_) {
    wifi_->DisassociateFromService(this);
  }
  if (new_wifi) {
    adaptor()->EmitRpcIdentifierChanged(kDeviceProperty,
                                        new_wifi->GetRpcIdentifier());
  } else {
    adaptor()->EmitRpcIdentifierChanged(kDeviceProperty,
                                        DBusControl::NullRpcIdentifier());
  }
  wifi_ = new_wifi;
}

std::string WiFiService::CalculateRoamState(Error* /*error*/) {
  return GetRoamStateString();
}

void WiFiService::SetRoamState(RoamState roam_state) {
  if (roam_state == roam_state_) {
    return;
  }
  roam_state_ = roam_state;
  adaptor()->EmitStringChanged(kWifiRoamStateProperty, GetRoamStateString());
}

std::string WiFiService::GetRoamStateString() const {
  switch (roam_state_) {
    case Service::kRoamStateIdle:
      return shill::kRoamStateIdle;
    case Service::kRoamStateAssociating:
      return shill::kRoamStateAssociation;
    case Service::kRoamStateConfiguring:
      return shill::kRoamStateConfiguration;
    case Service::kRoamStateConnected:
      return shill::kRoamStateReady;
    default:
      return "";
  }
}

void WiFiService::SetIsRekeyInProgress(bool is_rekey_in_progress) {
  if (is_rekey_in_progress == is_rekey_in_progress_) {
    return;
  }
  is_rekey_in_progress_ = is_rekey_in_progress;
  adaptor()->EmitBoolChanged(kWifiRekeyInProgressProperty,
                             is_rekey_in_progress_);
}

void WiFiService::set_parent_credentials(
    const PasspointCredentialsRefPtr& credentials) {
  parent_credentials_ = credentials;
}

bool WiFiService::CompareWithSameTechnology(const ServiceRefPtr& service,
                                            bool* decision) {
  CHECK(decision);

  // We can do this safely because Service::Compare calls us only when services
  // have the same technology.
  CHECK(service->technology() == Technology::kWiFi);
  WiFiService* wifi_service = static_cast<WiFiService*>(service.get());

  // A service without Passpoint credentials should be selected before a
  // service with Passpoint credentials.
  if (Service::DecideBetween(parent_credentials_ == nullptr,
                             wifi_service->parent_credentials() == nullptr,
                             decision)) {
    return true;
  }

  // A lower match priority is better than a higher one.
  if (Service::DecideBetween(wifi_service->match_priority(), match_priority_,
                             decision)) {
    return true;
  }

  return false;
}

Strings WiFiService::GetBSSIDAllowlist(Error* error) {
  return GetBSSIDAllowlistConst(error);
}

Strings WiFiService::GetBSSIDAllowlistConst(Error* /*error*/) const {
  Strings bssid_allowlist;
  for (const ByteArray& bssid : bssid_allowlist_) {
    bssid_allowlist.push_back(Device::MakeStringFromHardwareAddress(bssid));
  }
  return bssid_allowlist;
}

bool WiFiService::SetBSSIDAllowlist(const Strings& bssid_allowlist,
                                    Error* error) {
  std::set<ByteArray> filtered_bssid_allowlist;
  bool found_zero = false;
  for (const std::string& bssid : bssid_allowlist) {
    const ByteArray bssid_bytes = Device::MakeHardwareAddressFromString(bssid);

    if (bssid_bytes.empty()) {
      Error::PopulateAndLog(
          FROM_HERE, error, Error::kInvalidArguments,
          base::StringPrintf("Invalid BSSID '%s' in BSSID allowlist: [%s]",
                             bssid.c_str(),
                             base::JoinString(bssid_allowlist, ", ").c_str()));
      return false;
    }

    if (IsZero(bssid_bytes)) {
      found_zero = true;
    }

    filtered_bssid_allowlist.insert(bssid_bytes);
  }

  // If there is a zero BSSID, it must be the only element in the list
  if (found_zero && filtered_bssid_allowlist.size() != 1) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kInvalidArguments,
        base::StringPrintf("00:00:00:00:00:00 should be the only element in a "
                           "BSSID allowlist: [%s]",
                           base::JoinString(bssid_allowlist, ", ").c_str()));
    return false;
  }

  if (bssid_allowlist_ == filtered_bssid_allowlist) {
    return false;
  }

  if (wifi_) {
    Strings strings_bssid_allowlist;
    for (const auto& bytes : filtered_bssid_allowlist) {
      strings_bssid_allowlist.push_back(
          Device::MakeStringFromHardwareAddress(bytes));
    }
    // Try to update WPA supplicant as well.
    if (!wifi_->SetBSSIDAllowlist(this, strings_bssid_allowlist, error)) {
      // We allow a kNotFound error because it's ok if the network rpcid doesn't
      // exist yet. We'll eventually set the BSSID allowlist in WPA supplicant
      // on the initial configuration/connection later.
      if (error->type() != Error::kNotFound) {
        // If the network rpcid does exist but we failed for some other reason,
        // then signal a failure.
        return false;
      }
      error->Reset();
    }
  }

  bssid_allowlist_ = filtered_bssid_allowlist;
  return true;
}

std::string WiFiService::GetBSSIDRequested(Error* /*error*/) {
  return bssid_requested_;
}

bool WiFiService::SetBSSIDRequested(const std::string& bssid_requested,
                                    Error* error) {
  if (bssid_requested_ == bssid_requested) {
    return false;
  }

  if (!bssid_requested.empty()) {
    const ByteArray bssid_bytes =
        Device::MakeHardwareAddressFromString(bssid_requested);
    if (bssid_bytes.empty()) {
      Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                            base::StringPrintf("Invalid BSSID '%s' requested",
                                               bssid_requested.c_str()));
      return false;
    }
  }

  bssid_requested_ = bssid_requested;
  return true;
}

int WiFiService::GetBSSIDConnectableEndpointCount() const {
  if (GetBSSIDAllowlistPolicy(bssid_allowlist_) ==
      BSSIDAllowlistPolicy::kNoneAllowed) {
    return 0;
  }

  int connectable_endpoints = 0;
  for (const auto& endpoint : endpoints_) {
    if (IsBSSIDConnectable(endpoint)) {
      connectable_endpoints++;
    }
  }
  return connectable_endpoints;
}

bool WiFiService::HasBSSIDConnectableEndpoints() const {
  for (const auto& endpoint : endpoints_) {
    if (IsBSSIDConnectable(endpoint)) {
      return true;
    }
  }
  return false;
}

bool WiFiService::IsBSSIDConnectable(
    const WiFiEndpointConstRefPtr& endpoint) const {
  switch (GetBSSIDAllowlistPolicy(bssid_allowlist_)) {
    case BSSIDAllowlistPolicy::kNoneAllowed:
      return false;
    case BSSIDAllowlistPolicy::kMatchOnlyAllowed:
      if (!base::Contains(bssid_allowlist_, endpoint->bssid())) {
        return false;
      }
      [[fallthrough]];
    case BSSIDAllowlistPolicy::kAllAllowed:
      // If there was a specific BSSID requested, then only that one endpoint
      // is considered connectable.
      return bssid_requested_.empty() ||
             bssid_requested_ == endpoint->bssid_string();
  }
}

}  // namespace shill
