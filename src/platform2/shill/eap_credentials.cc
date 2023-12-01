// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/eap_credentials.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/functional/bind.h>
#include <base/json/json_reader.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_split.h>
#include <base/strings/string_tokenizer.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/values.h>

#include <chromeos/dbus/service_constants.h>
#include <libpasswordprovider/password.h>
#include <libpasswordprovider/password_provider.h>

#include "shill/certificate_file.h"
#include "shill/error.h"
#include "shill/logging.h"
#include "shill/metrics.h"
#include "shill/service.h"
#include "shill/store/key_value_store.h"
#include "shill/store/pkcs11_slot_getter.h"
#include "shill/store/pkcs11_util.h"
#include "shill/store/property_accessor.h"
#include "shill/store/property_store.h"
#include "shill/store/store_interface.h"
#include "shill/supplicant/wpa_supplicant.h"

namespace shill {

namespace {

// Chrome sends key value pairs for "phase2" inner EAP configuration and shill
// just forwards that to wpa_supplicant. This function adds additional flags for
// phase2 if necessary.
// Currently it adds the mschapv2_retry=0 flag if MSCHAPV2 auth is being used
// so that wpa_supplicant does not auto-retry. The auto-retry would expect shill
// to send a new identity/password (https://crbug.com/1027323).
std::string AddAdditionalInnerEapParams(const std::string& inner_eap) {
  if (inner_eap.empty())
    return std::string();
  std::vector<base::StringPiece> params = base::SplitStringPiece(
      inner_eap, " ", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  bool has_mschapv2_auth = false;
  for (const auto& param : params) {
    if (param == WPASupplicant::kFlagInnerEapAuthMSCHAPV2) {
      has_mschapv2_auth = true;
      break;
    }
  }

  if (!has_mschapv2_auth)
    return inner_eap;

  return inner_eap + " " + WPASupplicant::kFlagInnerEapNoMSCHAPV2Retry;
}

// Gets the PKCS#11 slot type of |pkcs11_id|. This is done by comparing the
// slot ID part of |pkcs11_id| with the slot IDs taken from chaps through
// |slot_getter|.
pkcs11::Slot GetPkcs11Slot(const std::string& pkcs11_id,
                           Pkcs11SlotGetter* slot_getter) {
  std::optional<pkcs11::Pkcs11Id> parsed =
      pkcs11::Pkcs11Id::ParseFromColonSeparated(pkcs11_id);
  if (!parsed) {
    LOG(ERROR) << "Invalid PKCS#11 ID " << pkcs11_id;
    return pkcs11::Slot::kUnknown;
  }
  return slot_getter->GetSlotType(parsed->slot_id);
}

// Deprecated to migrate from ROT47 to plaintext.
// TODO(crbug.com/1084279) Remove after migration is complete.
const char kStorageDeprecatedEapAnonymousIdentity[] = "EAP.AnonymousIdentity";
const char kStorageDeprecatedEapIdentity[] = "EAP.Identity";
const char kStorageDeprecatedEapPassword[] = "EAP.Password";

}  // namespace

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kService;
}  // namespace Logging

const char EapCredentials::kStorageCredentialEapAnonymousIdentity[] =
    "EAP.Credential.AnonymousIdentity";
const char EapCredentials::kStorageCredentialEapIdentity[] =
    "EAP.Credential.Identity";
const char EapCredentials::kStorageCredentialEapPassword[] =
    "EAP.Credential.Password";

const char EapCredentials::kStorageEapCACertID[] = "EAP.CACertID";
const char EapCredentials::kStorageEapCACertPEM[] = "EAP.CACertPEM";
const char EapCredentials::kStorageEapCertID[] = "EAP.CertID";
const char EapCredentials::kStorageEapEap[] = "EAP.EAP";
const char EapCredentials::kStorageEapInnerEap[] = "EAP.InnerEAP";
const char EapCredentials::kStorageEapTLSVersionMax[] = "EAP.TLSVersionMax";
const char EapCredentials::kStorageEapKeyID[] = "EAP.KeyID";
const char EapCredentials::kStorageEapKeyManagement[] = "EAP.KeyMgmt";
const char EapCredentials::kStorageEapPin[] = "EAP.PIN";
const char EapCredentials::kStorageEapSlot[] = "EAP.Slot";
const char EapCredentials::kStorageEapSubjectMatch[] = "EAP.SubjectMatch";
const char EapCredentials::kStorageEapUseProactiveKeyCaching[] =
    "EAP.UseProactiveKeyCaching";
const char EapCredentials::kStorageEapUseSystemCAs[] = "EAP.UseSystemCAs";
const char EapCredentials::kStorageEapUseLoginPassword[] =
    "EAP.UseLoginPassword";
constexpr char kStorageEapSubjectAlternativeNameMatch[] =
    "EAP.SubjectAlternativeNameMatch";
constexpr char kStorageEapDomainSuffixMatch[] = "EAP.DomainSuffixMatch";

EapCredentials::EapCredentials()
    : use_system_cas_(true),
      use_proactive_key_caching_(false),
      use_login_password_(false),
      slot_getter_(nullptr),
      password_provider_(
          std::make_unique<password_provider::PasswordProvider>()) {}

EapCredentials::~EapCredentials() = default;

// static
void EapCredentials::PopulateSupplicantProperties(
    CertificateFile* certificate_file, KeyValueStore* params) const {
  if (eap_ == kEapMethodMSCHAPV2) {
    // Plain MSCHAPv2 should only be used by IKEv2 VPN, and this path will not
    // be called in that case.
    LOG(ERROR) << "Plain MSCHAPv2 is not supported outside of IKEv2 VPN.";
    return;
  }

  std::string ca_cert;
  if (!ca_cert_pem_.empty()) {
    base::FilePath certfile =
        certificate_file->CreatePEMFromStrings(ca_cert_pem_);
    if (certfile.empty()) {
      LOG(ERROR) << "Unable to extract PEM certificate.";
    } else {
      ca_cert = certfile.value();
    }
  }

  std::string updated_inner_eap = AddAdditionalInnerEapParams(inner_eap_);
  using KeyVal = std::pair<const char*, const char*>;
  std::vector<KeyVal> propertyvals = {
      // Authentication properties.
      KeyVal(WPASupplicant::kNetworkPropertyEapAnonymousIdentity,
             anonymous_identity_.c_str()),
      KeyVal(WPASupplicant::kNetworkPropertyEapIdentity, identity_.c_str()),

      // Non-authentication properties.
      KeyVal(WPASupplicant::kNetworkPropertyEapCaCert, ca_cert.c_str()),
      KeyVal(WPASupplicant::kNetworkPropertyEapCaCertId, ca_cert_id_.c_str()),
      KeyVal(WPASupplicant::kNetworkPropertyEapEap, eap_.c_str()),
      KeyVal(WPASupplicant::kNetworkPropertyEapInnerEap,
             updated_inner_eap.c_str()),
      KeyVal(WPASupplicant::kNetworkPropertyEapSubjectMatch,
             subject_match_.c_str()),
  };
  std::optional<std::string> altsubject_match =
      TranslateSubjectAlternativeNameMatch(
          subject_alternative_name_match_list_);
  if (altsubject_match.has_value()) {
    propertyvals.push_back(
        KeyVal(WPASupplicant::kNetworkPropertyEapSubjectAlternativeNameMatch,
               altsubject_match.value().c_str()));
  }
  std::optional<std::string> domain_suffix_match =
      TranslateDomainSuffixMatch(domain_suffix_match_list_);
  if (domain_suffix_match.has_value()) {
    propertyvals.push_back(
        KeyVal(WPASupplicant::kNetworkPropertyEapDomainSuffixMatch,
               domain_suffix_match.value().c_str()));
  }
  if (use_system_cas_) {
    propertyvals.push_back(
        KeyVal(WPASupplicant::kNetworkPropertyCaPath, WPASupplicant::kCaPath));
  } else if (ca_cert.empty()) {
    LOG(WARNING) << __func__ << ": No certificate authorities are configured."
                 << " Server certificates will be accepted"
                 << " unconditionally.";
  }

  if (ClientAuthenticationUsesCryptoToken()) {
    propertyvals.push_back(
        KeyVal(WPASupplicant::kNetworkPropertyEapCertId, cert_id_.c_str()));
    propertyvals.push_back(
        KeyVal(WPASupplicant::kNetworkPropertyEapKeyId, key_id_.c_str()));
  }

  if (ClientAuthenticationUsesCryptoToken() || !ca_cert_id_.empty()) {
    propertyvals.push_back(
        KeyVal(WPASupplicant::kNetworkPropertyEapPin, pin_.c_str()));
    propertyvals.push_back(KeyVal(WPASupplicant::kNetworkPropertyEngineId,
                                  WPASupplicant::kEnginePKCS11));
    // We can't use the propertyvals vector for this since this argument
    // is a uint32_t, not a string.
    params->Set<uint32_t>(WPASupplicant::kNetworkPropertyEngine,
                          WPASupplicant::kDefaultEngine);
  }

  if (use_proactive_key_caching_) {
    params->Set<uint32_t>(WPASupplicant::kNetworkPropertyEapProactiveKeyCaching,
                          WPASupplicant::kProactiveKeyCachingEnabled);
  } else {
    params->Set<uint32_t>(WPASupplicant::kNetworkPropertyEapProactiveKeyCaching,
                          WPASupplicant::kProactiveKeyCachingDisabled);
  }

  if (tls_version_max_ == kEapTLSVersion1p0) {
    params->Set<std::string>(
        WPASupplicant::kNetworkPropertyEapOuterEap,
        std::string(WPASupplicant::kFlagDisableEapTLS1p1) + " " +
            std::string(WPASupplicant::kFlagDisableEapTLS1p2));
  } else if (tls_version_max_ == kEapTLSVersion1p1) {
    params->Set<std::string>(WPASupplicant::kNetworkPropertyEapOuterEap,
                             WPASupplicant::kFlagDisableEapTLS1p2);
  }

  if (use_login_password_) {
    std::unique_ptr<password_provider::Password> password =
        password_provider_->GetPassword();
    if (password == nullptr || password->size() == 0) {
      LOG(WARNING) << "Unable to retrieve user password";
    } else {
      params->Set<std::string>(
          WPASupplicant::kNetworkPropertyEapCaPassword,
          std::string(password->GetRaw(), password->size()));
    }
  } else {
    if (!password_.empty()) {
      params->Set<std::string>(WPASupplicant::kNetworkPropertyEapCaPassword,
                               password_);
    }
  }

  for (const auto& keyval : propertyvals) {
    if (strlen(keyval.second) > 0) {
      params->Set<std::string>(keyval.first, keyval.second);
    }
  }
}

void EapCredentials::InitPropertyStore(PropertyStore* store) {
  // Authentication properties.
  store->RegisterString(kEapAnonymousIdentityProperty, &anonymous_identity_);
  store->RegisterString(kEapCertIdProperty, &cert_id_);
  store->RegisterString(kEapIdentityProperty, &identity_);
  store->RegisterString(kEapKeyIdProperty, &key_id_);
  HelpRegisterDerivedString(store, kEapKeyMgmtProperty,
                            &EapCredentials::GetKeyManagement,
                            &EapCredentials::SetKeyManagement);
  HelpRegisterWriteOnlyDerivedString(store, kEapPasswordProperty,
                                     &EapCredentials::SetEapPassword, nullptr,
                                     &password_);
  store->RegisterString(kEapPinProperty, &pin_);
  store->RegisterBool(kEapUseLoginPasswordProperty, &use_login_password_);

  // Non-authentication properties.
  store->RegisterStrings(kEapCaCertPemProperty, &ca_cert_pem_);
  store->RegisterString(kEapCaCertIdProperty, &ca_cert_id_);
  store->RegisterString(kEapMethodProperty, &eap_);
  store->RegisterString(kEapPhase2AuthProperty, &inner_eap_);
  store->RegisterString(kEapTLSVersionMaxProperty, &tls_version_max_);
  store->RegisterString(kEapSubjectMatchProperty, &subject_match_);
  store->RegisterStrings(kEapSubjectAlternativeNameMatchProperty,
                         &subject_alternative_name_match_list_);
  store->RegisterStrings(kEapDomainSuffixMatchProperty,
                         &domain_suffix_match_list_);
  store->RegisterBool(kEapUseProactiveKeyCachingProperty,
                      &use_proactive_key_caching_);
  store->RegisterBool(kEapUseSystemCasProperty, &use_system_cas_);
}

// static
bool EapCredentials::IsEapAuthenticationProperty(base::StringPiece property) {
  return property == kEapAnonymousIdentityProperty ||
         property == kEapCertIdProperty || property == kEapIdentityProperty ||
         property == kEapKeyIdProperty || property == kEapKeyMgmtProperty ||
         property == kEapPasswordProperty || property == kEapPinProperty ||
         property == kEapUseLoginPasswordProperty;
}

bool EapCredentials::IsConnectable() const {
  // Identity is required.
  if (identity_.empty()) {
    SLOG(2) << "Not connectable: Identity is empty.";
    return false;
  }

  if (!cert_id_.empty()) {
    // If a client certificate is being used, we must have a private key.
    if (key_id_.empty()) {
      SLOG(2) << "Not connectable: Client certificate but no private key.";
      return false;
    }
  }
  if (!cert_id_.empty() || !key_id_.empty() || !ca_cert_id_.empty()) {
    // If PKCS#11 data is needed, a PIN is required.
    if (pin_.empty()) {
      SLOG(2) << "Not connectable: PKCS#11 data but no PIN.";
      return false;
    }
  }

  // For EAP-TLS, a client certificate is required.
  if (eap_.empty() || eap_ == kEapMethodTLS) {
    if (!cert_id_.empty() && !key_id_.empty()) {
      SLOG(2) << "Connectable: EAP-TLS with a client cert and key.";
      return true;
    }
  }

  // For EAP types other than TLS (e.g. EAP-TTLS or EAP-PEAP, password is the
  // minimum requirement), at least an identity + password is required.
  if (eap_.empty() || eap_ != kEapMethodTLS) {
    if (!password_.empty()) {
      SLOG(2) << "Connectable. !EAP-TLS and has a password.";
      return true;
    }
  }

  SLOG(2) << "Not connectable: No suitable EAP configuration was found.";
  return false;
}

bool EapCredentials::IsConnectableUsingPassphrase() const {
  return !identity_.empty() && !password_.empty();
}

void EapCredentials::Load(const StoreInterface* storage,
                          const std::string& id) {
  // Authentication properties.
  storage->GetCryptedString(id, kStorageDeprecatedEapAnonymousIdentity,
                            kStorageCredentialEapAnonymousIdentity,
                            &anonymous_identity_);
  storage->GetString(id, kStorageEapCertID, &cert_id_);
  storage->GetCryptedString(id, kStorageDeprecatedEapIdentity,
                            kStorageCredentialEapIdentity, &identity_);
  storage->GetString(id, kStorageEapKeyID, &key_id_);
  std::string key_management;
  storage->GetString(id, kStorageEapKeyManagement, &key_management);
  SetKeyManagement(key_management, nullptr);
  storage->GetCryptedString(id, kStorageDeprecatedEapPassword,
                            kStorageCredentialEapPassword, &password_);
  storage->GetString(id, kStorageEapPin, &pin_);
  storage->GetBool(id, kStorageEapUseLoginPassword, &use_login_password_);

  // Non-authentication properties.
  storage->GetString(id, kStorageEapCACertID, &ca_cert_id_);
  storage->GetStringList(id, kStorageEapCACertPEM, &ca_cert_pem_);
  storage->GetString(id, kStorageEapEap, &eap_);
  storage->GetString(id, kStorageEapInnerEap, &inner_eap_);
  storage->GetString(id, kStorageEapTLSVersionMax, &tls_version_max_);
  storage->GetString(id, kStorageEapSubjectMatch, &subject_match_);
  storage->GetStringList(id, kStorageEapSubjectAlternativeNameMatch,
                         &subject_alternative_name_match_list_);
  storage->GetStringList(id, kStorageEapDomainSuffixMatch,
                         &domain_suffix_match_list_);
  storage->GetBool(id, kStorageEapUseProactiveKeyCaching,
                   &use_proactive_key_caching_);
  storage->GetBool(id, kStorageEapUseSystemCAs, &use_system_cas_);

  // Fix possible slot ID instability. If the slot type is unknown, no need to
  // replace the slot ID.
  pkcs11::Slot slot;
  storage->GetInt(id, kStorageEapSlot, reinterpret_cast<int*>(&slot));
  if (slot == pkcs11::kUnknown || slot_getter_ == nullptr) {
    return;
  }
  slot_getter_->GetPkcs11SlotIdWithRetries(
      slot, base::BindOnce(&EapCredentials::ReplacePkcs11SlotIds,
                           weak_factory_.GetWeakPtr()));
}

void EapCredentials::Load(const KeyValueStore& store) {
  ca_cert_id_ = store.Lookup<std::string>(kEapCaCertIdProperty, std::string());
  ca_cert_pem_ = store.Lookup<Strings>(kEapCaCertPemProperty, Strings());
  eap_ = store.Lookup<std::string>(kEapMethodProperty, std::string());
  inner_eap_ = store.Lookup<std::string>(kEapPhase2AuthProperty, std::string());
  tls_version_max_ =
      store.Lookup<std::string>(kEapTLSVersionMaxProperty, std::string());
  subject_match_ =
      store.Lookup<std::string>(kEapSubjectMatchProperty, std::string());
  subject_alternative_name_match_list_ =
      store.Lookup<Strings>(kEapSubjectAlternativeNameMatchProperty, Strings());
  domain_suffix_match_list_ =
      store.Lookup<Strings>(kEapDomainSuffixMatchProperty, Strings());
  use_proactive_key_caching_ =
      store.Lookup<bool>(kEapUseProactiveKeyCachingProperty, false);
  use_system_cas_ = store.Lookup<bool>(kEapUseSystemCasProperty, true);
  anonymous_identity_ =
      store.Lookup<std::string>(kEapAnonymousIdentityProperty, std::string());
  identity_ = store.Lookup<std::string>(kEapIdentityProperty, std::string());
  password_ = store.Lookup<std::string>(kEapPasswordProperty, std::string());
  use_login_password_ = store.Lookup<bool>(kEapUseLoginPasswordProperty, false);
  cert_id_ = store.Lookup<std::string>(kEapCertIdProperty, std::string());
  key_id_ = store.Lookup<std::string>(kEapKeyIdProperty, std::string());
  SetKeyManagement(
      store.Lookup<std::string>(kEapKeyMgmtProperty, std::string()), nullptr);
  pin_ = store.Lookup<std::string>(kEapPinProperty, std::string());
}

void EapCredentials::Load(const EapCredentials& eap) {
  ca_cert_id_ = eap.ca_cert_id_;
  ca_cert_pem_ = eap.ca_cert_pem_;
  eap_ = eap.eap_;
  inner_eap_ = eap.inner_eap_;
  tls_version_max_ = eap.tls_version_max_;
  subject_match_ = eap.subject_match_;
  subject_alternative_name_match_list_ =
      eap.subject_alternative_name_match_list_;
  domain_suffix_match_list_ = eap.domain_suffix_match_list_;
  use_proactive_key_caching_ = eap.use_proactive_key_caching_;
  use_system_cas_ = eap.use_system_cas_;
  anonymous_identity_ = eap.anonymous_identity_;
  identity_ = eap.identity_;
  password_ = eap.password_;
  use_login_password_ = eap.use_login_password_;
  cert_id_ = eap.cert_id_;
  key_id_ = eap.key_id_;
  SetKeyManagement(eap.key_management_, nullptr);
  pin_ = eap.pin_;
}

void EapCredentials::ReplacePkcs11SlotIds(CK_SLOT_ID slot_id) {
  if (slot_id == pkcs11::kInvalidSlot) {
    return;
  }
  if (cert_id_ != key_id_) {
    LOG(ERROR) << "PKCS#11 IDs of the certificate and key are not equal";
    return;
  }

  std::optional<pkcs11::Pkcs11Id> pkcs11_id =
      pkcs11::Pkcs11Id::ParseFromColonSeparated(cert_id_);
  if (!pkcs11_id) {
    LOG(ERROR) << "Invalid PKCS#11 ID " << cert_id_;
    return;
  }
  pkcs11_id->slot_id = slot_id;

  cert_id_ = pkcs11_id->ToColonSeparated();
  key_id_ = cert_id_;
}

void EapCredentials::MigrateDeprecatedStorage(StoreInterface* storage,
                                              const std::string& id) const {
  // Note that if we found any of these keys, then we already know that
  // save_credentials was true during the last Save, and therefore can set the
  // new (key, plaintext_value).
  //
  // TODO(crbug.com/1084279) Remove after migration is complete.
  if (storage->DeleteKey(id, kStorageDeprecatedEapAnonymousIdentity)) {
    storage->SetString(id, kStorageCredentialEapAnonymousIdentity,
                       anonymous_identity_);
  }
  if (storage->DeleteKey(id, kStorageDeprecatedEapIdentity)) {
    storage->SetString(id, kStorageCredentialEapIdentity, identity_);
  }
  if (storage->DeleteKey(id, kStorageDeprecatedEapPassword)) {
    storage->SetString(id, kStorageCredentialEapPassword, password_);
  }
}

void EapCredentials::SetEapSlotGetter(Pkcs11SlotGetter* slot_getter) {
  slot_getter_ = slot_getter;
}

void EapCredentials::OutputConnectionMetrics(Metrics* metrics,
                                             Technology technology) const {
  Metrics::EapOuterProtocol outer_protocol =
      Metrics::EapOuterProtocolStringToEnum(eap_);
  metrics->SendEnumToUMA(Metrics::kMetricNetworkEapOuterProtocol, technology,
                         outer_protocol);

  Metrics::EapInnerProtocol inner_protocol =
      Metrics::EapInnerProtocolStringToEnum(inner_eap_);
  metrics->SendEnumToUMA(Metrics::kMetricNetworkEapInnerProtocol, technology,
                         inner_protocol);
}

void EapCredentials::Save(StoreInterface* storage,
                          const std::string& id,
                          bool save_credentials) const {
  // Fix possible slot ID instability. Only try to get the PKCS#11 slot ID
  // synchronously as the profile might be removed soon after this call.
  if (!cert_id_.empty() && slot_getter_ != nullptr && save_credentials) {
    storage->SetInt(id, kStorageEapSlot, GetPkcs11Slot(cert_id_, slot_getter_));
  } else {
    storage->DeleteKey(id, kStorageEapSlot);
  }

  // Authentication properties.
  Service::SaveStringOrClear(storage, id,
                             kStorageCredentialEapAnonymousIdentity,
                             save_credentials ? anonymous_identity_ : "");
  Service::SaveStringOrClear(storage, id, kStorageEapCertID,
                             save_credentials ? cert_id_ : "");
  Service::SaveStringOrClear(storage, id, kStorageCredentialEapIdentity,
                             save_credentials ? identity_ : "");
  Service::SaveStringOrClear(storage, id, kStorageEapKeyID,
                             save_credentials ? key_id_ : "");
  Service::SaveStringOrClear(storage, id, kStorageEapKeyManagement,
                             key_management_);
  Service::SaveStringOrClear(storage, id, kStorageCredentialEapPassword,
                             save_credentials ? password_ : "");
  Service::SaveStringOrClear(storage, id, kStorageEapPin,
                             save_credentials ? pin_ : "");
  storage->SetBool(id, kStorageEapUseLoginPassword, use_login_password_);

  // Non-authentication properties.
  Service::SaveStringOrClear(storage, id, kStorageEapCACertID, ca_cert_id_);
  if (ca_cert_pem_.empty()) {
    storage->DeleteKey(id, kStorageEapCACertPEM);
  } else {
    storage->SetStringList(id, kStorageEapCACertPEM, ca_cert_pem_);
  }
  Service::SaveStringOrClear(storage, id, kStorageEapEap, eap_);
  Service::SaveStringOrClear(storage, id, kStorageEapInnerEap, inner_eap_);
  Service::SaveStringOrClear(storage, id, kStorageEapTLSVersionMax,
                             tls_version_max_);
  Service::SaveStringOrClear(storage, id, kStorageEapSubjectMatch,
                             subject_match_);
  storage->SetStringList(id, kStorageEapSubjectAlternativeNameMatch,
                         subject_alternative_name_match_list_);
  storage->SetStringList(id, kStorageEapDomainSuffixMatch,
                         domain_suffix_match_list_);
  storage->SetBool(id, kStorageEapUseProactiveKeyCaching,
                   use_proactive_key_caching_);
  storage->SetBool(id, kStorageEapUseSystemCAs, use_system_cas_);
}

void EapCredentials::Reset() {
  // Authentication properties.
  anonymous_identity_ = "";
  cert_id_ = "";
  identity_ = "";
  key_id_ = "";
  // Do not reset key_management_, since it should never be emptied.
  password_ = "";
  pin_ = "";
  use_login_password_ = false;

  // Non-authentication properties.
  ca_cert_id_ = "";
  ca_cert_pem_.clear();
  domain_suffix_match_list_.clear();
  eap_ = "";
  inner_eap_ = "";
  subject_match_ = "";
  subject_alternative_name_match_list_.clear();
  use_system_cas_ = true;
  use_proactive_key_caching_ = false;

  slot_getter_ = nullptr;
}

bool EapCredentials::SetEapPassword(const std::string& password,
                                    Error* /*error*/) {
  if (use_login_password_) {
    LOG(WARNING) << "Setting EAP password for configuration requiring the "
                    "user's login password";
    return false;
  }

  if (password_ == password) {
    return false;
  }
  password_ = password;
  return true;
}

std::string EapCredentials::GetKeyManagement(Error* /*error*/) {
  return key_management_;
}

bool EapCredentials::SetKeyManagement(const std::string& key_management,
                                      Error* /*error*/) {
  if (key_management.empty()) {
    return false;
  }
  if (key_management_ == key_management) {
    return false;
  }
  key_management_ = key_management;
  return true;
}

bool EapCredentials::ClientAuthenticationUsesCryptoToken() const {
  return (eap_.empty() || eap_ == kEapMethodTLS ||
          inner_eap_ == kEapMethodTLS) &&
         (!cert_id_.empty() || !key_id_.empty());
}

void EapCredentials::HelpRegisterDerivedString(
    PropertyStore* store,
    base::StringPiece name,
    std::string (EapCredentials::*get)(Error* error),
    bool (EapCredentials::*set)(const std::string&, Error*)) {
  store->RegisterDerivedString(
      name, StringAccessor(new CustomAccessor<EapCredentials, std::string>(
                this, get, set)));
}

void EapCredentials::HelpRegisterWriteOnlyDerivedString(
    PropertyStore* store,
    base::StringPiece name,
    bool (EapCredentials::*set)(const std::string&, Error*),
    void (EapCredentials::*clear)(Error* error),
    const std::string* default_value) {
  store->RegisterDerivedString(
      name,
      StringAccessor(new CustomWriteOnlyAccessor<EapCredentials, std::string>(
          this, set, clear, default_value)));
}

// static
bool EapCredentials::ValidSubjectAlternativeNameMatchType(
    const std::string& type) {
  return type == kEapSubjectAlternativeNameMatchTypeEmail ||
         type == kEapSubjectAlternativeNameMatchTypeDNS ||
         type == kEapSubjectAlternativeNameMatchTypeURI;
}

// static
bool EapCredentials::ValidDomainSuffixMatch(
    const std::string& domain_suffix_match) {
  if (domain_suffix_match.empty() || domain_suffix_match.size() > 255)
    return false;

  std::vector<base::StringPiece> labels = base::SplitStringPiece(
      domain_suffix_match, ".", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);

  DCHECK(!labels.empty());

  for (const base::StringPiece& label : labels) {
    if (label.size() == 0 || label.size() > 63)
      return false;
    // Labels can't start and end with hyphens.
    if (label.front() == '-' || label.back() == '-')
      return false;

    for (auto it = label.begin(); it != label.end(); ++it) {
      // The top level domain must contain only letters.
      if (label == labels.back()) {
        if (!base::IsAsciiAlpha(*it))
          return false;
      } else {
        if (!base::IsAsciiAlpha(*it) && !base::IsAsciiDigit(*it) &&
            (*it) != '-') {
          return false;
        }
      }
    }
  }

  return true;
}

// static
std::optional<std::string> EapCredentials::TranslateDomainSuffixMatch(
    const std::vector<std::string>& domain_suffix_match_list) {
  if (domain_suffix_match_list.empty())
    return std::nullopt;
  std::vector<std::string> filtered_domains;
  for (const std::string& domain : domain_suffix_match_list) {
    if (ValidDomainSuffixMatch(domain)) {
      filtered_domains.push_back(domain);
    } else {
      LOG(ERROR)
          << "Ignoring invalid domain name in EAP.DomainSuffixMatch list: "
          << domain;
    }
  }
  if (filtered_domains.empty())
    return std::nullopt;

  return base::JoinString(filtered_domains, ";");
}

// static
std::optional<std::string> EapCredentials::TranslateSubjectAlternativeNameMatch(
    const std::vector<std::string>& subject_alternative_name_match_list) {
  std::vector<std::string> entries;
  for (const auto& subject_alternative_name_match :
       subject_alternative_name_match_list) {
    auto json_value = base::JSONReader::ReadAndReturnValueWithError(
        subject_alternative_name_match, base::JSON_PARSE_RFC);

    if (!json_value.has_value() || !json_value->is_dict()) {
      LOG(ERROR)
          << "Could not deserialize a subject alternative name match. Error: "
          << json_value.error().message;
      return std::nullopt;
    }
    base::Value::Dict deserialized_value = std::move(json_value->GetDict());

    const std::string* type = deserialized_value.FindString(
        kEapSubjectAlternativeNameMatchTypeProperty);
    if (!type) {
      LOG(ERROR) << "Could not find "
                 << kEapSubjectAlternativeNameMatchTypeProperty
                 << " of a subject alternative name match.";
      return std::nullopt;
    }
    if (!ValidSubjectAlternativeNameMatchType(*type)) {
      LOG(ERROR) << "Subject alternative name match type: \"" << *type
                 << "\" is not supported.";
      return std::nullopt;
    }
    const std::string* value = deserialized_value.FindString(
        kEapSubjectAlternativeNameMatchValueProperty);
    if (!value) {
      LOG(ERROR) << "Could not find "
                 << kEapSubjectAlternativeNameMatchValueProperty
                 << " of a subject alternative name match.";
      return std::nullopt;
    }
    std::string translated_entry = *type + ":" + *value;
    entries.push_back(translated_entry);
  }
  return base::JoinString(entries, ";");
}

std::string EapCredentials::GetEapPassword(Error* error) const {
  if (use_login_password_ || password_.empty()) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kNotSupported,
                          "EAP config has no password.");
    return std::string();
  }
  return password_;
}

}  // namespace shill
