// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_EAP_CREDENTIALS_H_
#define SHILL_EAP_CREDENTIALS_H_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <base/strings/string_piece.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST
#include <libpasswordprovider/password_provider.h>

#include "shill/store/pkcs11_slot_getter.h"
#include "shill/technology.h"

namespace shill {

class CertificateFile;
class Error;
class KeyValueStore;
class Metrics;
class PropertyStore;
class StoreInterface;

class EapCredentials {
 public:
  EapCredentials();
  EapCredentials(const EapCredentials&) = delete;
  EapCredentials& operator=(const EapCredentials&) = delete;

  virtual ~EapCredentials();

  // Add property accessors to the EAP credential parameters in |this| to
  // |store|.
  void InitPropertyStore(PropertyStore* store);

  // Returns true if |property| is used for authentication in EapCredentials.
  static bool IsEapAuthenticationProperty(base::StringPiece property);

  // Returns true if a connection can be made with |this| credentials using
  // either passphrase or certificates.
  virtual bool IsConnectable() const;

  // Returns true if a connection can be made with |this| credentials using
  // only passphrase properties.
  virtual bool IsConnectableUsingPassphrase() const;

  // Loads EAP properties from |storage| in group |id|.
  virtual void Load(const StoreInterface* store, const std::string& id);

  // Load EAP properties from key/value store |store|.
  virtual void Load(const KeyValueStore& store);

  // Load EAP properties from another EapCredentials set |eap|.
  virtual void Load(const EapCredentials& eap);

  void MigrateDeprecatedStorage(StoreInterface* storage,
                                const std::string& id) const;

  // Set PKCS#11 slot type by comparing slot ID value from |cert_id_| with the
  // slot ID value taken from chaps through |slot_getter|.
  void SetEapSlotGetter(Pkcs11SlotGetter* slot_getter);

  // Output metrics about this EAP connection to |metrics| with technology
  // |technology|.
  virtual void OutputConnectionMetrics(Metrics* metrics,
                                       Technology technology) const;

  // Populate the wpa_supplicant DBus parameter map |params| with the
  // credentials in |this|.  To do so, this function may use |certificate_file|
  // to export CA certificates to be passed to wpa_supplicant.
  virtual void PopulateSupplicantProperties(CertificateFile* certificate_file,
                                            KeyValueStore* params) const;

  // Save EAP properties to |storage| in group |id|.  If |save_credentials|
  // is true, passwords and identities that are a part of the credentials are
  // also saved.
  virtual void Save(StoreInterface* store,
                    const std::string& id,
                    bool save_credentials) const;

  // Restore EAP properties to their initial state.
  virtual void Reset();

  // Setter that guards against emptying the "Key Management" value.
  virtual bool SetKeyManagement(const std::string& key_management,
                                Error* error);

  // Returns true if |type| is one of the subject alternative name types
  // supported by wpa_supplicant.
  static bool ValidSubjectAlternativeNameMatchType(const std::string& type);

  // Returns true if `domain_suffix_match` is a valid FQDN. A FQDN is composed
  // of labels separated by dots (.), with the following restrictions (according
  // to rfc1034#section-3.5, rfc2181#section-11, rfc1123#section-2):
  // - (rfc1034+rfc1123) Labels must start with a letter or digit.
  // - (rfc1034) Labels must end with a letter or digit
  // - (rfc1034) Labels must have as interior characters only letters, digits,
  // and hyphen (-).
  // - (rfc1034) Labels must be 63 characters or less.
  // - (rfc2181) The full domain name is limited to 255 octets.
  // - (rfc1123) The highest-level component (i.e. the top level domain) label
  // will be alphabetic.
  static bool ValidDomainSuffixMatch(const std::string& domain_suffix_match);

  // Returns the domain suffix match list in the format used by
  // wpa_supplicant by translating |domain_suffix_match_list| and filtering out
  // entries that are not valid domain names according to
  // `ValidDomainSuffixMatch`.
  static std::optional<std::string> TranslateDomainSuffixMatch(
      const std::vector<std::string>& domain_suffix_match_list);

  // Returns subject alternative name match in the format used by
  // wpa_supplicant by translating |subject_alternative_name_match_list|.
  static std::optional<std::string> TranslateSubjectAlternativeNameMatch(
      const std::vector<std::string>& subject_alternative_name_match_list);

  std::string GetEapPassword(Error* error) const;

  // Getters and setters.
  virtual const std::string& cert_id() const { return cert_id_; }
  virtual const std::string& identity() const { return identity_; }
  void set_identity(const std::string& identity) { identity_ = identity; }
  virtual const std::string& key_id() const { return key_id_; }
  virtual const std::string& key_management() const { return key_management_; }
  virtual const std::string& password() const { return password_; }
  virtual void set_password(const std::string& password) {
    password_ = password;
  }
  virtual bool use_system_cas() const { return use_system_cas_; }
  virtual void set_use_system_cas(bool use_system_cas) {
    use_system_cas_ = use_system_cas;
  }
  virtual const std::string& pin() const { return pin_; }
  virtual const std::string& method() const { return eap_; }
  virtual const std::string& inner_method() const { return inner_eap_; }
  virtual const std::vector<std::string>& ca_cert_pem() const {
    return ca_cert_pem_;
  }
  virtual const std::string& subject_match() const { return subject_match_; }
  virtual const std::vector<std::string>& subject_alternative_name_match_list()
      const {
    return subject_alternative_name_match_list_;
  }
  virtual const std::vector<std::string>& domain_suffix_match_list() const {
    return domain_suffix_match_list_;
  }

 private:
  friend class EapCredentialsTest;
  FRIEND_TEST(EapCredentialsTest, LoadAndSave);
  FRIEND_TEST(EapCredentialsTest, Load);
  FRIEND_TEST(EapCredentialsTest, Load_UserSlot);
  FRIEND_TEST(EapCredentialsTest, Load_SystemSlot);
  FRIEND_TEST(EapCredentialsTest, SaveAndLoad_Pkcs11Id);
  FRIEND_TEST(ServiceTest, LoadEap);
  FRIEND_TEST(ServiceTest, SaveEap);

  static const char kStorageCredentialEapAnonymousIdentity[];
  static const char kStorageCredentialEapIdentity[];
  static const char kStorageCredentialEapPassword[];

  static const char kStorageEapCACertID[];
  static const char kStorageEapCACertPEM[];
  static const char kStorageEapCertID[];
  static const char kStorageEapEap[];
  static const char kStorageEapInnerEap[];
  static const char kStorageEapTLSVersionMax[];
  static const char kStorageEapKeyID[];
  static const char kStorageEapKeyManagement[];
  static const char kStorageEapPin[];
  static const char kStorageEapSlot[];
  static const char kStorageEapSubjectMatch[];
  static const char kStorageEapUseProactiveKeyCaching[];
  static const char kStorageEapUseSystemCAs[];
  static const char kStorageEapUseLoginPassword[];

  // Replace the slot ID part of |cert_id_| and |key_id_| with slot ID value of
  // |slot_id|. Do nothing if |slot_id| is invalid. This method assumes that
  // |cert_id_| and |key_id_| are equal.
  void ReplacePkcs11SlotIds(CK_SLOT_ID slot_id);

  // Returns true if the current EAP authentication type requires certificate
  // authentication and any of the client credentials are provided via
  // referencea cypto token.
  bool ClientAuthenticationUsesCryptoToken() const;

  // Expose a property in |store|, with the name |name|.
  //
  // Reads of the property will be handled by invoking |get|.
  // Writes to the property will be handled by invoking |set|.
  void HelpRegisterDerivedString(
      PropertyStore* store,
      base::StringPiece name,
      std::string (EapCredentials::*get)(Error* error),
      bool (EapCredentials::*set)(const std::string& value, Error* error));

  // Expose a property in |store|, with the name |name|.
  //
  // Reads of the property will be handled by invoking |get|.
  //
  // Clearing the property will be handled by invoking |clear|, or
  // calling |set| with |default_value| (whichever is non-NULL).  It
  // is an error to call this method with both |clear| and
  // |default_value| non-NULL.
  void HelpRegisterWriteOnlyDerivedString(
      PropertyStore* store,
      base::StringPiece name,
      bool (EapCredentials::*set)(const std::string& value, Error* error),
      void (EapCredentials::*clear)(Error* error),
      const std::string* default_value);

  // Setters for write-only RPC properties.
  bool SetEapPassword(const std::string& password, Error* error);

  // RPC getter for key_management_.
  std::string GetKeyManagement(Error* error);

  // When there is an inner EAP type, use this identity for the outer.
  std::string anonymous_identity_;
  // Locator for the client certificate within the security token.
  std::string cert_id_;
  // Who we identify ourselves as to the EAP authenticator.
  std::string identity_;
  // Locator for the client private key within the security token.
  std::string key_id_;
  // Key management algorithm to use after EAP succeeds.
  std::string key_management_;
  // Password to use for EAP methods which require one.
  std::string password_;
  // PIN code for accessing the security token.
  std::string pin_;

  // Locator for the CA certificate within the security token.
  std::string ca_cert_id_;
  // Raw PEM contents of the CA certificate.
  std::vector<std::string> ca_cert_pem_;
  // The outer or only EAP authentication type.
  std::string eap_;
  // The inner EAP authentication type.
  std::string inner_eap_;
  // The highest TLS version supplicant is allowed to negotiate.
  std::string tls_version_max_;
  // If non-empty, string to match remote subject against before connecting.
  std::string subject_match_;
  // A list of serialized subject alternative names (SANs) to be matched against
  // the alternative subject name of the authentication server certificate. When
  // multiple match strings are specified, a match with any one of the values is
  // considered a sufficient match for the server certificate.
  std::vector<std::string> subject_alternative_name_match_list_;
  //  A list of constraints for the server domain name. If set, the entries will
  //  be used as suffix match requirements against the dNSName element(s) of the
  //  alternative subject name of an authentication server. When multiple match
  //  strings are specified, a match with any one of the values is considered a
  //  sufficient match for the server certificate.
  std::vector<std::string> domain_suffix_match_list_;
  // If true, use the system-wide CA database to authenticate the remote.
  bool use_system_cas_;
  // If true, use per network proactive key caching.
  bool use_proactive_key_caching_;
  // If true, use the user's stored login password as the password.
  bool use_login_password_;

  // PKCS#11 slot getter to replace possible unstable slot ID of |cert_id_| and
  // |key_id_|.
  Pkcs11SlotGetter* slot_getter_;

  std::unique_ptr<password_provider::PasswordProviderInterface>
      password_provider_;

  base::WeakPtrFactory<EapCredentials> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_EAP_CREDENTIALS_H_
