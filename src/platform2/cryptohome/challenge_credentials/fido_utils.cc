// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/challenge_credentials/fido_utils.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/logging.h>
#include <brillo/secure_blob.h>
#include <cryptohome/proto_bindings/fido.pb.h>
#include <libhwsec-foundation/crypto/sha.h>

using ::hwsec_foundation::Sha256ToSecureBlob;

namespace cryptohome {

constexpr char kCrosLoginPrefix[] = "chromeos:login:";
constexpr char kIconUrl[] = "http://www.noicon.google.com";
// Default FIDO request timeout 30s.
constexpr base::TimeDelta kRequestTimeOut = base::Seconds(30);

// MakeCredential only uses ES256 algorithms.
constexpr int kCOSEAlgorithmIdentifierES256 = -7;

std::vector<uint8_t> GetFidoUserId(const std::string& account_id) {
  auto digest = Sha256ToSecureBlob(brillo::BlobFromString(account_id));
  return std::vector<uint8_t>(digest.begin(), digest.end());
}

std::unique_ptr<cryptohome::fido::PublicKeyCredentialRpEntity>
GetPublicKeyCredentialRpEntity(const std::string& id, const std::string& name) {
  auto rp = std::make_unique<cryptohome::fido::PublicKeyCredentialRpEntity>();
  rp->set_id(id);
  rp->set_name(name);
  return rp;
}

// Create User entity. Note the id is a 32-byte unique identifier derived from
// AccountIdentifier.account_id.
std::unique_ptr<cryptohome::fido::PublicKeyCredentialUserEntity>
GetPublicKeyCredentialUserEntity(const std::string& name,
                                 const std::vector<uint8_t>& id,
                                 const std::string& url_str,
                                 const std::string& display_name) {
  auto user =
      std::make_unique<cryptohome::fido::PublicKeyCredentialUserEntity>();
  user->set_name(name);
  user->set_id(std::string(id.begin(), id.end()));
  auto url = new cryptohome::fido::Url();
  url->set_url(url_str);
  user->set_allocated_icon(url);
  user->set_display_name(display_name);
  return user;
}

FidoPKCredCreationOptionsPtr BuildFidoMakeCredentialOptions(
    std::unique_ptr<cryptohome::fido::PublicKeyCredentialUserEntity> user,
    std::unique_ptr<cryptohome::fido::PublicKeyCredentialRpEntity> rp,
    std::vector<uint8_t> challenge,
    std::vector<cryptohome::fido::PublicKeyCredentialDescriptor>
        exclude_credentials,
    base::TimeDelta adjusted_timeout,
    std::unique_ptr<cryptohome::fido::CableRegistration>
        cable_registration_data,
    cryptohome::fido::ProtectionPolicy protection_policy,
    bool use_hmac_secret,
    bool enforce_protection_policy,
    std::string appid_exclude) {
  auto options =
      std::make_unique<cryptohome::fido::PublicKeyCredentialCreationOptions>();

  // Owned by |options| and lifecycle managed by |options|.
  options->set_allocated_relying_party(rp.release());
  options->set_allocated_user(user.release());
  auto param = options->add_public_key_parameters();
  param->set_type(cryptohome::fido::PUBLIC_KEY);
  param->set_algorithm_identifier(kCOSEAlgorithmIdentifierES256);

  options->set_adjusted_timeout(adjusted_timeout.InMilliseconds());
  options->set_challenge({challenge.begin(), challenge.end()});

  // TODO(xzhou): need to implement attestation signature checking.
  options->set_attestation(cryptohome::fido::NONE_ATTESTATION_PREFERENCE);

  // Specify the RP's authenticator attributes requirements.
  auto authenticator_selection =
      std::make_unique<cryptohome::fido::AuthenticatorSelectionCriteria>();

  authenticator_selection->set_authenticator_attachment(
      cryptohome::fido::NO_PREFERENCE /* equivalent to any or unset */);
  authenticator_selection->set_require_resident_key(false);
  // TODO(xzhou): If security key supports user verification, we may allow
  // security key as single factor authentication.
  authenticator_selection->set_user_verification(cryptohome::fido::DISCOURAGED);
  options->set_allocated_authenticator_selection(
      authenticator_selection.release());

  // A list of credentials RP knows about. If an authenticator has one of these
  // credentials, it should not create a new one.
  for (auto credential : exclude_credentials) {
    auto next = options->add_exclude_credentials();
    // Deep copy.
    next->CopyFrom(credential);
  }

  if (cable_registration_data) {
    options->set_allocated_cable_registration_data(
        cable_registration_data.release());
  }

  options->set_hmac_create_secret(use_hmac_secret);
  if (protection_policy != cryptohome::fido::ProtectionPolicy::UNSPECIFIED)
    options->set_protection_policy(protection_policy);
  options->set_enforce_protection_policy(enforce_protection_policy);

  if (!appid_exclude.empty()) {
    options->set_appid_exclude(appid_exclude);
  }
  return options;
}

FidoPKCredCreationOptionsPtr BuildFidoMakeCredentialOptions(
    const cryptohome::AccountIdentifier& account,
    const std::vector<uint8_t>& challenge,
    bool create_hmac_secret) {
  if (account.account_id() == "")
    return nullptr;

  std::vector<uint8_t> fido_account_id = GetFidoUserId(account.account_id());
  auto user = GetPublicKeyCredentialUserEntity(
      account.email(), /* name */
      fido_account_id, /* id */
      kIconUrl, account.email() /* display name */);

  auto rp = GetPublicKeyCredentialRpEntity(
      kCrosLoginPrefix + account.account_id(), /* the relying party id */
      "Chrome OS Login" /* relying party name */);

  return BuildFidoMakeCredentialOptions(
      std::move(user), std::move(rp), challenge, {}, /* exclude credentials */
      kRequestTimeOut, nullptr, /* cable registration data */
      cryptohome::fido::ProtectionPolicy::UNSPECIFIED, create_hmac_secret,
      false, /* enforce protection policy */
      "" /* appid exclude */);
}

FidoPKCredRequestOptionsPtr BuildFidoGetAssertionOptions(
    std::vector<uint8_t> challenge,
    int64_t adjusted_timeout,
    std::string relying_party_id,
    std::vector<cryptohome::fido::PublicKeyCredentialDescriptor>
        allow_credentials,
    std::string appid,
    std::vector<cryptohome::fido::CableAuthentication>
        cable_authentication_data) {
  auto options =
      std::make_unique<cryptohome::fido::PublicKeyCredentialRequestOptions>();
  std::string str_challenge(challenge.begin(), challenge.end());
  options->set_challenge(str_challenge);
  options->set_adjusted_timeout(adjusted_timeout);
  options->set_relying_party_id(relying_party_id);

  for (auto& credential : allow_credentials) {
    auto next = options->add_allow_credentials();
    next->CopyFrom(credential);
  }

  options->set_appid(appid);
  for (const auto& cable_authentication : cable_authentication_data) {
    auto next = options->add_cable_authentication_data();
    next->CopyFrom(cable_authentication);
  }
  return options;
}

FidoPKCredRequestOptionsPtr BuildFidoGetAssertionOptions(
    std::vector<uint8_t> challenge,
    std::string relying_party_id,
    std::string appid) {
  return BuildFidoGetAssertionOptions(
      challenge, kRequestTimeOut.InMilliseconds(), relying_party_id,
      {}, /* allow credentials */
      appid, {} /* Cloud Assisted BLE authentication data */);
}

}  // namespace cryptohome
