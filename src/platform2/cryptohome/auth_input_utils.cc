// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_input_utils.h"

#include <optional>
#include <string>

#include <base/logging.h>
#include <brillo/cryptohome.h>
#include <brillo/secure_blob.h>
#include <cryptohome/proto_bindings/auth_factor.pb.h>

#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/crypto.h"
#include "cryptohome/filesystem_layout.h"
#include "cryptohome/flatbuffer_schemas/auth_factor.h"
#include "cryptohome/key_objects.h"
#include "cryptohome/platform.h"
#include "cryptohome/signature_sealing/structures_proto.h"

using brillo::SecureBlob;

namespace cryptohome {

namespace {

AuthInput FromPasswordAuthInput(
    const user_data_auth::PasswordAuthInput& proto) {
  return AuthInput{
      .user_input = SecureBlob(proto.secret()),
  };
}

AuthInput FromPinAuthInput(const user_data_auth::PinAuthInput& proto) {
  return AuthInput{
      .user_input = SecureBlob(proto.secret()),
  };
}

AuthInput FromCryptohomeRecoveryAuthInput(
    const user_data_auth::CryptohomeRecoveryAuthInput& proto,
    const std::optional<brillo::SecureBlob>&
        cryptohome_recovery_ephemeral_pub_key) {
  CryptohomeRecoveryAuthInput recovery_auth_input{
      // These fields are used for `Create`:
      .mediator_pub_key = SecureBlob(proto.mediator_pub_key()),
      .user_gaia_id = proto.user_gaia_id(),
      .device_user_id = proto.device_user_id(),
      // These fields are used for `Derive`:
      .epoch_response = SecureBlob(proto.epoch_response()),
      .ephemeral_pub_key =
          cryptohome_recovery_ephemeral_pub_key.value_or(SecureBlob()),
      .recovery_response = SecureBlob(proto.recovery_response()),
      .ledger_name = proto.ledger_info().name(),
      .ledger_key_hash = proto.ledger_info().key_hash(),
      .ledger_public_key = SecureBlob(proto.ledger_info().public_key()),
  };

  return AuthInput{.cryptohome_recovery_auth_input = recovery_auth_input};
}

AuthInput FromSmartCardAuthInput(
    const user_data_auth::SmartCardAuthInput& proto,
    const std::optional<brillo::Blob>& public_key_spki_der) {
  ChallengeCredentialAuthInput chall_cred_auth_input;
  for (const auto& content : proto.signature_algorithms()) {
    std::optional<structure::ChallengeSignatureAlgorithm> signature_algorithm =
        proto::FromProto(ChallengeSignatureAlgorithm(content));
    if (signature_algorithm.has_value()) {
      chall_cred_auth_input.challenge_signature_algorithms.push_back(
          signature_algorithm.value());
    } else {
      // One of the signature algorithm's parsed is CHALLENGE_NOT_SPECIFIED.
      return AuthInput{
          .challenge_credential_auth_input = std::nullopt,
      };
    }
  }

  if (public_key_spki_der && !public_key_spki_der->empty()) {
    chall_cred_auth_input.public_key_spki_der = public_key_spki_der.value();
  }

  if (!proto.key_delegate_dbus_service_name().empty()) {
    chall_cred_auth_input.dbus_service_name =
        proto.key_delegate_dbus_service_name();
  }

  return AuthInput{
      .challenge_credential_auth_input = chall_cred_auth_input,
  };
}

std::optional<AuthInput> FromKioskAuthInput(
    Platform* platform,
    const user_data_auth::KioskAuthInput& proto,
    const Username& username) {
  brillo::SecureBlob public_mount_salt;
  if (!GetPublicMountSalt(platform, &public_mount_salt)) {
    LOG(ERROR) << "Could not get or create public salt from file";
    return std::nullopt;
  }
  brillo::SecureBlob passkey;
  Crypto::PasswordToPasskey(username->c_str(), public_mount_salt, &passkey);
  return AuthInput{
      .user_input = passkey,
  };
}

AuthInput FromLegacyFingerprintAuthInput(
    const user_data_auth::LegacyFingerprintAuthInput& proto) {
  return AuthInput{};
}

AuthInput FromFingerprintAuthInput(
    const user_data_auth::FingerprintAuthInput& proto) {
  return AuthInput{};
}

}  // namespace

std::optional<AuthInput> CreateAuthInput(
    Platform* platform,
    const user_data_auth::AuthInput& auth_input_proto,
    const Username& username,
    const ObfuscatedUsername& obfuscated_username,
    bool locked_to_single_user,
    const std::optional<brillo::SecureBlob>&
        cryptohome_recovery_ephemeral_pub_key,
    const AuthFactorMetadata& auth_factor_metadata) {
  std::optional<AuthInput> auth_input;
  switch (auth_input_proto.input_case()) {
    case user_data_auth::AuthInput::kPasswordInput:
      auth_input = FromPasswordAuthInput(auth_input_proto.password_input());
      break;
    case user_data_auth::AuthInput::kPinInput:
      auth_input = FromPinAuthInput(auth_input_proto.pin_input());
      break;
    case user_data_auth::AuthInput::kCryptohomeRecoveryInput:
      auth_input = FromCryptohomeRecoveryAuthInput(
          auth_input_proto.cryptohome_recovery_input(),
          cryptohome_recovery_ephemeral_pub_key);
      break;
    case user_data_auth::AuthInput::kKioskInput:
      auth_input = FromKioskAuthInput(platform, auth_input_proto.kiosk_input(),
                                      username);
      break;
    case user_data_auth::AuthInput::kSmartCardInput: {
      // Check for auth_factor_metadata and add the public_key_spki_der to
      // AuthInput from the auth_factor_metadata
      const auto* smart_card_metadata =
          std::get_if<auth_factor::SmartCardMetadata>(
              &auth_factor_metadata.metadata);
      std::optional<brillo::Blob> public_key_spki_der;
      if (smart_card_metadata) {
        public_key_spki_der = smart_card_metadata->public_key_spki_der;
      } else {
        public_key_spki_der = std::nullopt;
      }
      auth_input = FromSmartCardAuthInput(auth_input_proto.smart_card_input(),
                                          public_key_spki_der);
      break;
    }
    case user_data_auth::AuthInput::kLegacyFingerprintInput:
      auth_input = FromLegacyFingerprintAuthInput(
          auth_input_proto.legacy_fingerprint_input());
      break;
    case user_data_auth::AuthInput::kFingerprintInput:
      auth_input =
          FromFingerprintAuthInput(auth_input_proto.fingerprint_input());
      break;
    case user_data_auth::AuthInput::INPUT_NOT_SET:
      break;
  }

  if (!auth_input.has_value()) {
    LOG(ERROR) << "Empty or unknown auth input";
    return std::nullopt;
  }

  // Fill out common fields.
  auth_input.value().username = username;
  auth_input.value().obfuscated_username = obfuscated_username;
  auth_input.value().locked_to_single_user = locked_to_single_user;

  return auth_input;
}

std::optional<AuthFactorType> DetermineFactorTypeFromAuthInput(
    const user_data_auth::AuthInput& auth_input_proto) {
  switch (auth_input_proto.input_case()) {
    case user_data_auth::AuthInput::kPasswordInput:
      return AuthFactorType::kPassword;
    case user_data_auth::AuthInput::kPinInput:
      return AuthFactorType::kPin;
    case user_data_auth::AuthInput::kCryptohomeRecoveryInput:
      return AuthFactorType::kCryptohomeRecovery;
    case user_data_auth::AuthInput::kKioskInput:
      return AuthFactorType::kKiosk;
    case user_data_auth::AuthInput::kSmartCardInput:
      return AuthFactorType::kSmartCard;
    case user_data_auth::AuthInput::kLegacyFingerprintInput:
      return AuthFactorType::kLegacyFingerprint;
    case user_data_auth::AuthInput::kFingerprintInput:
      return AuthFactorType::kFingerprint;
    case user_data_auth::AuthInput::INPUT_NOT_SET:
      return std::nullopt;
  }
}

}  // namespace cryptohome
