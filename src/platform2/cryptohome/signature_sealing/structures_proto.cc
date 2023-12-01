// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>
#include <variant>

#include <base/notreached.h>
#include <brillo/secure_blob.h>
#include <libhwsec/structures/signature_sealed_data.h>

#include "cryptohome/signature_sealing/structures_proto.h"

using brillo::BlobFromString;
using brillo::BlobToString;

namespace cryptohome {
namespace proto {

// We don't need to export these functions.
namespace {
SignatureSealedData_Tpm2PolicySignedData ToProto(
    const hwsec::Tpm2PolicySignedData& obj) {
  SignatureSealedData_Tpm2PolicySignedData result;
  result.set_public_key_spki_der(BlobToString(obj.public_key_spki_der));
  result.set_srk_wrapped_secret(BlobToString(obj.srk_wrapped_secret));
  if (obj.scheme.has_value()) {
    result.set_scheme(obj.scheme.value());
  }
  if (obj.hash_alg.has_value()) {
    result.set_hash_alg(obj.hash_alg.value());
  }

  // Note: The order of items added here is important, as it must match the
  // reading order in FromProto() and must never change due to backwards
  // compatibility.
  for (const hwsec::Tpm2PolicyDigest& digest : obj.pcr_policy_digests) {
    SignatureSealedData_Tpm2PcrRestriction restriction;
    restriction.set_policy_digest(BlobToString(digest.digest));
    *result.add_pcr_restrictions() = std::move(restriction);
  }

  return result;
}

hwsec::Tpm2PolicySignedData FromProto(
    const SignatureSealedData_Tpm2PolicySignedData& obj) {
  hwsec::Tpm2PolicySignedData result;
  result.public_key_spki_der = BlobFromString(obj.public_key_spki_der());
  result.srk_wrapped_secret = BlobFromString(obj.srk_wrapped_secret());
  if (obj.has_scheme()) {
    result.scheme = obj.scheme();
  }
  if (obj.has_hash_alg()) {
    result.hash_alg = obj.hash_alg();
  }

  // Note: The order of items added here is important, as it must match the
  // reading order in FromProto() and must never change due to backwards
  // compatibility.
  for (const SignatureSealedData_Tpm2PcrRestriction& restriction :
       obj.pcr_restrictions()) {
    result.pcr_policy_digests.push_back(hwsec::Tpm2PolicyDigest{
        .digest = BlobFromString(restriction.policy_digest())});
  }

  return result;
}

SignatureSealedData_Tpm12CertifiedMigratableKeyData ToProto(
    const hwsec::Tpm12CertifiedMigratableKeyData& obj) {
  SignatureSealedData_Tpm12CertifiedMigratableKeyData result;
  result.set_public_key_spki_der(BlobToString(obj.public_key_spki_der));
  result.set_srk_wrapped_cmk(BlobToString(obj.srk_wrapped_cmk));
  result.set_cmk_pubkey(BlobToString(obj.cmk_pubkey));
  result.set_cmk_wrapped_auth_data(BlobToString(obj.cmk_wrapped_auth_data));

  for (const hwsec::Tpm12PcrBoundItem& item : obj.pcr_bound_items) {
    SignatureSealedData_Tpm12PcrBoundItem bound_item;
    for (const hwsec::Tpm12PcrValue& value : item.pcr_values) {
      SignatureSealedData_PcrValue pcr_value;
      if (!value.pcr_index.has_value()) {
        LOG(WARNING) << "No PCR index in PCR bound items.";
      }
      pcr_value.set_pcr_index(value.pcr_index.value_or(0));
      pcr_value.set_pcr_value(BlobToString(value.pcr_value));
      *bound_item.add_pcr_values() = std::move(pcr_value);
    }
    bound_item.set_bound_secret(BlobToString(item.bound_secret));
    *result.add_pcr_bound_items() = std::move(bound_item);
  }

  return result;
}

hwsec::Tpm12CertifiedMigratableKeyData FromProto(
    const SignatureSealedData_Tpm12CertifiedMigratableKeyData& obj) {
  hwsec::Tpm12CertifiedMigratableKeyData result;
  result.public_key_spki_der = BlobFromString(obj.public_key_spki_der());
  result.srk_wrapped_cmk = BlobFromString(obj.srk_wrapped_cmk());
  result.cmk_pubkey = BlobFromString(obj.cmk_pubkey());
  result.cmk_wrapped_auth_data = BlobFromString(obj.cmk_wrapped_auth_data());

  for (const SignatureSealedData_Tpm12PcrBoundItem& item :
       obj.pcr_bound_items()) {
    hwsec::Tpm12PcrBoundItem bound_item{
        .bound_secret = BlobFromString(item.bound_secret())};

    for (const SignatureSealedData_PcrValue& value : item.pcr_values()) {
      bound_item.pcr_values.push_back(hwsec::Tpm12PcrValue{
          .pcr_index = value.pcr_index(),
          .pcr_value = BlobFromString(value.pcr_value()),
      });
    }

    result.pcr_bound_items.push_back(std::move(bound_item));
  }

  return result;
}

}  // namespace

ChallengeSignatureAlgorithm ToProto(
    structure::ChallengeSignatureAlgorithm obj) {
  switch (obj) {
    case structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha1:
      return ChallengeSignatureAlgorithm::CHALLENGE_RSASSA_PKCS1_V1_5_SHA1;
    case structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha256:
      return ChallengeSignatureAlgorithm::CHALLENGE_RSASSA_PKCS1_V1_5_SHA256;
    case structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha384:
      return ChallengeSignatureAlgorithm::CHALLENGE_RSASSA_PKCS1_V1_5_SHA384;
    case structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha512:
      return ChallengeSignatureAlgorithm::CHALLENGE_RSASSA_PKCS1_V1_5_SHA512;
  }
}

structure::ChallengeSignatureAlgorithm FromProto(
    ChallengeSignatureAlgorithm obj) {
  switch (obj) {
    case ChallengeSignatureAlgorithm::CHALLENGE_RSASSA_PKCS1_V1_5_SHA1:
      return structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha1;
    case ChallengeSignatureAlgorithm::CHALLENGE_RSASSA_PKCS1_V1_5_SHA256:
      return structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha256;
    case ChallengeSignatureAlgorithm::CHALLENGE_RSASSA_PKCS1_V1_5_SHA384:
      return structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha384;
    case ChallengeSignatureAlgorithm::CHALLENGE_RSASSA_PKCS1_V1_5_SHA512:
      return structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha512;
  }
}

std::optional<structure::ChallengeSignatureAlgorithm> FromProto(
    user_data_auth::SmartCardSignatureAlgorithm obj) {
  switch (obj) {
    case user_data_auth::SmartCardSignatureAlgorithm::
        CHALLENGE_RSASSA_PKCS1_V1_5_SHA1:
      return structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha1;
    case user_data_auth::SmartCardSignatureAlgorithm::
        CHALLENGE_RSASSA_PKCS1_V1_5_SHA256:
      return structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha256;
    case user_data_auth::SmartCardSignatureAlgorithm::
        CHALLENGE_RSASSA_PKCS1_V1_5_SHA384:
      return structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha384;
    case user_data_auth::SmartCardSignatureAlgorithm::
        CHALLENGE_RSASSA_PKCS1_V1_5_SHA512:
      return structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha512;
    default:  // ::SmartCardSignatureAlgorithm::CHALLENGE_NOT_SPECIFIED
      return std::nullopt;
  }
}

SignatureSealedData ToProto(const hwsec::SignatureSealedData& obj) {
  SignatureSealedData result;
  if (auto* data = std::get_if<hwsec::Tpm2PolicySignedData>(&obj)) {
    *result.mutable_tpm2_policy_signed_data() = ToProto(*data);
  } else if (auto* data =
                 std::get_if<hwsec::Tpm12CertifiedMigratableKeyData>(&obj)) {
    *result.mutable_tpm12_certified_migratable_key_data() = ToProto(*data);
  } else {
    NOTREACHED() << "Unknown signature sealed data type.";
  }
  return result;
}

hwsec::SignatureSealedData FromProto(const SignatureSealedData& obj) {
  if (obj.has_tpm2_policy_signed_data())
    return FromProto(obj.tpm2_policy_signed_data());
  else if (obj.has_tpm12_certified_migratable_key_data())
    return FromProto(obj.tpm12_certified_migratable_key_data());

  LOG(WARNING) << "Unknown signature sealed data type from protobuf.";
  // Return with the default constructor.
  return {};
}

SerializedVaultKeyset_SignatureChallengeInfo ToProto(
    const structure::SignatureChallengeInfo& obj) {
  SerializedVaultKeyset_SignatureChallengeInfo result;
  result.set_public_key_spki_der(BlobToString(obj.public_key_spki_der));
  *result.mutable_sealed_secret() = ToProto(obj.sealed_secret);
  result.set_salt(BlobToString(obj.salt));
  if (obj.salt_signature_algorithm.has_value()) {
    result.set_salt_signature_algorithm(
        ToProto(obj.salt_signature_algorithm.value()));
  }
  return result;
}

structure::SignatureChallengeInfo FromProto(
    const SerializedVaultKeyset_SignatureChallengeInfo& obj) {
  structure::SignatureChallengeInfo result;
  result.public_key_spki_der = BlobFromString(obj.public_key_spki_der());
  result.sealed_secret = FromProto(obj.sealed_secret());
  result.salt = BlobFromString(obj.salt());
  if (obj.has_salt_signature_algorithm()) {
    result.salt_signature_algorithm = FromProto(obj.salt_signature_algorithm());
  }
  return result;
}

ChallengePublicKeyInfo ToProto(const structure::ChallengePublicKeyInfo& obj) {
  ChallengePublicKeyInfo result;
  result.set_public_key_spki_der(BlobToString(obj.public_key_spki_der));
  for (const auto& content : obj.signature_algorithm)
    result.add_signature_algorithm(ToProto(content));
  return result;
}

structure::ChallengePublicKeyInfo FromProto(const ChallengePublicKeyInfo& obj) {
  structure::ChallengePublicKeyInfo result;
  result.public_key_spki_der = BlobFromString(obj.public_key_spki_der());
  for (const auto& content : obj.signature_algorithm()) {
    result.signature_algorithm.push_back(
        FromProto(ChallengeSignatureAlgorithm{content}));
  }
  return result;
}

}  // namespace proto
}  // namespace cryptohome
