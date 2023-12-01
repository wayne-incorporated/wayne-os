// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-test-utils/verified_access/verified_access.h"

#include <optional>
#include <string>
#include <utility>

#include <attestation/proto_bindings/attestation_ca.pb.h>
#include <base/logging.h>
#include <crypto/scoped_openssl_types.h>

#include "hwsec-test-utils/common/attestation_crypto.h"
#include "hwsec-test-utils/common/openssl_utility.h"
#include "hwsec-test-utils/well_known_key_pairs/well_known_key_pairs.h"

namespace hwsec_test_utils {
namespace verified_access {

namespace {

constexpr int kNonceSize = 20;

std::optional<std::string> GenerateNonce() {
  return GetRandom(kNonceSize);
}

std::optional<attestation::KeyInfo> DecryptKeyInfo(
    const attestation::EncryptedData& encrypted_key_info) {
  crypto::ScopedEVP_PKEY key = well_known_key_pairs::GetVaEncryptionkey();

  std::string decrypted_data;
  attestation_crypto::ReturnStatus decrypt_status = attestation_crypto::Decrypt(
      encrypted_key_info, key, attestation_crypto::KeyDeriverDirect(),
      &decrypted_data);
  if (decrypt_status != attestation_crypto::ReturnStatus::kSuccess) {
    LOG(ERROR) << __func__
               << ": Failed to decrypt serialized key info; status code: "
               << static_cast<int>(decrypt_status);
    return {};
  }

  // Deserialize.
  attestation::KeyInfo key_info;
  if (!key_info.ParseFromString(decrypted_data)) {
    LOG(ERROR) << __func__ << ": Failed to parse |KeyInfo|.";
    return {};
  }
  return key_info;
}

bool VerifySPKAC(const attestation::KeyInfo& key_info) {
  auto asn1_ptr = reinterpret_cast<const unsigned char*>(
      key_info.signed_public_key_and_challenge().data());
  crypto::ScopedNETSCAPE_SPKI spki(d2i_NETSCAPE_SPKI(
      nullptr, &asn1_ptr, key_info.signed_public_key_and_challenge().length()));
  if (!spki) {
    LOG(ERROR) << __func__
               << ": Failed to call d2i_NETSCAPE_SPKI: " << GetOpenSSLError();
    return false;
  }

  // Verifies the SPKI with the key in the SPKI.
  crypto::ScopedEVP_PKEY key(NETSCAPE_SPKI_get_pubkey(spki.get()));
  if (!key) {
    LOG(ERROR) << __func__ << ": Failed to call NETSCAPE_SPKI_get_pubkey: "
               << GetOpenSSLError();
    return false;
  }

  crypto::ScopedX509 x509 = PemToX509(key_info.certificate());
  if (!x509) {
    LOG(ERROR) << __func__ << ": Failed to parse certificate.";
    return false;
  }

  if (NETSCAPE_SPKI_verify(spki.get(), key.get()) != 1) {
    LOG(ERROR) << __func__ << ": Failed to call NETSCAPE_SPKI_verify: "
               << GetOpenSSLError();
    return false;
  }

  crypto::ScopedEVP_PKEY key_in_cert(X509_get_pubkey(x509.get()));
  if (!key_in_cert) {
    LOG(ERROR) << __func__
               << ": Failed to call X509_get_pubkey: " << GetOpenSSLError();
    return false;
  }

  // It is intentional not to print any interpreted result because the
  // interpretation might be subject to change or extension with openssl version
  // being upgraded. Please look up the openssl document for the meaning.
  int compare_result;
  if ((compare_result = EVP_PKEY_cmp(key.get(), key_in_cert.get())) != 1) {
    LOG(ERROR) << __func__ << ": EVP_PKEY_cmp result: " << compare_result;
    return false;
  }
  return true;
}

}  // namespace

VerifiedAccessChallenge::VerifiedAccessChallenge() {
  InitializeOpenSSL();
}

std::optional<attestation::SignedData>
VerifiedAccessChallenge::GenerateChallenge(const std::string& prefix) {
  // Generate the data to sign, including the prefix and a nonce.
  attestation::Challenge challenge;
  challenge.set_prefix(prefix);
  std::optional<std::string> nonce = GenerateNonce();
  if (!nonce) {
    LOG(WARNING) << __func__ << ": Failed to generate nonce.";
    return {};
  }
  challenge.set_nonce(*nonce);
  std::string serialized_challenge;
  if (!challenge.SerializeToString(&serialized_challenge)) {
    LOG(ERROR) << __func__ << ": Failed to serialize challenge.";
    return {};
  }

  // Construct the return value, including the data and its signature.
  attestation::SignedData signed_data;
  signed_data.set_data(serialized_challenge);
  crypto::ScopedEVP_PKEY key = well_known_key_pairs::GetVaSigningkey();
  if (!key) {
    LOG(ERROR) << __func__ << ": Failed get the va signing key.";
    return {};
  }
  std::optional<std::string> signature =
      EVPDigestSign(key, EVP_sha256(), serialized_challenge);
  if (!signature) {
    LOG(ERROR) << __func__ << ": Failed to sign the generated challenge.";
  }
  *signed_data.mutable_signature() = std::move(*signature);
  return signed_data;
}

bool VerifiedAccessChallenge::VerifyChallengeResponse(
    const attestation::SignedData& signed_challenge_response,
    const std::string& prefix) {
  attestation::ChallengeResponse challenge_response;
  if (!challenge_response.ParseFromString(signed_challenge_response.data())) {
    LOG(ERROR) << __func__ << ": Failed to parse |ChallengeResponse|";
    return false;
  }

  // Verify the nonce is set.
  if (challenge_response.nonce().empty()) {
    LOG(ERROR) << __func__ << ": no nonce in response.";
    return false;
  }

  // Verify the challenge has expected signature and prefix.
  crypto::ScopedEVP_PKEY google_signing_key =
      well_known_key_pairs::GetVaSigningkey();
  const attestation::SignedData& challenge_with_signature =
      challenge_response.challenge();
  if (!EVPDigestVerify(google_signing_key, EVP_sha256(),
                       challenge_with_signature.data(),
                       challenge_with_signature.signature())) {
    LOG(ERROR) << __func__ << ": challenge signature mismatch.";
    return false;
  }
  attestation::Challenge challenge;
  if (!challenge.ParseFromString(challenge_with_signature.data())) {
    LOG(ERROR) << __func__ << ": Failed to parse |Challenge|";
    return false;
  }
  if (challenge.prefix() != prefix) {
    LOG(ERROR) << __func__ << ": Prefix mismatch: " << challenge.prefix()
               << "(expected: " << prefix << ")";
    return false;
  }

  // Note that by design there is no verification against key_id since in the
  // testing we don't care.
  std::optional<attestation::KeyInfo> key_info =
      DecryptKeyInfo(challenge_response.encrypted_key_info());
  if (!key_info) {
    LOG(ERROR) << __func__ << ": Failed to decrypt |KeyInfo|.";
    return false;
  }

  if (!VerifySPKAC(*key_info)) {
    LOG(ERROR) << __func__ << ": Failed to verify SPKAC.";
    return false;
  }

  crypto::ScopedX509 x509 = PemToX509(key_info->certificate());
  if (!x509) {
    LOG(ERROR) << __func__ << ": Failed to parse certificate.";
    return false;
  }

  // Verify response signature.
  crypto::ScopedEVP_PKEY key_in_cert(X509_get_pubkey(x509.get()));
  if (!key_in_cert) {
    LOG(ERROR) << __func__
               << ": Failed to call X509_get_pubkey: " << GetOpenSSLError();
    return false;
  }
  if (!EVPDigestVerify(key_in_cert, EVP_sha256(),
                       signed_challenge_response.data(),
                       signed_challenge_response.signature())) {
    LOG(ERROR) << __func__
               << ": Failed to verify signature of challenge response.";
  }
  return true;
}

}  // namespace verified_access
}  // namespace hwsec_test_utils
