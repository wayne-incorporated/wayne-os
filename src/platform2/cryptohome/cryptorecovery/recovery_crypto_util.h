// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_CRYPTORECOVERY_RECOVERY_CRYPTO_UTIL_H_
#define CRYPTOHOME_CRYPTORECOVERY_RECOVERY_CRYPTO_UTIL_H_

#include <string>
#include <vector>

#include <brillo/secure_blob.h>
#include <chromeos/cbor/values.h>
#include <libhwsec/structures/explicit_init.h>

namespace cryptohome {
namespace cryptorecovery {

// AEAD-encrypted payload.
struct AeadPayload {
  // AES-GCM tag for encryption.
  brillo::SecureBlob tag;
  // AES-GCM iv for encryption.
  brillo::SecureBlob iv;
  // Additional authentication data, passed in clear. Serialized in cbor.
  brillo::SecureBlob associated_data;
  // Encrypted plain text. Plain text is serialized in cbor.
  brillo::SecureBlob cipher_text;
};

// HSM Payload is created at onboarding and contains all the data that are
// persisted on a chromebook and will be eventually used for recovery.
using HsmPayload = AeadPayload;

// Recovery Request Payload is created during recovery flow.
// `associated_data` contains data from `HsmPayload`, request metadata (RMD),
// and epoch public key (G*r).
using RequestPayload = AeadPayload;

// HSM response. Contains response associated data AD3 = {kav, HMD}
// (where kav is Key Auth Value and HMD is HSM Metadata) and plain text
// response PT3 = {dealer_pub_key, mediated_share} encrypted with
// DH of epoch and channel_pub_key.
using ResponsePayload = AeadPayload;

// !!! DO NOT MODIFY !!!
// The enum values below are exchanged with the server and must be synced with
// the server/HSM implementation (or the other party will not be able to decrypt
// the data). Type of the `cryptohome_user` field sent in `OnboardingMetadata`.
enum class UserType {
  kUnknown = 0,
  kGaiaId = 1,
};

// LoggedRecord is included in LedgerSignedProof of HsmResponseAssociatedData.
struct LoggedRecord {
  // Leaf content (serialized PublicLedgerEntry).
  brillo::Blob public_ledger_entry;
  // Serialized private log entry.
  brillo::Blob private_log_entry;
  // Leaf index of this record in the tree.
  int64_t leaf_index = -1;
};

// LedgerSignedProof is included in HsmResponseAssociatedData.
struct LedgerSignedProof {
  // Tree checkpoint in signed note format.
  brillo::Blob checkpoint_note;
  // Corresponding inclusion proof.
  std::vector<brillo::Blob> inclusion_proof;
  // Record of what was logged in the ledger.
  LoggedRecord logged_record;
};

// The ledger info from the chrome side and used by Cryptohome
// recovery flow to determine which ledger is used.
struct LedgerInfo {
  // Ledger's name.
  std::string name;
  // Ledger's public key hash.
  hwsec::ExplicitInit<uint32_t> key_hash;
  // Ledger's public key.
  hwsec::ExplicitInit<brillo::SecureBlob> public_key;
};

// `OnboardingMetadata` contains essential information that needs to be
// available during the Recovery workflow. This information is used by the
// Recovery Service and may be recorded in the Ledger.
struct OnboardingMetadata {
  UserType cryptohome_user_type = UserType::kUnknown;
  // Format of `cryptohome_user` is determined by `cryptohome_user_type` enum.
  std::string cryptohome_user;
  // Unique ID tied to the user's cryptohome on the device
  std::string device_user_id;
  std::string board_name;
  std::string form_factor;
  std::string rlz_code;
  // Generated anew after each successful recovery, hex-encoded sha-256 hash
  // string.
  std::string recovery_id;
};

// `associated_data` for the HSM payload.
// `publisher_pub_key` and `channel_pub_key` are elliptic curve points in
// DER-encoded X.509 SubjectPublicKeyInfo format.
struct HsmAssociatedData {
  // G*u, one of the keys that will be used for HSM payload decryption.
  brillo::SecureBlob publisher_pub_key;
  // G*s, one of the keys that will be used for Request payload decryption.
  brillo::SecureBlob channel_pub_key;
  // The key (X.509 SubjectPublicKeyInfo structure in DER) sent to HSM so that
  // it can validate Request payload, used only for TPM 1.2.
  brillo::SecureBlob rsa_public_key;
  // The metadata generated during the Onboarding workflow on a Chromebook
  // (OMD).
  OnboardingMetadata onboarding_meta_data;
};

// Plain text for the HSM payload.
// `dealer_pub_key` is an elliptic curve point in DER-encoded X.509
// SubjectPublicKeyInfo format. `mediator_share` and `key_auth_value` are
// BIGNUMs encoded in big-endian form.
struct HsmPlainText {
  // Secret share of the Mediator (b1).
  brillo::SecureBlob mediator_share;
  // Key generated on Chromebook, to be sent to the Mediator service (G*a).
  brillo::SecureBlob dealer_pub_key;
  // Additional secret to seal the destination share. Used for TPM 1.2 only.
  brillo::SecureBlob key_auth_value;
};

// Data used to prove user's authentication to the Recovery Service.
struct AuthClaim {
  // Access token with reauth scope.
  std::string gaia_access_token;
  // A short-lived token, it's validity will be verified by the Recovery
  // Service.
  std::string gaia_reauth_proof_token;
};

// `RequestMetadata` includes any information the Chromebook needs logged in the
// ledger. Different auth_claim types can be supported by using the
// schema_version to distinguish them.
struct RequestMetadata {
  AuthClaim auth_claim;
  UserType requestor_user_id_type = UserType::kUnknown;
  // Format of `requestor_user_id` is determined by `requestor_user_id_type`
  // enum.
  std::string requestor_user_id;
};

// `EpochMetadata` includes any information the HSM needs to compute the Epoch
// beacon, and which will be logged into the ledger.
struct EpochMetadata {
  // Cbor map containing epoch metadata. This map is passed to the recovery
  // server without being read by the client.
  cbor::Value meta_data_cbor;

  EpochMetadata() = default;

  EpochMetadata(EpochMetadata const& other)
      : meta_data_cbor(other.meta_data_cbor.Clone()) {}

  EpochMetadata& operator=(const EpochMetadata& other) {
    if (this != &other) {
      meta_data_cbor = other.meta_data_cbor.Clone();
    }
    return *this;
  }
};

// `associated_data` for the Request payload.
struct RecoveryRequestAssociatedData {
  // HSM payload.
  HsmPayload hsm_payload;
  // The metadata generated during the Recovery flow on a Chromebook (RMD).
  RequestMetadata request_meta_data;
  // The metadata generated on the Reverse Proxy, and retrieved by the
  // Chromebook from the Recovery Service when it obtains the Epoch Beacon.
  EpochMetadata epoch_meta_data;
  // Salt used in the derivation of request payload encryption key.
  brillo::SecureBlob request_payload_salt;
};

// Plain text for the Request payload.
// `ephemeral_pub_inv_key` is an elliptic curve point in DER-encoded X.509
// SubjectPublicKeyInfo format.
struct RecoveryRequestPlainText {
  // Ephemeral inverse key (G*-x) that is added to mediator DH (G*ab1) by the
  // Mediator service.
  brillo::SecureBlob ephemeral_pub_inv_key;
};

// RecoveryRequest is the request sent to the HSM server.
struct RecoveryRequest {
  // The AEAD-encrypted payload.
  brillo::SecureBlob request_payload;
  // The RSA signature of the AEAD-encrypted payload using SHA-256.
  // It's an optional field, used only on TPM 1.2 devices.
  brillo::SecureBlob rsa_signature;
};

// Metadata to be sent back from the HSM to the Chromebook, empty so far.
struct HsmMetaData {};

// `associated_data` for the Response payload.
struct HsmResponseAssociatedData {
  // Salt used in the derivation of response payload encryption key.
  brillo::SecureBlob response_payload_salt;
  // The metadata generated by HSM.
  HsmMetaData hsm_meta_data;
  // Inclusion proof signed by the ledger.
  LedgerSignedProof ledger_signed_proof;
};

// Plain text for the Response payload.
// `dealer_pub_key` and `mediated_point` are elliptic curve points in
// DER-encoded X.509 SubjectPublicKeyInfo format. `key_auth_value` is BIGNUM
// encoded in big-endian form.
struct HsmResponsePlainText {
  // Mediated mediator share (b1) sent back to the Chromebook.
  brillo::SecureBlob mediated_point;
  // Key generated on Chromebook, that was used for mediation (G*a).
  brillo::SecureBlob dealer_pub_key;
  // Additional secret to seal the destination share. Used for TPM 1.2 only.
  brillo::SecureBlob key_auth_value;
};

}  // namespace cryptorecovery
}  // namespace cryptohome

#endif  // CRYPTOHOME_CRYPTORECOVERY_RECOVERY_CRYPTO_UTIL_H_
