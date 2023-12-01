// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_CRYPTORECOVERY_RECOVERY_CRYPTO_H_
#define CRYPTOHOME_CRYPTORECOVERY_RECOVERY_CRYPTO_H_

#include <memory>
#include <optional>
#include <string>

#include <brillo/secure_blob.h>
#include <crypto/scoped_openssl_types.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <libhwsec-foundation/crypto/ecdh_hkdf.h>
#include <libhwsec-foundation/crypto/elliptic_curve.h>
#include <libhwsec-foundation/utility/no_default_init.h>

#include "cryptohome/cryptorecovery/cryptorecovery.pb.h"
#include "cryptohome/cryptorecovery/recovery_crypto_util.h"
#include "cryptohome/error/cryptohome_crypto_error.h"
#include "cryptohome/username.h"

namespace cryptohome {
namespace cryptorecovery {

// RecoveryCrypto input parameters for function GenerateHsmPayload.
struct GenerateHsmPayloadRequest {
  hwsec_foundation::NoDefault<brillo::SecureBlob> mediator_pub_key;
  // The metadata generated during the Onboarding workflow on a Chromebook
  // (OMD).
  hwsec_foundation::NoDefault<OnboardingMetadata> onboarding_metadata;
  // Used to generate PCR map.
  hwsec_foundation::NoDefault<ObfuscatedUsername> obfuscated_username;
};

// RecoveryCrypto output parameters for function GenerateHsmPayload.
struct GenerateHsmPayloadResponse {
  HsmPayload hsm_payload;
  brillo::SecureBlob encrypted_rsa_priv_key;
  brillo::SecureBlob encrypted_destination_share;
  brillo::SecureBlob extended_pcr_bound_destination_share;
  brillo::SecureBlob recovery_key;
  brillo::SecureBlob channel_pub_key;
  brillo::SecureBlob encrypted_channel_priv_key;
};

// RecoveryCrypto input parameters for function GenerateRecoveryRequest.
struct GenerateRecoveryRequestRequest {
  hwsec_foundation::NoDefault<HsmPayload> hsm_payload;
  hwsec_foundation::NoDefault<RequestMetadata> request_meta_data;
  CryptoRecoveryEpochResponse epoch_response;
  hwsec_foundation::NoDefault<brillo::SecureBlob> encrypted_rsa_priv_key;
  hwsec_foundation::NoDefault<brillo::SecureBlob> encrypted_channel_priv_key;
  hwsec_foundation::NoDefault<brillo::SecureBlob> channel_pub_key;
  hwsec_foundation::NoDefault<ObfuscatedUsername> obfuscated_username;
};

// RecoveryCrypto input parameters for function RecoverDestination.
struct RecoverDestinationRequest {
  hwsec_foundation::NoDefault<brillo::SecureBlob> dealer_pub_key;
  hwsec_foundation::NoDefault<brillo::SecureBlob> key_auth_value;
  hwsec_foundation::NoDefault<brillo::SecureBlob> encrypted_destination_share;
  hwsec_foundation::NoDefault<brillo::SecureBlob>
      extended_pcr_bound_destination_share;
  hwsec_foundation::NoDefault<brillo::SecureBlob> ephemeral_pub_key;
  hwsec_foundation::NoDefault<brillo::SecureBlob> mediated_publisher_pub_key;
  hwsec_foundation::NoDefault<ObfuscatedUsername> obfuscated_username;
};

// RecoveryCrypto input parameters for function DecryptResponsePayload.
struct DecryptResponsePayloadRequest {
  hwsec_foundation::NoDefault<brillo::SecureBlob> encrypted_channel_priv_key;
  CryptoRecoveryEpochResponse epoch_response;
  CryptoRecoveryRpcResponse recovery_response_proto;
  hwsec_foundation::NoDefault<ObfuscatedUsername> obfuscated_username;
  LedgerInfo ledger_info;
};

// Cryptographic operations for cryptohome recovery.
// Recovery mechanism involves dealer, publisher, mediator and destination. The
// dealer is invoked during initial setup to generate random shares. The dealer
// functionality is implemented in `GenerateShares` method. The publisher
// performs the actual encryption of the cryptohome recovery key using a
// symmetric key derived from `publisher_dh` - the result of
// `GeneratePublisherKeys` method. The mediator is an external service that is
// invoked during the recovery process to perform mediation of an encrypted
// mediator share. The destination is invoked as part of the recovery UX on the
// device to obtain a cryptohome recovery key. The recovery key can be derived
// from `destination_dh` - the result of `RecoverDestination` method. Note that
// in a successful recovery `destination_dh` should be equal to `publisher_dh`.
class RecoveryCrypto {
 public:
  // Constant value of hkdf_info for mediator share. Must be kept in sync with
  // the server.
  static const char kMediatorShareHkdfInfoValue[];

  // Constant value of hkdf_info for request payload plaintext. Must be kept in
  // sync with the server.
  static const char kRequestPayloadPlainTextHkdfInfoValue[];

  // Constant value of hkdf_info for response payload plaintext. Must be kept in
  // sync with the server.
  static const char kResponsePayloadPlainTextHkdfInfoValue[];

  // Elliptic Curve type used by the protocol.
  static const hwsec_foundation::EllipticCurve::CurveType kCurve;

  // Hash used by HKDF for encrypting mediator share.
  static const hwsec_foundation::HkdfHash kHkdfHash;

  // Length of the salt (in bytes) used by HKDF for encrypting mediator share.
  static const unsigned int kHkdfSaltLength;

  virtual ~RecoveryCrypto();

  // Generates Request payload that will be sent to Recovery Mediator Service
  // during recovery process.
  // Consist of the following steps:
  // 1. Construct associated data AD2 = {hsm_payload, `request_metadata`}.
  // 2. Generate symmetric key for encrypting plain text from (G*r)*s
  // (`epoch_response::epoch_pub_key` * `channel_priv_key`).
  // 3. Generate ephemeral key pair {x, G*x} and calculate an inverse G*-x.
  // 4. Save G*x to `ephemeral_pub_key` parameter.
  // 5. Construct plain text PT2 = {G*-x}.
  // 6. Encrypt {AD2, PT2} using AES-GCM scheme.
  // 7. Construct `CryptoRecoveryRpcRequest` which contains `RecoveryRequest`
  // serialized to CBOR.
  [[nodiscard]] virtual bool GenerateRecoveryRequest(
      const GenerateRecoveryRequestRequest& request,
      CryptoRecoveryRpcRequest* recovery_request,
      brillo::SecureBlob* ephemeral_pub_key) const = 0;

  // Generates HSM payload that will be persisted on a chromebook at enrollment
  // to be subsequently used for recovery.
  // Consist of the following steps:
  // 1. Generate publisher key pair (u, G * u according to the protocol spec).
  // 2. Generate dealer key pair (a, G * a)
  // 3. Generate 2 shares: mediator (b1) and destination (b2).
  // 4. Generate channel key pair (s, G*s) and set `channel_priv_key` and
  // `channel_pub_key`.
  // 5. Construct associated data {G*s, G*u, `rsa_pub_key`,
  // `onboarding_metadata`}.
  // 6. Construct plain text {G*a, b2, kav} (note kav == key auth value is used
  // only in TPM 1.2 and will be generated for non-empty `rsa_pub_key`).
  // 7. Calculate shared secret G*(a(b1+b2)) and convert it to the
  // `recovery_key`.
  // 8. Generate symmetric key for encrypting PT from (G*h)*u (where G*h is the
  // mediator public key provided as input).
  // 9. Encrypt {AD, PT} using AES-GCM scheme.
  //
  // G*s is included in associated data, s is either wrapped with TPM 2.0 or
  // stored in host for TPM 1.2.
  // The resulting destination share should be either added to TPM 2.0 or sealed
  // with kav for TPM 1.2 and stored in the host.
  [[nodiscard]] virtual bool GenerateHsmPayload(
      const GenerateHsmPayloadRequest& request,
      GenerateHsmPayloadResponse* response) const = 0;

  // Recovers destination. Returns false if error occurred.
  // Formula:
  //   mediated_point = `mediated_publisher_pub_key` + `ephemeral_pub_key`
  //   destination_recovery_key = HKDF((dealer_pub_key * destination_share
  //                                   + mediated_point))
  // key_auth_value is required for unsealing destination_share on TPM1 modules
  // whereas for TPM2, destination_share is imported into TPM2 modules, and
  // loaded back in the form of key handle, which requires no additional crypto
  // secret.
  [[nodiscard]] virtual bool RecoverDestination(
      const RecoverDestinationRequest& request,
      brillo::SecureBlob* destination_recovery_key) const = 0;

  // Decrypt plain text from the Recovery Response.
  // Consists of the following steps:
  // 1. Deserialize `recovery_response_proto.cbor_cryptorecoveryresponse` to
  // `ResponsePayload`.
  // 2. Get cipher text, associated data, AES-GCM tag and iv from
  // `response_payload` field of `ResponsePayload`
  // 3. Decrypt cipher text of response payload, deserialize it from CBOR
  // and store the result in `response_plain_text`. The key for decryption is
  // HKDF(ECDH(channel_priv_key, epoch_response.epoch_pub_key)).
  virtual CryptoStatus DecryptResponsePayload(
      const DecryptResponsePayloadRequest& request,
      HsmResponsePlainText* response_plain_text) const = 0;
};

}  // namespace cryptorecovery
}  // namespace cryptohome

#endif  // CRYPTOHOME_CRYPTORECOVERY_RECOVERY_CRYPTO_H_
