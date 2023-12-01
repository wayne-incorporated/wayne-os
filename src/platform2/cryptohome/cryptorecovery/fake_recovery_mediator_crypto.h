// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_CRYPTORECOVERY_FAKE_RECOVERY_MEDIATOR_CRYPTO_H_
#define CRYPTOHOME_CRYPTORECOVERY_FAKE_RECOVERY_MEDIATOR_CRYPTO_H_

#include <memory>

#include <brillo/secure_blob.h>
#include <libhwsec-foundation/crypto/elliptic_curve.h>

#include "cryptohome/cryptorecovery/recovery_crypto.h"
#include "cryptohome/cryptorecovery/recovery_crypto_util.h"

namespace cryptohome {
namespace cryptorecovery {

// Cryptographic operations for fake mediator for cryptohome recovery.
// Recovery mechanism involves dealer, publisher, mediator and destination.
// The mediator is an external service that is invoked during the recovery
// process to perform mediation of an encrypted mediator share. The
// functionality of mediator should be implemented on the server and here it is
// implemented for testing purposes only.
class FakeRecoveryMediatorCrypto {
 public:
  // Creates instance. Returns nullptr if error occurred.
  static std::unique_ptr<FakeRecoveryMediatorCrypto> Create();

  // Returns hardcoded dev ledger info that can be used to verify the payload
  // created with MediateHsmPayload().
  static LedgerInfo GetLedgerInfo();

  // Returns hardcoded fake mediator public key for encrypting mediator share.
  // Do not use this key in production!
  // Returns false if error occurred.
  static bool GetFakeMediatorPublicKey(brillo::SecureBlob* mediator_pub_key);

  // Returns hardcoded fake mediator private key for decrypting mediator share.
  // Do not use this key in production!
  // Returns false if error occurred.
  static bool GetFakeMediatorPrivateKey(brillo::SecureBlob* mediator_priv_key);

  // Returns hardcoded fake epoch public key for encrypting request payload.
  // Do not use this key in production!
  // Returns false if error occurred.
  static bool GetFakeEpochPublicKey(brillo::SecureBlob* epoch_pub_key);

  // Returns hardcoded fake epoch private key for decrypting request payload.
  // Do not use this key in production!
  // Returns false if error occurred.
  static bool GetFakeEpochPrivateKey(brillo::SecureBlob* epoch_priv_key);

  // Returns `CryptoRecoveryEpochResponse` with  hardcoded fake epoch public key
  // for encrypting request payload. Do not use this in production!
  static bool GetFakeEpochResponse(CryptoRecoveryEpochResponse* epoch_response);

  // Receives `request_payload`, performs mediation and generates response
  // payload. This function consist of the following steps:
  // 1. Deserialize `channel_pub_key` from `hsm_aead_ad` in
  // `request_payload.associated_data`.
  // 2. Perform DH(`epoch_priv_key`, channel_pub_key), decrypt
  // `cipher_text` (CT2) from `request_payload`.
  // 3. Deserialize `recovery_request.cbor_cryptorecoveryrequest` to
  // `RequestPayload`.
  // 4. Extract `hsm_payload` from `RequestPayload`.
  // 5. Do `MediateHsmPayload` with `hsm_payload` and keys (`epoch_pub_key`,
  // `epoch_priv_key`, `mediator_priv_key`).
  bool MediateRequestPayload(
      const brillo::SecureBlob& epoch_pub_key,
      const brillo::SecureBlob& epoch_priv_key,
      const brillo::SecureBlob& mediator_priv_key,
      const CryptoRecoveryRpcRequest& recovery_request_proto,
      CryptoRecoveryRpcResponse* recovery_response_proto) const;

 private:
  // Constructor is private. Use Create method to instantiate.
  explicit FakeRecoveryMediatorCrypto(hwsec_foundation::EllipticCurve ec);

  // Receives `hsm_payload`, performs mediation and generates response payload.
  // This function consist of the following steps:
  // 1. Deserialize publisher_pub_key from `associated_data` in `hsm_payload`.
  // 2. Perform DH(`mediator_priv_key`, publisher_pub_key), decrypt
  // `cipher_text` from `hsm_payload` and get mediator_share and
  // dealer_pub_key
  // 3. Construct mediated_share = G * dealer_priv_key * mediator_share +
  // `ephemeral_pub_inv_key`.
  // 4. Serialize response payload associated_data and plain_text
  // 5. Generate encryption key as KDF(combine(epoch_pub_key,
  //                                     ECDH(epoch_priv_key, channel_pub_key)))
  // 6. Encrypt plain_text, generate `ResponsePayload` and serialize it to
  // `recovery_response_proto.cbor_cryptorecoveryresponse`.
  bool MediateHsmPayload(
      const brillo::SecureBlob& mediator_priv_key,
      const brillo::SecureBlob& epoch_pub_key,
      const brillo::SecureBlob& epoch_priv_key,
      const brillo::SecureBlob& ephemeral_pub_inv_key,
      const HsmPayload& hsm_payload,
      CryptoRecoveryRpcResponse* recovery_response_proto) const;

  // Decrypt `cipher_text` from `hsm_payload' using provided
  // `mediator_priv_key`.
  bool DecryptHsmPayloadPlainText(const brillo::SecureBlob& mediator_priv_key,
                                  const HsmPayload& hsm_payload,
                                  brillo::SecureBlob* plain_text) const;

  // Decrypt `cipher_text` from `request_payload' using provided
  // `epoch_priv_key` and store the result in `plain_text`.
  bool DecryptRequestPayloadPlainText(const brillo::SecureBlob& epoch_priv_key,
                                      const RequestPayload& request_payload,
                                      brillo::SecureBlob* plain_text) const;
  hwsec_foundation::EllipticCurve ec_;
};

}  // namespace cryptorecovery
}  // namespace cryptohome

#endif  // CRYPTOHOME_CRYPTORECOVERY_FAKE_RECOVERY_MEDIATOR_CRYPTO_H_
