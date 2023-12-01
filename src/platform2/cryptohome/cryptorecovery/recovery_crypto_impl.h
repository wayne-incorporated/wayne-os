// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_CRYPTORECOVERY_RECOVERY_CRYPTO_IMPL_H_
#define CRYPTOHOME_CRYPTORECOVERY_RECOVERY_CRYPTO_IMPL_H_

#include <memory>
#include <string>
#include <vector>

#include <brillo/secure_blob.h>
#include <cryptohome/platform.h>
#include <libhwsec/frontend/recovery_crypto/frontend.h>
#include <libhwsec-foundation/crypto/elliptic_curve.h>

#include "cryptohome/cryptorecovery/recovery_crypto.h"
#include "cryptohome/cryptorecovery/recovery_crypto_util.h"
#include "cryptohome/cryptorecovery/recovery_id_container.pb.h"
#include "cryptohome/proto_bindings/rpc.pb.h"

namespace cryptohome {
namespace cryptorecovery {
// Cryptographic operations for cryptohome recovery performed on either CPU
// (software emulation) or TPM modules depending on the TPM backend.
class RecoveryCryptoImpl : public RecoveryCrypto {
 public:
  // Creates instance. Returns nullptr if error occurred.
  static std::unique_ptr<RecoveryCryptoImpl> Create(
      const hwsec::RecoveryCryptoFrontend* hwsec_backend, Platform* platform);

  RecoveryCryptoImpl(const RecoveryCryptoImpl&) = delete;
  RecoveryCryptoImpl& operator=(const RecoveryCryptoImpl&) = delete;

  ~RecoveryCryptoImpl() override;

  bool GenerateRecoveryRequest(
      const GenerateRecoveryRequestRequest& request_param,
      CryptoRecoveryRpcRequest* recovery_request,
      brillo::SecureBlob* ephemeral_pub_key) const override;
  bool GenerateHsmPayload(const GenerateHsmPayloadRequest& request,
                          GenerateHsmPayloadResponse* response) const override;
  bool RecoverDestination(const RecoverDestinationRequest& request,
                          brillo::SecureBlob* destination_dh) const override;
  CryptoStatus DecryptResponsePayload(
      const DecryptResponsePayloadRequest& request,
      HsmResponsePlainText* response_plain_text) const override;

  void GenerateOnboardingMetadata(
      const std::string& gaia_id,
      const std::string& user_device_id,
      const std::string& recovery_id,
      OnboardingMetadata* onboarding_metadata) const;
  // Gets the current serialized value of the Recovery Id from cryptohome or
  // returns an empty string if it does not exist. It should be called by the
  // client before GenerateOnboardingMetadata in order to get the recovery_id
  // that will be passed as an argument.
  std::string LoadStoredRecoveryIdFromFile(
      const base::FilePath& recovery_id_path) const;
  std::string LoadStoredRecoveryId(const AccountIdentifier& account_id) const;
  // Creates a random seed and computes Recovery Id from it or (if the
  // Recovery Id already exists) re-hashes and persists it in the cryptohome.
  // This method should be called on the initial creation of OnboardingMetadata
  // and after every successful recovery operation to refresh the Recovery Id.
  // Secrets used to generate Recovery Id are stored in cryptohome but the
  // resulting Recovery Id is part of OnboardingMetadata stored outside of the
  // cryptohome.
  [[nodiscard]] bool GenerateRecoveryIdToFile(
      const base::FilePath& recovery_id_path) const;
  [[nodiscard]] bool GenerateRecoveryId(
      const AccountIdentifier& account_id) const;
  // Returns a vector of last |max_depth| Recovery ids. The current recovery_id
  // is returned as the first entry.
  std::vector<std::string> GetLastRecoveryIds(
      const AccountIdentifier& account_id, int max_depth) const;

 private:
  RecoveryCryptoImpl(hwsec_foundation::EllipticCurve ec,
                     const hwsec::RecoveryCryptoFrontend* hwsec_backend,
                     Platform* platform);
  [[nodiscard]] bool GenerateRecoveryKey(
      const crypto::ScopedEC_POINT& recovery_pub_point,
      const crypto::ScopedEC_KEY& dealer_key_pair,
      brillo::SecureBlob* recovery_key) const;
  // Generate ephemeral public and inverse public keys {G*x, G*-x}
  [[nodiscard]] bool GenerateEphemeralKey(
      brillo::SecureBlob* ephemeral_spki_der,
      brillo::SecureBlob* ephemeral_inv_spki_der) const;
  [[nodiscard]] bool GenerateHsmAssociatedData(
      const brillo::SecureBlob& channel_pub_key,
      const brillo::SecureBlob& rsa_pub_key,
      const crypto::ScopedEC_KEY& publisher_key_pair,
      const OnboardingMetadata& onboarding_metadata,
      brillo::SecureBlob* hsm_associated_data) const;
  [[nodiscard]] bool IsRecoveryIdAvailable(
      const base::FilePath& recovery_id_path) const;
  [[nodiscard]] bool RotateRecoveryId(
      CryptoRecoveryIdContainer* recovery_id_pb) const;
  void GenerateInitialRecoveryId(
      CryptoRecoveryIdContainer* recovery_id_pb) const;
  void GenerateRecoveryIdProto(CryptoRecoveryIdContainer* recovery_id_pb) const;
  [[nodiscard]] bool LoadPersistedRecoveryIdContainer(
      const base::FilePath& recovery_id_path,
      CryptoRecoveryIdContainer* recovery_id_pb) const;
  [[nodiscard]] bool PersistRecoveryIdContainer(
      const base::FilePath& recovery_id_path,
      const CryptoRecoveryIdContainer& recovery_id_pb) const;
  std::vector<std::string> GetLastRecoveryIdsFromFile(
      const base::FilePath& recovery_id_path, int max_depth) const;

  hwsec_foundation::EllipticCurve ec_;
  const hwsec::RecoveryCryptoFrontend* const hwsec_backend_;
  Platform* const platform_;
};

}  // namespace cryptorecovery
}  // namespace cryptohome

#endif  // CRYPTOHOME_CRYPTORECOVERY_RECOVERY_CRYPTO_IMPL_H_
