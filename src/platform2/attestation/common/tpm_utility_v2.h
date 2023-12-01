// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_COMMON_TPM_UTILITY_V2_H_
#define ATTESTATION_COMMON_TPM_UTILITY_V2_H_

#include <stdint.h>

#include "attestation/common/tpm_utility_common.h"

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/threading/thread.h>
#include <trunks/trunks_factory_impl.h>

namespace attestation {

// A TpmUtility implementation for TPM v2.0 modules.
class TpmUtilityV2 : public TpmUtilityCommon {
 public:
  TpmUtilityV2() = default;
  TpmUtilityV2(tpm_manager::TpmManagerUtility* tpm_manager_utility,
               trunks::TrunksFactory* trunks_factory);
  TpmUtilityV2(const TpmUtilityV2&) = delete;
  TpmUtilityV2& operator=(const TpmUtilityV2&) = delete;

  ~TpmUtilityV2() override;

  // TpmUtility methods.
  bool Initialize() override;
  std::vector<KeyType> GetSupportedKeyTypes() override;
  TpmVersion GetVersion() override { return TPM_2_0; }
  bool ActivateIdentity(const std::string& identity_key_blob,
                        const std::string& asym_ca_contents,
                        const std::string& sym_ca_attestation,
                        std::string* credential) override;
  bool ActivateIdentityForTpm2(KeyType key_type,
                               const std::string& identity_key_blob,
                               const std::string& encrypted_seed,
                               const std::string& credential_mac,
                               const std::string& wrapped_credential,
                               std::string* credential) override;
  bool CreateCertifiedKey(KeyType key_type,
                          KeyUsage key_usage,
                          KeyRestriction key_restriction,
                          std::optional<CertificateProfile> profile_hint,
                          const std::string& identity_key_blob,
                          const std::string& external_data,
                          std::string* key_blob,
                          std::string* public_key_der,
                          std::string* public_key_tpm_format,
                          std::string* key_info,
                          std::string* proof) override;
  bool GetEndorsementPublicKey(KeyType key_type,
                               std::string* public_key_der) override;
  bool GetEndorsementCertificate(KeyType key_type,
                                 std::string* certificate) override;
  bool Unbind(const std::string& key_blob,
              const std::string& bound_data,
              std::string* data) override;
  bool Sign(const std::string& key_blob,
            const std::string& data_to_sign,
            std::string* signature) override;
  bool ReadPCR(uint32_t pcr_index, std::string* pcr_value) override;
  bool GetNVDataSize(uint32_t nv_index, uint16_t* nv_size) const override;
  bool CertifyNV(uint32_t nv_index,
                 int nv_size,
                 const std::string& key_blob,
                 std::string* quoted_data,
                 std::string* quote) override;
  bool GetEndorsementPublicKeyModulus(KeyType key_type,
                                      std::string* ekm) override;
  bool GetEndorsementPublicKeyBytes(KeyType key_type,
                                    std::string* ek_bytes) override;

  bool CreateIdentity(KeyType key_type,
                      AttestationDatabase::Identity* identity) override;

  // Creates a restricted key of |key_type| for |key_usage|.
  // |public_key_der| is DER encoded which is converted from TPM public key
  // object. |public_key_tpm_format| is a serialized TPMT_PUBLIC.
  // |private_key_blob| is an opaque blob which only the TPM is able to unwrap.
  // Note: Currently the function is still in the public field because of the
  // legacy unittest code.
  // TODO(cylai): redesign the interface of this class or move out to a common
  // TPM2.0 utility.
  bool CreateRestrictedKey(KeyType key_type,
                           KeyUsage key_usage,
                           std::string* public_key_der,
                           std::string* public_key_tpm_format,
                           std::string* private_key_blob);

 private:
  // Gets the specified endorsement key. Returns true on success and provides
  // the |key_handle|.
  bool GetEndorsementKey(KeyType key_type, trunks::TPM_HANDLE* key_handle);

  // Creates an endorsement auth HMAC session.
  std::unique_ptr<trunks::HmacSession> CreateEndorsementAuthorizationSession();

  // Creates a policy session that is extended by PolicySecret with
  // `endorsement_session`.
  std::unique_ptr<trunks::PolicySession> CreateEndorsementPolicySecretSession(
      const std::unique_ptr<trunks::HmacSession>& endorsement_session);

  // Gets the ECC EK's public key formatted as concatenation of X and Y
  // component, and stores in `xy`.
  bool GetECCEndorsementPublicKey(std::string* xy);

  std::map<KeyType, trunks::TPM_HANDLE> endorsement_keys_;

  trunks::TrunksFactory* trunks_factory_{nullptr};
  std::unique_ptr<trunks::TrunksFactoryImpl> default_trunks_factory_;
  std::unique_ptr<trunks::TpmUtility> trunks_utility_;
};

}  // namespace attestation

#endif  // ATTESTATION_COMMON_TPM_UTILITY_V2_H_
