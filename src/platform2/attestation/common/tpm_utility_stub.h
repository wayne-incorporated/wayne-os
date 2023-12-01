// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_COMMON_TPM_UTILITY_STUB_H_
#define ATTESTATION_COMMON_TPM_UTILITY_STUB_H_

#include <optional>
#include <string>
#include <vector>

#include "attestation/common/tpm_utility.h"

namespace attestation {

// A stub TpmUtility implementation.
class TpmUtilityStub : public TpmUtility {
 public:
  TpmUtilityStub() = default;
  TpmUtilityStub(const TpmUtilityStub&) = delete;
  TpmUtilityStub& operator=(const TpmUtilityStub&) = delete;

  ~TpmUtilityStub() override = default;

  // TpmUtility methods.
  bool Initialize() override { return true; }
  std::vector<KeyType> GetSupportedKeyTypes() override { return {}; }
  bool IsTpmReady() override { return false; }
  bool RemoveOwnerDependency() override { return false; }
  TpmVersion GetVersion() override { return TPM_1_2; }
  bool ActivateIdentity(const std::string& identity_key_blob,
                        const std::string& asym_ca_contents,
                        const std::string& sym_ca_attestation,
                        std::string* credential) override {
    return false;
  }
  bool ActivateIdentityForTpm2(KeyType key_type,
                               const std::string& identity_key_blob,
                               const std::string& encrypted_seed,
                               const std::string& credential_mac,
                               const std::string& wrapped_credential,
                               std::string* credential) override {
    return false;
  }
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
                          std::string* proof) override {
    return false;
  }
  bool GetEndorsementPublicKey(KeyType key_type,
                               std::string* public_key_der) override {
    return false;
  }
  bool GetEndorsementCertificate(KeyType key_type,
                                 std::string* certificate) override {
    return false;
  }
  bool Unbind(const std::string& key_blob,
              const std::string& bound_data,
              std::string* data) override {
    return false;
  }
  bool Sign(const std::string& key_blob,
            const std::string& data_to_sign,
            std::string* signature) override {
    return false;
  }
  bool GetNVDataSize(uint32_t nv_index, uint16_t* nv_size) const override {
    return false;
  }
  bool CertifyNV(uint32_t nv_index,
                 int nv_size,
                 const std::string& key_blob,
                 std::string* quoted_data,
                 std::string* quote) override {
    return false;
  }
  bool ReadPCR(uint32_t pcr_index, std::string* pcr_value) override {
    return false;
  }
  bool GetEndorsementPublicKeyModulus(KeyType key_type,
                                      std::string* ekm) override {
    return false;
  }
  bool GetEndorsementPublicKeyBytes(KeyType key_type,
                                    std::string* ek_bytes) override {
    return false;
  }

  bool CreateIdentity(KeyType key_type,
                      AttestationDatabase::Identity* identity) override {
    return false;
  }
};

}  // namespace attestation

#endif  // ATTESTATION_COMMON_TPM_UTILITY_STUB_H_
