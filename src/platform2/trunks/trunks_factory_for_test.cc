// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/trunks_factory_for_test.h"

#include <map>
#include <memory>
#include <optional>
#include <vector>

#include <gmock/gmock.h>

#include "trunks/authorization_delegate.h"
#include "trunks/blob_parser.h"
#include "trunks/cr50_headers/ap_ro_status.h"
#include "trunks/hmac_session.h"
#include "trunks/mock_blob_parser.h"
#include "trunks/mock_hmac_session.h"
#include "trunks/mock_policy_session.h"
#include "trunks/mock_session_manager.h"
#include "trunks/mock_tpm.h"
#include "trunks/mock_tpm_cache.h"
#include "trunks/mock_tpm_state.h"
#include "trunks/mock_tpm_utility.h"
#include "trunks/policy_session.h"
#include "trunks/session_manager.h"
#include "trunks/tpm_generated.h"
#include "trunks/tpm_state.h"
#include "trunks/tpm_utility.h"

using testing::NiceMock;

namespace trunks {

// Forwards all calls to a target instance.
class TpmStateForwarder : public TpmState {
 public:
  explicit TpmStateForwarder(TpmState* target) : target_(target) {}
  ~TpmStateForwarder() override = default;

  TPM_RC Initialize() override { return target_->Initialize(); }

  bool IsOwnerPasswordSet() override { return target_->IsOwnerPasswordSet(); }

  bool IsEndorsementPasswordSet() override {
    return target_->IsEndorsementPasswordSet();
  }

  bool IsLockoutPasswordSet() override {
    return target_->IsLockoutPasswordSet();
  }

  bool IsOwned() override { return target_->IsOwned(); }

  bool IsInLockout() override { return target_->IsInLockout(); }

  bool IsPlatformHierarchyEnabled() override {
    return target_->IsPlatformHierarchyEnabled();
  }

  bool IsStorageHierarchyEnabled() override {
    return target_->IsStorageHierarchyEnabled();
  }

  bool IsEndorsementHierarchyEnabled() override {
    return target_->IsEndorsementHierarchyEnabled();
  }

  bool IsEnabled() override { return target_->IsEnabled(); }

  bool WasShutdownOrderly() override { return target_->WasShutdownOrderly(); }

  bool IsRSASupported() override { return target_->IsRSASupported(); }

  bool IsECCSupported() override { return target_->IsECCSupported(); }

  uint32_t GetLockoutCounter() override { return target_->GetLockoutCounter(); }

  uint32_t GetLockoutThreshold() override {
    return target_->GetLockoutThreshold();
  }

  uint32_t GetLockoutInterval() override {
    return target_->GetLockoutInterval();
  }

  uint32_t GetLockoutRecovery() override {
    return target_->GetLockoutRecovery();
  }

  uint32_t GetTpmFamily() override { return target_->GetTpmFamily(); }

  uint32_t GetSpecificationLevel() override {
    return target_->GetSpecificationLevel();
  }

  uint32_t GetSpecificationRevision() override {
    return target_->GetSpecificationRevision();
  }

  uint32_t GetManufacturer() override { return target_->GetManufacturer(); }

  uint32_t GetTpmModel() override { return target_->GetTpmModel(); }

  uint64_t GetFirmwareVersion() override {
    return target_->GetFirmwareVersion();
  }

  std::string GetVendorIDString() override {
    return target_->GetVendorIDString();
  }

  uint32_t GetMaxNVSize() override { return target_->GetMaxNVSize(); }

  bool GetTpmProperty(TPM_PT property, uint32_t* value) override {
    return target_->GetTpmProperty(property, value);
  }

  bool GetAlgorithmProperties(TPM_ALG_ID algorithm,
                              TPMA_ALGORITHM* properties) override {
    return target_->GetAlgorithmProperties(algorithm, properties);
  }

 private:
  TpmState* target_;
};

// Forwards all calls to a target instance.
class TpmUtilityForwarder : public TpmUtility {
 public:
  explicit TpmUtilityForwarder(TpmUtility* target) : target_(target) {}
  ~TpmUtilityForwarder() override = default;

  TPM_RC Startup() override { return target_->Startup(); }

  TPM_RC CheckState() override { return target_->CheckState(); }

  TPM_RC Clear() override { return target_->Clear(); }

  void Shutdown() override { return target_->Shutdown(); }

  TPM_RC InitializeTpm() override { return target_->InitializeTpm(); }

  TPM_RC AllocatePCR(const std::string& platform_password) override {
    return target_->AllocatePCR(platform_password);
  }

  TPM_RC PrepareForPinWeaver() override {
    return target_->PrepareForPinWeaver();
  }

  TPM_RC PrepareForOwnership() override {
    return target_->PrepareForOwnership();
  }

  TPM_RC TakeOwnership(const std::string& owner_password,
                       const std::string& endorsement_password,
                       const std::string& lockout_password) override {
    return target_->TakeOwnership(owner_password, endorsement_password,
                                  lockout_password);
  }

  TPM_RC StirRandom(const std::string& entropy_data,
                    AuthorizationDelegate* delegate) override {
    return target_->StirRandom(entropy_data, delegate);
  }

  TPM_RC ChangeOwnerPassword(const std::string& old_password,
                             const std::string& new_password) override {
    return target_->ChangeOwnerPassword(old_password, new_password);
  }

  TPM_RC GenerateRandom(size_t num_bytes,
                        AuthorizationDelegate* delegate,
                        std::string* random_data) override {
    return target_->GenerateRandom(num_bytes, delegate, random_data);
  }

  TPM_RC GetAlertsData(TpmAlertsData* alerts) override {
    return target_->GetAlertsData(alerts);
  }

  TPM_RC ExtendPCR(int pcr_index,
                   const std::string& extend_data,
                   AuthorizationDelegate* delegate) override {
    return target_->ExtendPCR(pcr_index, extend_data, delegate);
  }

  TPM_RC ExtendPCRForCSME(int pcr_index,
                          const std::string& extend_data) override {
    return target_->ExtendPCRForCSME(pcr_index, extend_data);
  }

  TPM_RC ReadPCR(int pcr_index, std::string* pcr_value) override {
    return target_->ReadPCR(pcr_index, pcr_value);
  }

  TPM_RC ReadPCRFromCSME(int pcr_index, std::string* pcr_value) override {
    return target_->ReadPCRFromCSME(pcr_index, pcr_value);
  }

  TPM_RC AsymmetricEncrypt(TPM_HANDLE key_handle,
                           TPM_ALG_ID scheme,
                           TPM_ALG_ID hash_alg,
                           const std::string& plaintext,
                           AuthorizationDelegate* delegate,
                           std::string* ciphertext) override {
    return target_->AsymmetricEncrypt(key_handle, scheme, hash_alg, plaintext,
                                      delegate, ciphertext);
  }

  TPM_RC AsymmetricDecrypt(TPM_HANDLE key_handle,
                           TPM_ALG_ID scheme,
                           TPM_ALG_ID hash_alg,
                           const std::string& ciphertext,
                           AuthorizationDelegate* delegate,
                           std::string* plaintext) override {
    return target_->AsymmetricDecrypt(key_handle, scheme, hash_alg, ciphertext,
                                      delegate, plaintext);
  }

  TPM_RC ECDHZGen(TPM_HANDLE key_handle,
                  const TPM2B_ECC_POINT& in_point,
                  AuthorizationDelegate* delegate,
                  TPM2B_ECC_POINT* out_point) override {
    return target_->ECDHZGen(key_handle, in_point, delegate, out_point);
  }

  TPM_RC RawSign(TPM_HANDLE key_handle,
                 TPM_ALG_ID scheme,
                 TPM_ALG_ID hash_alg,
                 const std::string& plaintext,
                 bool generate_hash,
                 AuthorizationDelegate* delegate,
                 TPMT_SIGNATURE* auth) override {
    return target_->RawSign(key_handle, scheme, hash_alg, plaintext,
                            generate_hash, delegate, auth);
  }

  TPM_RC Sign(TPM_HANDLE key_handle,
              TPM_ALG_ID scheme,
              TPM_ALG_ID hash_alg,
              const std::string& plaintext,
              bool generate_hash,
              AuthorizationDelegate* delegate,
              std::string* signature) override {
    return target_->Sign(key_handle, scheme, hash_alg, plaintext, generate_hash,
                         delegate, signature);
  }

  TPM_RC CertifyCreation(TPM_HANDLE key_handle,
                         const std::string& creation_blob) override {
    return target_->CertifyCreation(key_handle, creation_blob);
  }

  TPM_RC ChangeKeyAuthorizationData(TPM_HANDLE key_handle,
                                    const std::string& new_password,
                                    AuthorizationDelegate* delegate,
                                    std::string* key_blob) override {
    return target_->ChangeKeyAuthorizationData(key_handle, new_password,
                                               delegate, key_blob);
  }

  TPM_RC ImportRSAKey(AsymmetricKeyUsage key_type,
                      const std::string& modulus,
                      uint32_t public_exponent,
                      const std::string& prime_factor,
                      const std::string& password,
                      AuthorizationDelegate* delegate,
                      std::string* key_blob) override {
    return target_->ImportRSAKey(key_type, modulus, public_exponent,
                                 prime_factor, password, delegate, key_blob);
  }

  TPM_RC ImportECCKey(AsymmetricKeyUsage key_type,
                      TPMI_ECC_CURVE curve_id,
                      const std::string& public_point_x,
                      const std::string& public_point_y,
                      const std::string& private_value,
                      const std::string& password,
                      AuthorizationDelegate* delegate,
                      std::string* key_blob) override {
    return target_->ImportECCKey(key_type, curve_id, public_point_x,
                                 public_point_y, private_value, password,
                                 delegate, key_blob);
  }

  TPM_RC ImportECCKeyWithPolicyDigest(AsymmetricKeyUsage key_type,
                                      TPMI_ECC_CURVE curve_id,
                                      const std::string& public_point_x,
                                      const std::string& public_point_y,
                                      const std::string& private_value,
                                      const std::string& policy_digest,
                                      AuthorizationDelegate* delegate,
                                      std::string* key_blob) override {
    return target_->ImportECCKeyWithPolicyDigest(
        key_type, curve_id, public_point_x, public_point_y, private_value,
        policy_digest, delegate, key_blob);
  }

  TPM_RC CreateRSAKeyPair(AsymmetricKeyUsage key_type,
                          int modulus_bits,
                          uint32_t public_exponent,
                          const std::string& password,
                          const std::string& policy_digest,
                          bool use_only_policy_authorization,
                          const std::vector<uint32_t>& creation_pcr_indexes,
                          AuthorizationDelegate* delegate,
                          std::string* key_blob,
                          std::string* creation_blob) override {
    return target_->CreateRSAKeyPair(
        key_type, modulus_bits, public_exponent, password, policy_digest,
        use_only_policy_authorization, creation_pcr_indexes, delegate, key_blob,
        creation_blob);
  }

  TPM_RC CreateECCKeyPair(AsymmetricKeyUsage key_type,
                          TPMI_ECC_CURVE curve_id,
                          const std::string& password,
                          const std::string& policy_digest,
                          bool use_only_policy_authorization,
                          const std::vector<uint32_t>& creation_pcr_indexes,
                          AuthorizationDelegate* delegate,
                          std::string* key_blob,
                          std::string* creation_blob) override {
    return target_->CreateECCKeyPair(
        key_type, curve_id, password, policy_digest,
        use_only_policy_authorization, creation_pcr_indexes, delegate, key_blob,
        creation_blob);
  }

  TPM_RC CreateRestrictedECCKeyPair(
      AsymmetricKeyUsage key_type,
      TPMI_ECC_CURVE curve_id,
      const std::string& password,
      const std::string& policy_digest,
      bool use_only_policy_authorization,
      const std::vector<uint32_t>& creation_pcr_indexes,
      AuthorizationDelegate* delegate,
      std::string* key_blob,
      std::string* creation_blob) override {
    return target_->CreateRestrictedECCKeyPair(
        key_type, curve_id, password, policy_digest,
        use_only_policy_authorization, creation_pcr_indexes, delegate, key_blob,
        creation_blob);
  }

  TPM_RC LoadKey(const std::string& key_blob,
                 AuthorizationDelegate* delegate,
                 TPM_HANDLE* key_handle) override {
    return target_->LoadKey(key_blob, delegate, key_handle);
  }

  TPM_RC LoadRSAPublicKey(AsymmetricKeyUsage key_type,
                          TPM_ALG_ID scheme,
                          TPM_ALG_ID hash_alg,
                          const std::string& modulus,
                          uint32_t public_exponent,
                          AuthorizationDelegate* delegate,
                          TPM_HANDLE* key_handle) override {
    return target_->LoadRSAPublicKey(key_type, scheme, hash_alg, modulus,
                                     public_exponent, delegate, key_handle);
  }

  TPM_RC LoadECPublicKey(AsymmetricKeyUsage key_type,
                         TPM_ECC_CURVE curve_id,
                         TPM_ALG_ID scheme,
                         TPM_ALG_ID hash_alg,
                         const std::string& x,
                         const std::string& y,
                         AuthorizationDelegate* delegate,
                         TPM_HANDLE* key_handle) override {
    return target_->LoadECPublicKey(key_type, curve_id, scheme, hash_alg, x, y,
                                    delegate, key_handle);
  }

  TPM_RC GetKeyName(TPM_HANDLE handle, std::string* name) override {
    return target_->GetKeyName(handle, name);
  }

  TPM_RC GetKeyPublicArea(TPM_HANDLE handle,
                          TPMT_PUBLIC* public_data) override {
    return target_->GetKeyPublicArea(handle, public_data);
  }

  TPM_RC SealData(const std::string& data_to_seal,
                  const std::string& policy_digest,
                  const std::string& auth_value,
                  bool require_admin_with_policy,
                  AuthorizationDelegate* delegate,
                  std::string* sealed_data) override {
    return target_->SealData(data_to_seal, policy_digest, auth_value,
                             require_admin_with_policy, delegate, sealed_data);
  }

  TPM_RC UnsealData(const std::string& sealed_data,
                    AuthorizationDelegate* delegate,
                    std::string* unsealed_data) override {
    return target_->UnsealData(sealed_data, delegate, unsealed_data);
  }

  TPM_RC UnsealDataWithHandle(TPM_HANDLE object_handle,
                              AuthorizationDelegate* delegate,
                              std::string* unsealed_data) override {
    return target_->UnsealDataWithHandle(object_handle, delegate,
                                         unsealed_data);
  }

  TPM_RC StartSession(HmacSession* session) override {
    return target_->StartSession(session);
  }

  TPM_RC AddPcrValuesToPolicySession(
      const std::map<uint32_t, std::string>& pcr_map,
      bool use_auth_value,
      PolicySession* policy_session) override {
    return target_->AddPcrValuesToPolicySession(pcr_map, use_auth_value,
                                                policy_session);
  }

  TPM_RC GetPolicyDigestForPcrValues(
      const std::map<uint32_t, std::string>& pcr_map,
      bool use_auth_value,
      std::string* policy_digest) override {
    return target_->GetPolicyDigestForPcrValues(pcr_map, use_auth_value,
                                                policy_digest);
  }

  TPM_RC DefineNVSpace(uint32_t index,
                       size_t num_bytes,
                       TPMA_NV attributes,
                       const std::string& authorization_value,
                       const std::string& policy_digest,
                       AuthorizationDelegate* delegate) override {
    return target_->DefineNVSpace(index, num_bytes, attributes,
                                  authorization_value, policy_digest, delegate);
  }

  TPM_RC DestroyNVSpace(uint32_t index,
                        AuthorizationDelegate* delegate) override {
    return target_->DestroyNVSpace(index, delegate);
  }

  TPM_RC LockNVSpace(uint32_t index,
                     bool lock_read,
                     bool lock_write,
                     bool using_owner_authorization,
                     AuthorizationDelegate* delegate) override {
    return target_->LockNVSpace(index, lock_read, lock_write,
                                using_owner_authorization, delegate);
  }

  TPM_RC WriteNVSpace(uint32_t index,
                      uint32_t offset,
                      const std::string& nvram_data,
                      bool using_owner_authorization,
                      bool extend,
                      AuthorizationDelegate* delegate) override {
    return target_->WriteNVSpace(index, offset, nvram_data,
                                 using_owner_authorization, extend, delegate);
  }

  TPM_RC IncrementNVCounter(uint32_t index,
                            bool using_owner_authorization,
                            AuthorizationDelegate* delegate) override {
    return target_->IncrementNVCounter(index, using_owner_authorization,
                                       delegate);
  }

  TPM_RC ReadNVSpace(uint32_t index,
                     uint32_t offset,
                     size_t num_bytes,
                     bool using_owner_authorization,
                     std::string* nvram_data,
                     AuthorizationDelegate* delegate) override {
    return target_->ReadNVSpace(index, offset, num_bytes,
                                using_owner_authorization, nvram_data,
                                delegate);
  }

  TPM_RC GetNVSpaceName(uint32_t index, std::string* name) override {
    return target_->GetNVSpaceName(index, name);
  }

  TPM_RC GetNVSpacePublicArea(uint32_t index,
                              TPMS_NV_PUBLIC* public_data) override {
    return target_->GetNVSpacePublicArea(index, public_data);
  }

  TPM_RC ListNVSpaces(std::vector<uint32_t>* index_list) override {
    return target_->ListNVSpaces(index_list);
  }

  TPM_RC SetDictionaryAttackParameters(
      uint32_t max_tries,
      uint32_t recovery_time,
      uint32_t lockout_recovery,
      AuthorizationDelegate* delegate) override {
    return target_->SetDictionaryAttackParameters(max_tries, recovery_time,
                                                  lockout_recovery, delegate);
  }

  TPM_RC ResetDictionaryAttackLock(AuthorizationDelegate* delegate) override {
    return target_->ResetDictionaryAttackLock(delegate);
  }

  TPM_RC GetAuthPolicyEndorsementKey(
      TPM_ALG_ID key_type,
      const std::string& auth_policy,
      AuthorizationDelegate* endorsement_delegate,
      TPM_HANDLE* key_handle,
      TPM2B_NAME* key_name) override {
    return target_->GetAuthPolicyEndorsementKey(
        key_type, auth_policy, endorsement_delegate, key_handle, key_name);
  }

  TPM_RC GetEndorsementKey(TPM_ALG_ID key_type,
                           AuthorizationDelegate* endorsement_delegate,
                           AuthorizationDelegate* owner_delegate,
                           TPM_HANDLE* key_handle) override {
    return target_->GetEndorsementKey(key_type, endorsement_delegate,
                                      owner_delegate, key_handle);
  }

  TPM_RC CreateIdentityKey(TPM_ALG_ID key_type,
                           AuthorizationDelegate* delegate,
                           std::string* key_blob) override {
    return target_->CreateIdentityKey(key_type, delegate, key_blob);
  }

  TPM_RC DeclareTpmFirmwareStable() override {
    return target_->DeclareTpmFirmwareStable();
  }

  TPM_RC GetPublicRSAEndorsementKeyModulus(std::string* ekm) override {
    return target_->GetPublicRSAEndorsementKeyModulus(ekm);
  }

  TPM_RC ManageCCDPwd(bool allow_pwd) override {
    return target_->ManageCCDPwd(allow_pwd);
  }

  TPM_RC PinWeaverIsSupported(uint8_t request_version,
                              uint8_t* protocol_version) override {
    return target_->PinWeaverIsSupported(request_version, protocol_version);
  }

  TPM_RC PinWeaverResetTree(uint8_t protocol_version,
                            uint8_t bits_per_level,
                            uint8_t height,
                            uint32_t* result_code,
                            std::string* root_hash) override {
    return target_->PinWeaverResetTree(protocol_version, bits_per_level, height,
                                       result_code, root_hash);
  }

  TPM_RC PinWeaverInsertLeaf(uint8_t protocol_version,
                             uint64_t label,
                             const std::string& h_aux,
                             const brillo::SecureBlob& le_secret,
                             const brillo::SecureBlob& he_secret,
                             const brillo::SecureBlob& reset_secret,
                             const std::map<uint32_t, uint32_t>& delay_schedule,
                             const ValidPcrCriteria& valid_pcr_criteria,
                             std::optional<uint32_t> expiration_delay,
                             uint32_t* result_code,
                             std::string* root_hash,
                             std::string* cred_metadata,
                             std::string* mac) override {
    return target_->PinWeaverInsertLeaf(
        protocol_version, label, h_aux, le_secret, he_secret, reset_secret,
        delay_schedule, valid_pcr_criteria, expiration_delay, result_code,
        root_hash, cred_metadata, mac);
  }

  TPM_RC PinWeaverRemoveLeaf(uint8_t protocol_version,
                             uint64_t label,
                             const std::string& h_aux,
                             const std::string& mac,
                             uint32_t* result_code,
                             std::string* root_hash) override {
    return target_->PinWeaverRemoveLeaf(protocol_version, label, h_aux, mac,
                                        result_code, root_hash);
  }

  TPM_RC PinWeaverTryAuth(uint8_t protocol_version,
                          const brillo::SecureBlob& le_secret,
                          const std::string& h_aux,
                          const std::string& cred_metadata,
                          uint32_t* result_code,
                          std::string* root_hash,
                          uint32_t* seconds_to_wait,
                          brillo::SecureBlob* he_secret,
                          brillo::SecureBlob* reset_secret,
                          std::string* cred_metadata_out,
                          std::string* mac_out) override {
    return target_->PinWeaverTryAuth(protocol_version, le_secret, h_aux,
                                     cred_metadata, result_code, root_hash,
                                     seconds_to_wait, he_secret, reset_secret,
                                     cred_metadata_out, mac_out);
  }

  TPM_RC PinWeaverResetAuth(uint8_t protocol_version,
                            const brillo::SecureBlob& reset_secret,
                            bool strong_reset,
                            const std::string& h_aux,
                            const std::string& cred_metadata,
                            uint32_t* result_code,
                            std::string* root_hash,
                            std::string* cred_metadata_out,
                            std::string* mac_out) override {
    return target_->PinWeaverResetAuth(
        protocol_version, reset_secret, strong_reset, h_aux, cred_metadata,
        result_code, root_hash, cred_metadata_out, mac_out);
  }

  TPM_RC PinWeaverGetLog(uint8_t protocol_version,
                         const std::string& root,
                         uint32_t* result_code,
                         std::string* root_hash,
                         std::vector<trunks::PinWeaverLogEntry>* log) override {
    return target_->PinWeaverGetLog(protocol_version, root, result_code,
                                    root_hash, log);
  }

  TPM_RC PinWeaverLogReplay(uint8_t protocol_version,
                            const std::string& log_root,
                            const std::string& h_aux,
                            const std::string& cred_metadata,
                            uint32_t* result_code,
                            std::string* root_hash,
                            std::string* cred_metadata_out,
                            std::string* mac_out) override {
    return target_->PinWeaverLogReplay(protocol_version, log_root, h_aux,
                                       cred_metadata, result_code, root_hash,
                                       cred_metadata_out, mac_out);
  }

  TPM_RC PinWeaverSysInfo(uint8_t protocol_version,
                          uint32_t* result_code,
                          std::string* root_hash,
                          uint32_t* boot_count,
                          uint64_t* seconds_since_boot) override {
    return target_->PinWeaverSysInfo(protocol_version, result_code, root_hash,
                                     boot_count, seconds_since_boot);
  }

  TPM_RC PinWeaverGenerateBiometricsAuthPk(
      uint8_t protocol_version,
      uint8_t auth_channel,
      const PinWeaverEccPoint& client_public_key,
      uint32_t* result_code,
      std::string* root_hash,
      PinWeaverEccPoint* server_public_key) override {
    return target_->PinWeaverGenerateBiometricsAuthPk(
        protocol_version, auth_channel, client_public_key, result_code,
        root_hash, server_public_key);
  }

  TPM_RC PinWeaverCreateBiometricsAuthRateLimiter(
      uint8_t protocol_version,
      uint8_t auth_channel,
      uint64_t label,
      const std::string& h_aux,
      const brillo::SecureBlob& reset_secret,
      const std::map<uint32_t, uint32_t>& delay_schedule,
      const ValidPcrCriteria& valid_pcr_criteria,
      std::optional<uint32_t> expiration_delay,
      uint32_t* result_code,
      std::string* root_hash,
      std::string* cred_metadata,
      std::string* mac) override {
    return target_->PinWeaverCreateBiometricsAuthRateLimiter(
        protocol_version, auth_channel, label, h_aux, reset_secret,
        delay_schedule, valid_pcr_criteria, expiration_delay, result_code,
        root_hash, cred_metadata, mac);
  }

  TPM_RC PinWeaverStartBiometricsAuth(
      uint8_t protocol_version,
      uint8_t auth_channel,
      const brillo::Blob& client_nonce,
      const std::string& h_aux,
      const std::string& cred_metadata,
      uint32_t* result_code,
      std::string* root_hash,
      brillo::Blob* server_nonce,
      brillo::Blob* encrypted_high_entropy_secret,
      brillo::Blob* iv,
      std::string* cred_metadata_out,
      std::string* mac_out) override {
    return target_->PinWeaverStartBiometricsAuth(
        protocol_version, auth_channel, client_nonce, h_aux, cred_metadata,
        result_code, root_hash, server_nonce, encrypted_high_entropy_secret, iv,
        cred_metadata_out, mac_out);
  }

  TPM_RC PinWeaverBlockGenerateBiometricsAuthPk(
      uint8_t protocol_version,
      uint32_t* result_code,
      std::string* root_hash) override {
    return target_->PinWeaverBlockGenerateBiometricsAuthPk(
        protocol_version, result_code, root_hash);
  }

  TPM_RC U2fGenerate(const uint8_t version,
                     const brillo::Blob& app_id,
                     const brillo::SecureBlob& user_secret,
                     const bool consume,
                     const bool up_required,
                     const std::optional<brillo::Blob>& auth_time_secret_hash,
                     brillo::Blob* public_key,
                     brillo::Blob* key_handle) override {
    return target_->U2fGenerate(version, app_id, user_secret, consume,
                                up_required, auth_time_secret_hash, public_key,
                                key_handle);
  }

  TPM_RC U2fSign(const uint8_t version,
                 const brillo::Blob& app_id,
                 const brillo::SecureBlob& user_secret,
                 const std::optional<brillo::SecureBlob>& auth_time_secret,
                 const std::optional<brillo::Blob>& hash_to_sign,
                 const bool check_only,
                 const bool consume,
                 const bool up_required,
                 const brillo::Blob& key_handle,
                 brillo::Blob* sig_r,
                 brillo::Blob* sig_s) override {
    return target_->U2fSign(version, app_id, user_secret, auth_time_secret,
                            hash_to_sign, check_only, consume, up_required,
                            key_handle, sig_r, sig_s);
  }

  TPM_RC U2fAttest(const brillo::SecureBlob& user_secret,
                   uint8_t format,
                   const brillo::Blob& data,
                   brillo::Blob* sig_r,
                   brillo::Blob* sig_s) override {
    return target_->U2fAttest(user_secret, format, data, sig_r, sig_s);
  }

  TPM_RC GetRsuDeviceId(std::string* device_id) override {
    return target_->GetRsuDeviceId(device_id);
  }

  TPM_RC GetRoVerificationStatus(ap_ro_status* status) override {
    return target_->GetRoVerificationStatus(status);
  }

  bool IsGsc() override { return target_->IsGsc(); }

  std::string SendCommandAndWait(const std::string& command) override {
    return target_->SendCommandAndWait(command);
  }

  TPM_RC CreateSaltingKey(TPM_HANDLE* key, TPM2B_NAME* key_name) override {
    return target_->CreateSaltingKey(key, key_name);
  }

  TPM_RC GetTi50Stats(uint32_t* fs_init_time,
                      uint32_t* fs_size,
                      uint32_t* aprov_time,
                      uint32_t* aprov_status) override {
    return target_->GetTi50Stats(fs_init_time, fs_size, aprov_time,
                                 aprov_status);
  }

 private:
  TpmUtility* target_;
};

// Forwards all calls to a target instance.
class AuthorizationDelegateForwarder : public AuthorizationDelegate {
 public:
  explicit AuthorizationDelegateForwarder(AuthorizationDelegate* target)
      : target_(target) {}
  ~AuthorizationDelegateForwarder() override = default;

  bool GetCommandAuthorization(const std::string& command_hash,
                               bool is_command_parameter_encryption_possible,
                               bool is_response_parameter_encryption_possible,
                               std::string* authorization) override {
    return target_->GetCommandAuthorization(
        command_hash, is_command_parameter_encryption_possible,
        is_response_parameter_encryption_possible, authorization);
  }

  bool CheckResponseAuthorization(const std::string& response_hash,
                                  const std::string& authorization) override {
    return target_->CheckResponseAuthorization(response_hash, authorization);
  }

  bool EncryptCommandParameter(std::string* parameter) override {
    return target_->EncryptCommandParameter(parameter);
  }

  bool DecryptResponseParameter(std::string* parameter) override {
    return target_->DecryptResponseParameter(parameter);
  }

  bool GetTpmNonce(std::string* nonce) override {
    return target_->GetTpmNonce(nonce);
  }

 private:
  AuthorizationDelegate* target_;
};

// Forwards all calls to a target instance.
class SessionManagerForwarder : public SessionManager {
 public:
  explicit SessionManagerForwarder(SessionManager* target) : target_(target) {}
  ~SessionManagerForwarder() override {}

  TPM_HANDLE GetSessionHandle() const override {
    return target_->GetSessionHandle();
  }

  void CloseSession() override { return target_->CloseSession(); }

  TPM_RC StartSession(TPM_SE session_type,
                      TPMI_DH_ENTITY bind_entity,
                      const std::string& bind_authorization_value,
                      bool salted,
                      bool enable_encryption,
                      HmacAuthorizationDelegate* delegate) override {
    return target_->StartSession(session_type, bind_entity,
                                 bind_authorization_value, salted,
                                 enable_encryption, delegate);
  }

 private:
  SessionManager* target_;
};

// Forwards all calls to a target instance.
class HmacSessionForwarder : public HmacSession {
 public:
  explicit HmacSessionForwarder(HmacSession* target) : target_(target) {}
  ~HmacSessionForwarder() override = default;

  AuthorizationDelegate* GetDelegate() override {
    return target_->GetDelegate();
  }

  TPM_RC StartBoundSession(TPMI_DH_ENTITY bind_entity,
                           const std::string& bind_authorization_value,
                           bool salted,
                           bool enable_encryption) override {
    return target_->StartBoundSession(bind_entity, bind_authorization_value,
                                      salted, enable_encryption);
  }

  TPM_RC StartUnboundSession(bool salted, bool enable_encryption) override {
    return target_->StartUnboundSession(salted, enable_encryption);
  }

  void SetEntityAuthorizationValue(const std::string& value) override {
    return target_->SetEntityAuthorizationValue(value);
  }

  void SetFutureAuthorizationValue(const std::string& value) override {
    return target_->SetFutureAuthorizationValue(value);
  }

 private:
  HmacSession* target_;
};

// Forwards all calls to a target instance.
class PolicySessionForwarder : public PolicySession {
 public:
  explicit PolicySessionForwarder(PolicySession* target) : target_(target) {}
  ~PolicySessionForwarder() override = default;

  AuthorizationDelegate* GetDelegate() override {
    return target_->GetDelegate();
  }

  TPM_RC StartBoundSession(TPMI_DH_ENTITY bind_entity,
                           const std::string& bind_authorization_value,
                           bool salted,
                           bool enable_encryption) override {
    return target_->StartBoundSession(bind_entity, bind_authorization_value,
                                      salted, enable_encryption);
  }

  TPM_RC StartUnboundSession(bool salted, bool enable_encryption) override {
    return target_->StartUnboundSession(salted, enable_encryption);
  }

  TPM_RC GetDigest(std::string* digest) override {
    return target_->GetDigest(digest);
  }

  TPM_RC PolicyOR(const std::vector<std::string>& digests) override {
    return target_->PolicyOR(digests);
  }

  TPM_RC PolicyPCR(const std::map<uint32_t, std::string>& pcr_map) override {
    return target_->PolicyPCR(pcr_map);
  }

  TPM_RC PolicyCommandCode(TPM_CC command_code) override {
    return target_->PolicyCommandCode(command_code);
  }

  TPM_RC PolicySecret(TPMI_DH_ENTITY auth_entity,
                      const std::string& auth_entity_name,
                      const std::string& nonce,
                      const std::string& cp_hash,
                      const std::string& policy_ref,
                      int32_t expiration,
                      AuthorizationDelegate* delegate) override {
    return target_->PolicySecret(auth_entity, auth_entity_name, nonce, cp_hash,
                                 policy_ref, expiration, delegate);
  }

  TPM_RC PolicySigned(TPMI_DH_ENTITY auth_entity,
                      const std::string& auth_entity_name,
                      const std::string& nonce,
                      const std::string& cp_hash,
                      const std::string& policy_ref,
                      int32_t expiration,
                      const trunks::TPMT_SIGNATURE& signature,
                      AuthorizationDelegate* delegate) override {
    return target_->PolicySigned(auth_entity, auth_entity_name, nonce, cp_hash,
                                 policy_ref, expiration, signature, delegate);
  }

  TPM_RC PolicyFidoSigned(TPMI_DH_ENTITY auth_entity,
                          const std::string& auth_entity_name,
                          const std::string& auth_data,
                          const std::vector<FIDO_DATA_RANGE>& auth_data_descr,
                          const TPMT_SIGNATURE& signature,
                          AuthorizationDelegate* delegate) override {
    return target_->PolicyFidoSigned(auth_entity, auth_entity_name, auth_data,
                                     auth_data_descr, signature, delegate);
  }

  TPM_RC PolicyNV(uint32_t index,
                  uint32_t offset,
                  bool using_owner_authorization,
                  TPM2B_OPERAND operand,
                  TPM_EO operation,
                  AuthorizationDelegate* delegate) override {
    return target_->PolicyNV(index, offset, using_owner_authorization, operand,
                             operation, delegate);
  }

  TPM_RC PolicyAuthValue() override { return target_->PolicyAuthValue(); }

  TPM_RC PolicyRestart() override { return target_->PolicyRestart(); }

  void SetEntityAuthorizationValue(const std::string& value) override {
    return target_->SetEntityAuthorizationValue(value);
  }

 private:
  PolicySession* target_;
};

// Forwards all calls to a target instance.
class BlobParserForwarder : public BlobParser {
 public:
  explicit BlobParserForwarder(BlobParser* target) : target_(target) {}
  ~BlobParserForwarder() override = default;

  bool SerializeKeyBlob(const TPM2B_PUBLIC& public_info,
                        const TPM2B_PRIVATE& private_info,
                        std::string* key_blob) override {
    return target_->SerializeKeyBlob(public_info, private_info, key_blob);
  }

  bool ParseKeyBlob(const std::string& key_blob,
                    TPM2B_PUBLIC* public_info,
                    TPM2B_PRIVATE* private_info) override {
    return target_->ParseKeyBlob(key_blob, public_info, private_info);
  }

  bool SerializeCreationBlob(const TPM2B_CREATION_DATA& creation_data,
                             const TPM2B_DIGEST& creation_hash,
                             const TPMT_TK_CREATION& creation_ticket,
                             std::string* creation_blob) override {
    return target_->SerializeCreationBlob(creation_data, creation_hash,
                                          creation_ticket, creation_blob);
  }

  bool ParseCreationBlob(const std::string& creation_blob,
                         TPM2B_CREATION_DATA* creation_data,
                         TPM2B_DIGEST* creation_hash,
                         TPMT_TK_CREATION* creation_ticket) override {
    return target_->ParseCreationBlob(creation_blob, creation_data,
                                      creation_hash, creation_ticket);
  }

 private:
  BlobParser* target_;
};

TrunksFactoryForTest::TrunksFactoryForTest()
    : default_tpm_(new NiceMock<MockTpm>()),
      tpm_(default_tpm_.get()),
      default_tpm_cache_(new NiceMock<MockTpmCache>()),
      tpm_cache_(default_tpm_cache_.get()),
      default_tpm_state_(new NiceMock<MockTpmState>()),
      tpm_state_(default_tpm_state_.get()),
      default_tpm_utility_(new NiceMock<MockTpmUtility>()),
      tpm_utility_(default_tpm_utility_.get()),
      used_password_(nullptr),
      default_authorization_delegate_(new PasswordAuthorizationDelegate("")),
      password_authorization_delegate_(default_authorization_delegate_.get()),
      default_session_manager_(new NiceMock<MockSessionManager>()),
      session_manager_(default_session_manager_.get()),
      default_hmac_session_(new NiceMock<MockHmacSession>()),
      hmac_session_(default_hmac_session_.get()),
      default_policy_session_(new NiceMock<MockPolicySession>()),
      policy_session_(default_policy_session_.get()),
      default_trial_session_(new NiceMock<MockPolicySession>()),
      trial_session_(default_trial_session_.get()),
      default_blob_parser_(new NiceMock<MockBlobParser>()),
      blob_parser_(default_blob_parser_.get()) {}

TrunksFactoryForTest::~TrunksFactoryForTest() {}

Tpm* TrunksFactoryForTest::GetTpm() const {
  return tpm_;
}

TpmCache* TrunksFactoryForTest::GetTpmCache() const {
  return tpm_cache_;
}

std::unique_ptr<TpmState> TrunksFactoryForTest::GetTpmState() const {
  return std::make_unique<TpmStateForwarder>(tpm_state_);
}

std::unique_ptr<TpmUtility> TrunksFactoryForTest::GetTpmUtility() const {
  return std::make_unique<TpmUtilityForwarder>(tpm_utility_);
}

std::unique_ptr<AuthorizationDelegate>
TrunksFactoryForTest::GetPasswordAuthorization(
    const std::string& password) const {
  // The `password` parameter is not used since we don't really check the
  // content of delegate in unit tests.
  if (used_password_)
    used_password_->push_back(password);
  return std::make_unique<AuthorizationDelegateForwarder>(
      password_authorization_delegate_);
}

std::unique_ptr<SessionManager> TrunksFactoryForTest::GetSessionManager()
    const {
  return std::make_unique<SessionManagerForwarder>(session_manager_);
}

std::unique_ptr<HmacSession> TrunksFactoryForTest::GetHmacSession() const {
  return std::make_unique<HmacSessionForwarder>(hmac_session_);
}

std::unique_ptr<PolicySession> TrunksFactoryForTest::GetPolicySession() const {
  return std::make_unique<PolicySessionForwarder>(policy_session_);
}

std::unique_ptr<PolicySession> TrunksFactoryForTest::GetTrialSession() const {
  return std::make_unique<PolicySessionForwarder>(trial_session_);
}

std::unique_ptr<BlobParser> TrunksFactoryForTest::GetBlobParser() const {
  return std::make_unique<BlobParserForwarder>(blob_parser_);
}

}  // namespace trunks
