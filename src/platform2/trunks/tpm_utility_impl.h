// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_TPM_UTILITY_IMPL_H_
#define TRUNKS_TPM_UTILITY_IMPL_H_

#include "trunks/tpm_utility.h"

#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <brillo/secure_blob.h>
#include <gtest/gtest_prod.h>

#include "trunks/cr50_headers/ap_ro_status.h"
#include "trunks/scoped_key_handle.h"
#include "trunks/trunks_export.h"

namespace trunks {

const char kWellKnownPassword[] = "cros-password";

class AuthorizationDelegate;
class TrunksFactory;

// A default implementation of TpmUtility.
class TRUNKS_EXPORT TpmUtilityImpl : public TpmUtility {
 public:
  explicit TpmUtilityImpl(const TrunksFactory& factory);
  TpmUtilityImpl(const TpmUtilityImpl&) = delete;
  TpmUtilityImpl& operator=(const TpmUtilityImpl&) = delete;

  ~TpmUtilityImpl() override;

  // Helper function for U2f vendor specific commands.
  template <typename S, typename P>
  TPM_RC U2fCommand(const std::string& tag,
                    uint16_t subcommand,
                    S serialize,
                    P parse);

  // TpmUtility methods.
  TPM_RC Startup() override;
  TPM_RC Clear() override;
  void Shutdown() override;
  TPM_RC CheckState() override;
  TPM_RC InitializeTpm() override;
  TPM_RC AllocatePCR(const std::string& platform_password) override;
  TPM_RC PrepareForPinWeaver() override;
  TPM_RC PrepareForOwnership() override;
  TPM_RC TakeOwnership(const std::string& owner_password,
                       const std::string& endorsement_password,
                       const std::string& lockout_password) override;
  TPM_RC ChangeOwnerPassword(const std::string& old_password,
                             const std::string& new_password) override;
  TPM_RC StirRandom(const std::string& entropy_data,
                    AuthorizationDelegate* delegate) override;
  TPM_RC GenerateRandom(size_t num_bytes,
                        AuthorizationDelegate* delegate,
                        std::string* random_data) override;
  TPM_RC ExtendPCR(int pcr_index,
                   const std::string& extend_data,
                   AuthorizationDelegate* delegate) override;
  TPM_RC ExtendPCRForCSME(int pcr_index,
                          const std::string& extend_data) override;
  TPM_RC ReadPCR(int pcr_index, std::string* pcr_value) override;
  TPM_RC ReadPCRFromCSME(int pcr_index, std::string* pcr_value) override;
  TPM_RC AsymmetricEncrypt(TPM_HANDLE key_handle,
                           TPM_ALG_ID scheme,
                           TPM_ALG_ID hash_alg,
                           const std::string& plaintext,
                           AuthorizationDelegate* delegate,
                           std::string* ciphertext) override;
  TPM_RC AsymmetricDecrypt(TPM_HANDLE key_handle,
                           TPM_ALG_ID scheme,
                           TPM_ALG_ID hash_alg,
                           const std::string& ciphertext,
                           AuthorizationDelegate* delegate,
                           std::string* plaintext) override;
  TPM_RC ECDHZGen(TPM_HANDLE key_handle,
                  const TPM2B_ECC_POINT& in_point,
                  AuthorizationDelegate* delegate,
                  TPM2B_ECC_POINT* out_point) override;
  TPM_RC RawSign(TPM_HANDLE key_handle,
                 TPM_ALG_ID scheme,
                 TPM_ALG_ID hash_alg,
                 const std::string& plaintext,
                 bool generate_hash,
                 AuthorizationDelegate* delegate,
                 TPMT_SIGNATURE* auth) override;
  TPM_RC Sign(TPM_HANDLE key_handle,
              TPM_ALG_ID scheme,
              TPM_ALG_ID hash_alg,
              const std::string& plaintext,
              bool generate_hash,
              AuthorizationDelegate* delegate,
              std::string* signature) override;
  TPM_RC CertifyCreation(TPM_HANDLE key_handle,
                         const std::string& creation_blob) override;
  TPM_RC ChangeKeyAuthorizationData(TPM_HANDLE key_handle,
                                    const std::string& new_password,
                                    AuthorizationDelegate* delegate,
                                    std::string* key_blob) override;
  TPM_RC ImportRSAKey(AsymmetricKeyUsage key_type,
                      const std::string& modulus,
                      uint32_t public_exponent,
                      const std::string& prime_factor,
                      const std::string& password,
                      AuthorizationDelegate* delegate,
                      std::string* key_blob) override;
  TPM_RC ImportECCKey(AsymmetricKeyUsage key_type,
                      TPMI_ECC_CURVE curve_id,
                      const std::string& public_point_x,
                      const std::string& public_point_y,
                      const std::string& private_value,
                      const std::string& password,
                      AuthorizationDelegate* delegate,
                      std::string* key_blob) override;
  TPM_RC ImportECCKeyWithPolicyDigest(AsymmetricKeyUsage key_type,
                                      TPMI_ECC_CURVE curve_id,
                                      const std::string& public_point_x,
                                      const std::string& public_point_y,
                                      const std::string& private_value,
                                      const std::string& policy_digest,
                                      AuthorizationDelegate* delegate,
                                      std::string* key_blob) override;
  TPM_RC CreateRSAKeyPair(AsymmetricKeyUsage key_type,
                          int modulus_bits,
                          uint32_t public_exponent,
                          const std::string& password,
                          const std::string& policy_digest,
                          bool use_only_policy_authorization,
                          const std::vector<uint32_t>& creation_pcr_indexes,
                          AuthorizationDelegate* delegate,
                          std::string* key_blob,
                          std::string* creation_blob) override;
  TPM_RC CreateECCKeyPair(AsymmetricKeyUsage key_type,
                          TPMI_ECC_CURVE curve_id,
                          const std::string& password,
                          const std::string& policy_digest,
                          bool use_only_policy_authorization,
                          const std::vector<uint32_t>& creation_pcr_indexes,
                          AuthorizationDelegate* delegate,
                          std::string* key_blob,
                          std::string* creation_blob) override;
  TPM_RC CreateRestrictedECCKeyPair(
      AsymmetricKeyUsage key_type,
      TPMI_ECC_CURVE curve_id,
      const std::string& password,
      const std::string& policy_digest,
      bool use_only_policy_authorization,
      const std::vector<uint32_t>& creation_pcr_indexes,
      AuthorizationDelegate* delegate,
      std::string* key_blob,
      std::string* creation_blob) override;
  TPM_RC LoadKey(const std::string& key_blob,
                 AuthorizationDelegate* delegate,
                 TPM_HANDLE* key_handle) override;
  TPM_RC LoadRSAPublicKey(AsymmetricKeyUsage key_type,
                          TPM_ALG_ID scheme,
                          TPM_ALG_ID hash_alg,
                          const std::string& modulus,
                          uint32_t public_exponent,
                          AuthorizationDelegate* delegate,
                          TPM_HANDLE* key_handle) override;
  TPM_RC LoadECPublicKey(AsymmetricKeyUsage key_type,
                         TPM_ECC_CURVE curve_id,
                         TPM_ALG_ID scheme,
                         TPM_ALG_ID hash_alg,
                         const std::string& x,
                         const std::string& y,
                         AuthorizationDelegate* delegate,
                         TPM_HANDLE* key_handle) override;
  TPM_RC GetKeyName(TPM_HANDLE handle, std::string* name) override;
  TPM_RC GetKeyPublicArea(TPM_HANDLE handle, TPMT_PUBLIC* public_data) override;
  TPM_RC SealData(const std::string& data_to_seal,
                  const std::string& policy_digest,
                  const std::string& auth_value,
                  bool require_admin_with_policy,
                  AuthorizationDelegate* delegate,
                  std::string* sealed_data) override;
  TPM_RC UnsealData(const std::string& sealed_data,
                    AuthorizationDelegate* delegate,
                    std::string* unsealed_data) override;
  TPM_RC UnsealDataWithHandle(TPM_HANDLE object_handle,
                              AuthorizationDelegate* delegate,
                              std::string* unsealed_data) override;
  TPM_RC StartSession(HmacSession* session) override;
  TPM_RC AddPcrValuesToPolicySession(
      const std::map<uint32_t, std::string>& pcr_map,
      bool use_auth_value,
      PolicySession* policy_session) override;
  TPM_RC GetPolicyDigestForPcrValues(
      const std::map<uint32_t, std::string>& pcr_map,
      bool use_auth_value,
      std::string* policy_digest) override;
  TPM_RC DefineNVSpace(uint32_t index,
                       size_t num_bytes,
                       TPMA_NV attributes,
                       const std::string& authorization_value,
                       const std::string& policy_digest,
                       AuthorizationDelegate* delegate) override;
  TPM_RC DestroyNVSpace(uint32_t index,
                        AuthorizationDelegate* delegate) override;
  TPM_RC LockNVSpace(uint32_t index,
                     bool lock_read,
                     bool lock_write,
                     bool using_owner_authorization,
                     AuthorizationDelegate* delegate) override;
  TPM_RC WriteNVSpace(uint32_t index,
                      uint32_t offset,
                      const std::string& nvram_data,
                      bool using_owner_authorization,
                      bool extend,
                      AuthorizationDelegate* delegate) override;
  TPM_RC IncrementNVCounter(uint32_t index,
                            bool using_owner_authorization,
                            AuthorizationDelegate* delegate) override;
  TPM_RC ReadNVSpace(uint32_t index,
                     uint32_t offset,
                     size_t num_bytes,
                     bool using_owner_authorization,
                     std::string* nvram_data,
                     AuthorizationDelegate* delegate) override;
  TPM_RC GetNVSpaceName(uint32_t index, std::string* name) override;
  TPM_RC GetNVSpacePublicArea(uint32_t index,
                              TPMS_NV_PUBLIC* public_data) override;
  TPM_RC ListNVSpaces(std::vector<uint32_t>* index_list) override;
  TPM_RC SetDictionaryAttackParameters(
      uint32_t max_tries,
      uint32_t recovery_time,
      uint32_t lockout_recovery,
      AuthorizationDelegate* delegate) override;
  TPM_RC ResetDictionaryAttackLock(AuthorizationDelegate* delegate) override;
  TPM_RC GetAuthPolicyEndorsementKey(
      TPM_ALG_ID key_type,
      const std::string& auth_policy,
      AuthorizationDelegate* endorsement_delegate,
      TPM_HANDLE* key_handle,
      TPM2B_NAME* key_name) override;
  TPM_RC GetEndorsementKey(TPM_ALG_ID key_type,
                           AuthorizationDelegate* endorsement_delegate,
                           AuthorizationDelegate* owner_delegate,
                           TPM_HANDLE* key_handle) override;
  TPM_RC CreateIdentityKey(TPM_ALG_ID key_type,
                           AuthorizationDelegate* delegate,
                           std::string* key_blob) override;
  TPM_RC DeclareTpmFirmwareStable() override;
  TPM_RC GetPublicRSAEndorsementKeyModulus(std::string* ekm) override;
  TPM_RC ManageCCDPwd(bool allow_pwd) override;
  TPM_RC GetAlertsData(TpmAlertsData* alerts) override;
  TPM_RC PinWeaverIsSupported(uint8_t request_version,
                              uint8_t* protocol_version) override;
  TPM_RC PinWeaverResetTree(uint8_t protocol_version,
                            uint8_t bits_per_level,
                            uint8_t height,
                            uint32_t* result_code,
                            std::string* root_hash) override;
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
                             std::string* mac) override;
  TPM_RC PinWeaverRemoveLeaf(uint8_t protocol_version,
                             uint64_t label,
                             const std::string& h_aux,
                             const std::string& mac,
                             uint32_t* result_code,
                             std::string* root_hash) override;
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
                          std::string* mac_out) override;
  TPM_RC PinWeaverResetAuth(uint8_t protocol_version,
                            const brillo::SecureBlob& reset_secret,
                            bool strong_reset,
                            const std::string& h_aux,
                            const std::string& cred_metadata,
                            uint32_t* result_code,
                            std::string* root_hash,
                            std::string* cred_metadata_out,
                            std::string* mac_out) override;
  TPM_RC PinWeaverGetLog(uint8_t protocol_version,
                         const std::string& root,
                         uint32_t* result_code,
                         std::string* root_hash,
                         std::vector<trunks::PinWeaverLogEntry>* log) override;
  TPM_RC PinWeaverLogReplay(uint8_t protocol_version,
                            const std::string& log_root,
                            const std::string& h_aux,
                            const std::string& cred_metadata,
                            uint32_t* result_code,
                            std::string* root_hash,
                            std::string* cred_metadata_out,
                            std::string* mac_out) override;
  TPM_RC PinWeaverSysInfo(uint8_t protocol_version,
                          uint32_t* result_code,
                          std::string* root_hash,
                          uint32_t* boot_count,
                          uint64_t* seconds_since_boot) override;
  TPM_RC PinWeaverGenerateBiometricsAuthPk(
      uint8_t protocol_version,
      uint8_t auth_channel,
      const PinWeaverEccPoint& client_public_key,
      uint32_t* result_code,
      std::string* root_hash,
      PinWeaverEccPoint* server_public_key) override;
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
      std::string* mac) override;
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
      std::string* mac_out) override;
  TPM_RC PinWeaverBlockGenerateBiometricsAuthPk(
      uint8_t protocol_version,
      uint32_t* result_code,
      std::string* root_hash) override;
  TPM_RC U2fGenerate(uint8_t version,
                     const brillo::Blob& app_id,
                     const brillo::SecureBlob& user_secret,
                     bool consume,
                     bool up_required,
                     const std::optional<brillo::Blob>& auth_time_secret_hash,
                     brillo::Blob* public_key,
                     brillo::Blob* key_handle) override;
  TPM_RC U2fSign(uint8_t version,
                 const brillo::Blob& app_id,
                 const brillo::SecureBlob& user_secret,
                 const std::optional<brillo::SecureBlob>& auth_time_secret,
                 const std::optional<brillo::Blob>& hash_to_sign,
                 bool check_only,
                 bool consume,
                 bool up_required,
                 const brillo::Blob& key_handle,
                 brillo::Blob* sig_r,
                 brillo::Blob* sig_s) override;
  TPM_RC U2fAttest(const brillo::SecureBlob& user_secret,
                   uint8_t format,
                   const brillo::Blob& data,
                   brillo::Blob* sig_r,
                   brillo::Blob* sig_s) override;
  TPM_RC GetRsuDeviceId(std::string* device_id) override;
  TPM_RC GetRoVerificationStatus(ap_ro_status* status) override;

  bool IsGsc() override;

  std::string SendCommandAndWait(const std::string& command) override;

  TPM_RC CreateSaltingKey(TPM_HANDLE* key, TPM2B_NAME* key_name) override;

  TPM_RC GetTi50Stats(uint32_t* fs_init_time,
                      uint32_t* fs_size,
                      uint32_t* aprov_time,
                      uint32_t* aprov_status) override;

 private:
  friend class TpmUtilityTest;
  friend class NVTpmUtilityTest;

  const TrunksFactory& factory_;
  std::map<uint32_t, TPMS_NV_PUBLIC> nvram_public_area_map_;
  std::optional<uint32_t> vendor_id_;
  std::string cached_rsu_device_id_;
  size_t max_nv_chunk_size_ = 0;

  enum class PinWeaverBackendType {
    kUnknown,
    kNotSupported,
    kGsc,
    kCsme,
  };
  PinWeaverBackendType pinweaver_backend_type_ = PinWeaverBackendType::kUnknown;

  // Creates the CSME salting key and calls `InitOwner()` API of CSME to
  // initialize the necessary TPM resources for pinweaver-csme. Returns
  // `TPM_RC_SUCCESS` if the operations succeed; otherwise, return
  // `TPM_RC_FAILURE`. If the pinweaver is supported natively by GCS (e.g.,
  // cr50, ti50), performs no-ops and return `TPM_RC_SUCCESS`.
  TPM_RC InitializeOwnerForCsme();

  // This methods sets the well-known owner authorization and creates SRK and
  // the salting key with it. Only succeeds if owner authorization was not set
  // yet. These are the common operations done (1) by pre-initialization when
  // the owner authorization is not set yet, and (2) when taking ownership,
  // which repeats them in case (pre-)initialization was interrupted earlier.
  TPM_RC CreateStorageAndSaltingKeys();

  // This method sets a known owner password in the TPM_RH_OWNER hierarchy.
  TPM_RC SetKnownOwnerPassword(const std::string& known_owner_password);

  // Synchronously derives storage root keys for RSA and ECC and persists the
  // keys in the TPM. This operation must be authorized by the |owner_password|
  // and, on success, KRSAStorageRootKey and kECCStorageRootKey can be used
  // with an empty authorization value until the TPM is cleared.
  TPM_RC CreateStorageRootKeys(const std::string& owner_password);

  // This method creates an RSA/ECC decryption key to be used for salting
  // sessions. This method also makes the salting key permanent under the
  // storage hierarchy.
  TPM_RC CreatePersistentSaltingKey(const std::string& owner_password);

  // Creates and persists the salting key for CSME. If the key is already
  // persisted, performs no-ops.
  TPM_RC CreateCsmeSaltingKey();

  // This method returns a partially filled TPMT_PUBLIC structure,
  // which can then be modified by other methods to create the public
  // template for a key. It takes a valid |key_type| tp construct the
  // parameters.
  TPMT_PUBLIC CreateDefaultPublicArea(TPM_ALG_ID key_alg);

  // Shared inner logic regardless of the key algorithm.
  // |key_type| is type of key usage. Eg. signing key, decrption key, etc
  // |public_area| contains algorithm-specific public-area metadata.
  // It will be copy and filled the rest information according the other
  // parameters. Then, it will be used by the TPM_Create command.
  // |password| is the authorization value to use to authorize the generating
  // key.
  // |policy_digest| specifies an optional policy to use to authorize the
  // generating key.
  // |use_only_policy_authorization| specifies if we can use
  // HmacSession in addition to PolicySession to authorize use of this key.
  // |creation_pcr_indexes| allows the caller to specify a list of pcr indexes
  // in the creation data.
  // |delegate| is an AuthorizationDelegate used to authorize the SRK which is
  // the parent of created key.
  // |key_blob| contains the key blob of created key that can be loaded into the
  // TPM.
  // If the |creation_blob| out param is defined, it will contain the serialized
  // creation structures generated by the TPM. This can be used to verify the
  // state of the TPM during key creation.
  // NOTE: if |use_only_policy_authorization| is set to true,
  // parameter_encryption must be disabled when the key is used.
  TPM_RC CreateKeyPairInner(AsymmetricKeyUsage key_type,
                            TPMT_PUBLIC public_area,
                            const std::string& password,
                            const std::string& policy_digest,
                            bool use_only_policy_authorization,
                            const std::vector<uint32_t>& creation_pcr_indexes,
                            AuthorizationDelegate* delegate,
                            std::string* key_blob,
                            std::string* creation_blob);

  // Shared inner logic of key importing regardless of key algorithm.
  // |key_type| is type of key usage. Eg. signing key, decrption key, etc
  // |public_area| contains algorithm-specific public-area metadata.
  // |in_sensitive| contains algorithm-specific private-area metadata.
  // |password| is the authorization value for the imported key.
  // |delegate| is an AuthorizationDelegate used to authorize the SRK which is
  // the parent of created key.
  // If the out argument |key_blob| is not null, it is populated with
  // the imported key, which can then be loaded into the TPM.
  TPM_RC ImportKeyInner(AsymmetricKeyUsage key_type,
                        TPMT_PUBLIC public_area,
                        TPMT_SENSITIVE in_sensitive,
                        const std::string& password,
                        AuthorizationDelegate* delegate,
                        std::string* key_blob);

  // Sets TPM |hierarchy| authorization to |password| using |authorization|.
  TPM_RC SetHierarchyAuthorization(TPMI_RH_HIERARCHY_AUTH hierarchy,
                                   const std::string& password,
                                   AuthorizationDelegate* authorization);

  // Disables the TPM platform hierarchy until the next startup. This requires
  // platform |authorization|.
  TPM_RC DisablePlatformHierarchy(AuthorizationDelegate* authorization);

  // Given a public area, this method computes the object name. Following
  // TPM2.0 Specification Part 1 section 16,
  // object_name = HashAlg || Hash(public_area);
  TPM_RC ComputeKeyName(const TPMT_PUBLIC& public_area,
                        std::string* object_name);

  // Given a public area, this method computers the NVSpace's name.
  // It follows TPM2.0 Specification Part 1 section 16,
  // nv_name = HashAlg || Hash(nv_public_area);
  TPM_RC ComputeNVSpaceName(const TPMS_NV_PUBLIC& nv_public_area,
                            std::string* nv_name);

  // This encrypts the |sensitive_data| struct according to the specification
  // defined in TPM2.0 spec Part 1: Figure 19.
  TPM_RC EncryptPrivateData(const TPMT_SENSITIVE& sensitive_area,
                            const TPMT_PUBLIC& public_area,
                            TPM2B_PRIVATE* encrypted_private_data,
                            TPM2B_DATA* encryption_key);

  // Looks for a given persistent |key_handle| and outputs whether or not it
  // |exists|. Returns TPM_RC_SUCCESS on success.
  TPM_RC DoesPersistentKeyExist(TPMI_DH_PERSISTENT key_handle, bool* exists);

  // Connects to the TPM driver and runs a few basic operations/checks.
  // Returns an error in case it failed to conect to the tpm, genereates log
  // warnings for other conditions.
  //
  // Also returns tpm_state to the caller for further use.
  TPM_RC TpmBasicInit(std::unique_ptr<TpmState>* tpm_state);

  // Return true if the TPM supports padding-only scheme for Sign.
  bool SupportsPaddingOnlySigningScheme() { return IsGsc() || IsSimulator(); }

  // Queries Vendor ID as reported in TPM_PT_MANUFACTURER property and caches it
  // in `vendor_id_`.
  void CacheVendorId();

  // Returns true for TPMs running on simulator.
  bool IsSimulator();

  // Sends vendor command in GSC format, built from subcommand and already
  // serialized |command_payload|.
  // Returns the result of the command. Fills the |response_payload|,
  // if successful.
  TPM_RC GscVendorCommand(uint16_t subcommand,
                          const std::string& command_payload,
                          std::string* response_payload);

  // Helper function for serializing GSC vendor command called from
  // GscVendorCommand(). Builds the ready-to-send |serialized_command|
  // including the standard header, the |subcommand| code, and the
  // subcommand-specific |command_payload|.
  // Returns the result of serializing the command.
  TPM_RC SerializeCommand_GscVendor(uint16_t subcommand,
                                    const std::string& command_payload,
                                    std::string* serialized_command);

  // Helper function for parsing the response to GSC vendor command,
  // called from GscVendorCommand(). Takes the |response| received from
  // the TPM, parses and ensures the correctness of the header, and
  // extracts the subcommand-specific |response_payload| (kept serialized
  // as received from the TPM).
  // If deserialization failed, returns an error. If the header is correctly
  // parsed, returns the error code received from the TPM.
  TPM_RC ParseResponse_GscVendor(const std::string& response,
                                 std::string* response_payload);

  // Helper function for PinWeaver vendor specific commands.
  template <typename S, typename P>
  TPM_RC PinWeaverCommand(const std::string& tag, S serialize, P parse);

  // Obrains RSU device id from GSC.
  TPM_RC GetRsuDeviceIdInternal(std::string* device_id);

  // Sends pinweaver command to CSME instead of GSC.
  TPM_RC PinWeaverCsmeCommand(const std::string& in, std::string* out);

  PinWeaverBackendType GetPinwWeaverBackendType();

  // Obtains max supported size of NV_Read/Write buffer.
  TPM_RC GetMaxNVChunkSize(size_t* size);
};

}  // namespace trunks

#endif  // TRUNKS_TPM_UTILITY_IMPL_H_
