// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_COMMON_TPM_UTILITY_V1_H_
#define ATTESTATION_COMMON_TPM_UTILITY_V1_H_

#include "attestation/common/tpm_utility_common.h"

#include <stdint.h>

#include <optional>
#include <string>
#include <vector>

#include <openssl/rsa.h>
#include <trousers/scoped_tss_type.h>
#include <trousers/tss.h>

namespace attestation {

// A TpmUtility implementation for TPM v1.2 modules.
class TpmUtilityV1 : public TpmUtilityCommon {
 public:
  TpmUtilityV1() = default;
  // Testing constructor.
  explicit TpmUtilityV1(tpm_manager::TpmManagerUtility* tpm_manager_utility);
  TpmUtilityV1(const TpmUtilityV1&) = delete;
  TpmUtilityV1& operator=(const TpmUtilityV1&) = delete;

  ~TpmUtilityV1() override;

  // TpmUtility methods.
  bool Initialize() override;
  std::vector<KeyType> GetSupportedKeyTypes() override;
  TpmVersion GetVersion() override { return TPM_1_2; }
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
  bool GetNVDataSize(uint32_t nv_index, uint16_t* nv_size) const override;
  bool CertifyNV(uint32_t nv_index,
                 int nv_size,
                 const std::string& key_blob,
                 std::string* quoted_data,
                 std::string* quote) override;
  bool ReadPCR(uint32_t pcr_index, std::string* pcr_value) override;
  bool GetEndorsementPublicKeyModulus(KeyType key_type,
                                      std::string* ekm) override;
  bool GetEndorsementPublicKeyBytes(KeyType key_type,
                                    std::string* ek_bytes) override;

  bool CreateIdentity(KeyType key_type,
                      AttestationDatabase::Identity* identity) override;

 private:
  // Populates |context_handle| with a valid TSS_HCONTEXT and |tpm_handle|
  // with its matching TPM object iff the context can be created and a TPM
  // object exists in the TSS. Returns true on success.
  bool ConnectContextAsUser(trousers::ScopedTssContext* context_handle,
                            TSS_HTPM* tpm_handle);

  // Populates |context_handle| with a valid TSS_HCONTEXT and |tpm_handle| with
  // its matching TPM object iff the owner password is available and
  // authorization is successfully acquired.
  bool ConnectContextAsOwner(const std::string& owner_password,
                             trousers::ScopedTssContext* context_handle,
                             TSS_HTPM* tpm_handle);

  // Populates |context_handle| with a valid TSS_HCONTEXT and |tpm_handle|
  // with its matching TPM object authorized by the given |delegate_blob| and
  // |delegate_secret|. Returns true on success.
  bool ConnectContextAsDelegate(const std::string& delegate_blob,
                                const std::string& delegate_secret,
                                trousers::ScopedTssContext* context,
                                TSS_HTPM* tpm);

  // Set owner auth value to |tpm_handle|.
  bool SetTpmOwnerAuth(const std::string& owner_password,
                       TSS_HCONTEXT context_handle,
                       TSS_HTPM tpm_handle);
  // Reads an NVRAM space using the given context.
  bool ReadNvram(TSS_HCONTEXT context_handle,
                 TSS_HTPM tpm_handle,
                 TSS_HPOLICY policy_handle,
                 uint32_t index,
                 std::string* blob);

  // Returns if an Nvram space exists using the given context.
  bool IsNvramDefined(TSS_HCONTEXT context_handle,
                      TSS_HTPM tpm_handle,
                      uint32_t index);

  // TODO(cylai): make the return type right or change the definition of return
  // value.
  //
  // Returns the size of the specified NVRAM space.
  //
  // Parameters
  //   context_handle - The context handle for the TPM session
  //   index - NVRAM Space index
  // Returns -1 if the index, handle, or space is invalid.
  unsigned int GetNvramSize(TSS_HCONTEXT context_handle,
                            TSS_HTPM tpm_handle,
                            uint32_t index);

  // Sets up srk_handle_ if necessary. Returns true iff the SRK is ready.
  bool SetupSrk();

  // Loads the storage root key (SRK) and populates |srk_handle|. The
  // |context_handle| must be connected and valid. Returns true on success.
  bool LoadSrk(TSS_HCONTEXT context_handle, trousers::ScopedTssKey* srk_handle);

  // Loads a key in the TPM given a |key_blob| and a |parent_key_handle|. The
  // |context_handle| must be connected and valid. Returns true and populates
  // |key_handle| on success.
  bool LoadKeyFromBlob(const std::string& key_blob,
                       TSS_HCONTEXT context_handle,
                       TSS_HKEY parent_key_handle,
                       trousers::ScopedTssKey* key_handle);

  // Retrieves a |data| attribute defined by |flag| and |sub_flag| from a TSS
  // |object_handle|. The |context_handle| is only used for TSS memory
  // management.
  bool GetDataAttribute(TSS_HCONTEXT context_handle,
                        TSS_HOBJECT object_handle,
                        TSS_FLAG flag,
                        TSS_FLAG sub_flag,
                        std::string* data);

  // Convert a |tpm_public_key_object|, that is, a serialized TPM_PUBKEY for
  // TPM 1.2, to a DER encoded PKCS #1
  bool GetRSAPublicKeyFromTpmPublicKey(const std::string& tpm_public_key_object,
                                       std::string* public_key_der);

  // Creates an Attestation Identity Key (AIK). This method requires TPM owner
  // privilege.
  //
  // Parameters
  //   identity_public_key_der - The AIK public key in DER encoded form.
  //   identity_public_key - The AIK public key in serialized TPM_PUBKEY form.
  //   identity_key_blob - The AIK key in blob form.
  //   identity_binding - The EK-AIK binding (i.e. public key signature).
  //   identity_label - The label used to create the identity binding.
  //   pca_public_key - The public key of the temporary PCA used to create the
  //                    identity binding in serialized TPM_PUBKEY form.
  //
  // Returns true on success.
  bool MakeIdentity(std::string* identity_public_key_der,
                    std::string* identity_public_key,
                    std::string* identity_key_blob,
                    std::string* identity_binding,
                    std::string* identity_label,
                    std::string* pca_public_key);

  // Decrypts and parses an identity request.
  //
  // Parameters
  //   pca_key - The private key of the Privacy CA.
  //   request - The identity request data.
  //   identityBinding - The EK-AIK binding (i.e. public key signature).
  //
  // Returns true on success.
  bool DecryptIdentityRequest(RSA* pca_key,
                              const std::string& request,
                              std::string* identity_binding);

  // Initializes |context_handle_| if not yet. |consumer_name| refers to the
  // consumer of |context_handle_| after initialization; usually it is the
  // function name of the caller.
  bool InitializeContextHandle(const std::string& consumer_name);

  // Long-live TSS context in order reduce the overhead of context connection.
  trousers::ScopedTssContext context_handle_;
  TSS_HTPM tpm_handle_{0};
  trousers::ScopedTssKey srk_handle_{0};
};

}  // namespace attestation

#endif  // ATTESTATION_COMMON_TPM_UTILITY_V1_H_
