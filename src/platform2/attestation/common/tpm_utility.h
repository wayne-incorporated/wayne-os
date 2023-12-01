// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_COMMON_TPM_UTILITY_H_
#define ATTESTATION_COMMON_TPM_UTILITY_H_

#include <stdint.h>

#include <optional>
#include <string>
#include <vector>

#include <attestation/proto_bindings/attestation_ca.pb.h>
#include <attestation/proto_bindings/interface.pb.h>

#include "attestation/common/database.pb.h"

namespace attestation {

enum class KeyRestriction {
  kUnrestricted,
  kRestricted,
};

// A class which provides helpers for TPM-related tasks.
class TpmUtility {
 public:
  virtual ~TpmUtility() = default;

  // Override to perform initialization work. This must be called successfully
  // before calling any other methods.
  virtual bool Initialize() = 0;

  // Gets the supported key types (e.g., RSA, ECC, or both).
  virtual std::vector<KeyType> GetSupportedKeyTypes() = 0;

  // Returns the TPM version managed by this instance.
  virtual TpmVersion GetVersion() = 0;

  // Returns true iff the TPM is enabled, owned, and ready for attestation.
  virtual bool IsTpmReady() = 0;

  // Activates an attestation identity key for TPM 1.2. Effectively this
  // decrypts a certificate or some other type of credential with the
  // endorsement key.  The |identity_key_blob| is the key to which the
  // credential is bound. The |asym_ca_contents| and |sym_ca_attestation|
  // parameters are encrypted TPM structures, typically created by a CA
  // (TPM_ASYM_CA_CONTENTS and TPM_SYM_CA_ATTESTATION respectively). On success
  // returns true and populates the decrypted |credential|.
  virtual bool ActivateIdentity(const std::string& identity_key_blob,
                                const std::string& asym_ca_contents,
                                const std::string& sym_ca_attestation,
                                std::string* credential) = 0;

  // Activates an attestation identity key for TPM 2.0. The type of both the
  // endorsement key and the identity key is specified by |key_type|. The
  // |identity_key_blob| is as output by CreateRestrictedKey(). The
  // |encrypted_seed|, |credential_mac|, and |wrapped_credential| are provided
  // by the Attestation CA via an EncryptedIdentityCredential protobuf. Take
  // note that the |wrapped_credential| is not the wrapped certificate itself
  // but a shorter value which is used to derive
  virtual bool ActivateIdentityForTpm2(KeyType key_type,
                                       const std::string& identity_key_blob,
                                       const std::string& encrypted_seed,
                                       const std::string& credential_mac,
                                       const std::string& wrapped_credential,
                                       std::string* credential) = 0;

  // Generates and certifies a non-migratable key in the TPM. The new key will
  // correspond to |key_type| and |key_usage|. The parent key will be the
  // storage root key. The new key will be certified with the attestation
  // identity key represented by |identity_key_blob|. The |external_data| will
  // be included in the |key_info|. On success, returns true and populates
  // |public_key_tpm_format| with the public key of |key_blob| in TPM_PUBKEY
  // format, |public_key_der| with DER encoded format which converted from
  // TPM_PUBKEY, |key_info| with the TPM_CERTIFY_INFO that was signed, and
  // |proof| with the signature of |key_info| by the identity key. If
  // |restriction| is |kRestricted|, the signing/decrypting cannot work on an
  // arbitrary blob; instead the format is TPM-specific.
  virtual bool CreateCertifiedKey(
      KeyType key_type,
      KeyUsage key_usage,
      KeyRestriction key_restriction,
      std::optional<CertificateProfile> profile_hint,
      const std::string& identity_key_blob,
      const std::string& external_data,
      std::string* key_blob,
      std::string* public_key_der,
      std::string* public_key_tpm_format,
      std::string* key_info,
      std::string* proof) = 0;

  // Reads an endorsement public key from the TPM and provides it as a DER
  // encoded public key. PKCS #1 RSAPublicKey for RSA. RFC 5915 ECPublicKey for
  // EC.
  virtual bool GetEndorsementPublicKey(KeyType key_type,
                                       std::string* public_key_der) = 0;

  // Reads an endorsement certificate from the TPM.
  virtual bool GetEndorsementCertificate(KeyType key_type,
                                         std::string* certificate) = 0;

  // Unbinds |bound_data| with the key loaded from |key_blob| by decrypting
  // using the TPM_ES_RSAESOAEP_SHA1_MGF1 scheme. The input must be in the
  // format of a TPM_BOUND_DATA structure. On success returns true and provides
  // the decrypted |data|.
  virtual bool Unbind(const std::string& key_blob,
                      const std::string& bound_data,
                      std::string* data) = 0;

  // Signs |data_to_sign| with the key loaded from |key_blob| using the
  // TPM_SS_RSASSAPKCS1v15_DER scheme with SHA-256. On success returns true and
  // provides the |signature|.
  virtual bool Sign(const std::string& key_blob,
                    const std::string& data_to_sign,
                    std::string* signature) = 0;

  // Reads a PCR specified by |pcr_index|. On success returns true and
  // populates |_pcr_value|.
  virtual bool ReadPCR(uint32_t pcr_index, std::string* pcr_value) = 0;

  // Gets the data size for the NV data at |nv_index| and stores it into
  // |nv_size| if successful. Returns true for success, false otherwise.
  virtual bool GetNVDataSize(uint32_t nv_index, uint16_t* nv_size) const = 0;

  // Certifies NV data at |nv_index|. The amount of data to be certified,
  // starting at offset 0, is specified by |nv_size|. The |key_blob| must be a
  // restricted signing key. On success returns true and populates:
  //   |quoted_data| - The exact serialized data that was signed.
  //   |quote| - The signature.
  virtual bool CertifyNV(uint32_t nv_index,
                         int nv_size,
                         const std::string& key_blob,
                         std::string* quoted_data,
                         std::string* quote) = 0;

  // Signals to remove Attestation dependency on owner password.
  // Returns true if the dependency was removed this time, or it already has
  // been removed earlier; false otherwise.
  virtual bool RemoveOwnerDependency() = 0;

  // Reads an endorsement public key from the TPM and extracts the modulus in
  // |ekm|.
  virtual bool GetEndorsementPublicKeyModulus(KeyType key_type,
                                              std::string* ekm) = 0;

  // Reads the endorsement public key of `key_type` from TPM and extracts the
  // "bytes". For RSA key type, it is the modulus, and for ECC key type it is
  // the concatenation of X and Y components of the public key.
  virtual bool GetEndorsementPublicKeyBytes(KeyType key_type,
                                            std::string* ek_bytes) = 0;

  // Creates identity of |key_type| type and stores the output from TPM into
  // |identity|.
  virtual bool CreateIdentity(KeyType key_type,
                              AttestationDatabase::Identity* identity) = 0;
};

}  // namespace attestation

#endif  // ATTESTATION_COMMON_TPM_UTILITY_H_
