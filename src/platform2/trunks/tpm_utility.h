// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_TPM_UTILITY_H_
#define TRUNKS_TPM_UTILITY_H_

#include <map>
#include <optional>
#include <string>
#include <vector>

#include <brillo/secure_blob.h>

#include "trunks/cr50_headers/ap_ro_status.h"
#include "trunks/hmac_session.h"
#include "trunks/pinweaver.pb.h"
#include "trunks/policy_session.h"
#include "trunks/tpm_alerts.h"
#include "trunks/tpm_generated.h"
#include "trunks/trunks_export.h"

namespace trunks {

// These handles will be used by TpmUtility.
//   * kStorageRootKey: Storage Root Key (Primary Key in Storage Hierarchy in
// TPM2.0) It is ECC key by default, if the RSA key is already generated, we
// will keep use it.
//   * kSaltingKey: a RSA key under kStorageRootKey for
// asymmetric encrypting the salt when creating a HMAC session.
const TPMI_DH_PERSISTENT kStorageRootKey = PERSISTENT_FIRST;
// Deprecated: kECCStorageRootKey = PERSISTENT_FIRST + 1;
const TPMI_DH_PERSISTENT kSaltingKey = PERSISTENT_FIRST + 2;
const TPMI_DH_PERSISTENT kRSAEndorsementKey = PERSISTENT_FIRST + 3;
const TPMI_DH_PERSISTENT kCsmeSaltingKey = PERSISTENT_FIRST + 4;

// VENDOR_RC_ERR | VENDOR_RC_NO_SUCH_COMMAND
const int TPM_RC_NO_SUCH_COMMAND = 0x57f;

// Real NVRAM index for endoresement certificate. It is the real index which
// sent to TPM.
#if USE_GENERIC_TPM2
// This is specified in TCG EK Credential Profile for TPM Family 2.0.
constexpr uint32_t kRsaEndorsementCertificateIndex = 0x01c00002;
constexpr uint32_t kEccEndorsementCertificateIndex = 0x01c0000a;
#else
constexpr uint32_t kRsaEndorsementCertificateIndex = 0x1C00000;
constexpr uint32_t kEccEndorsementCertificateIndex = 0x1C00001;
#endif

// The non-real NVRAM index is only used and accepted by tpm_utility API.
// TODO(crbug/956855): remove these indexes.
constexpr uint32_t kRsaEndorsementCertificateNonRealIndex =
    kRsaEndorsementCertificateIndex & 0xFFFFFF;
constexpr uint32_t kEccEndorsementCertificateNonRealIndex =
    kEccEndorsementCertificateIndex & 0xFFFFFF;

constexpr int PinWeaverEccPointSize = 32;

struct PinWeaverEccPoint {
  uint8_t x[PinWeaverEccPointSize];
  uint8_t y[PinWeaverEccPointSize];
};

// An interface which provides convenient methods for common TPM operations.
class TRUNKS_EXPORT TpmUtility {
 public:
  enum AsymmetricKeyUsage { kDecryptKey, kSignKey, kDecryptAndSignKey };

  TpmUtility() {}
  TpmUtility(const TpmUtility&) = delete;
  TpmUtility& operator=(const TpmUtility&) = delete;

  virtual ~TpmUtility() {}

  // Synchronously performs a TPM startup sequence and self tests. Typically
  // this is done by the platform firmware. Returns the result of the startup
  // and self-tests or, if already started, just the result of the self-tests.
  virtual TPM_RC Startup() = 0;

  // Check if the TPM is in a state which allows trunks to proceed. The only
  // condition when the state is considered unacceptable and an error is
  // returned is if there is no way to communicate with the TPM.
  virtual TPM_RC CheckState() = 0;

  // This method removes all TPM context associated with a specific Owner.
  // As part of this process, it resets the SPS to a new random value, and
  // clears ownerAuth, endorsementAuth and lockoutAuth.
  // NOTE: This method needs to be called before InitializeTPM.
  virtual TPM_RC Clear() = 0;

  // Synchronously performs a TPM shutdown operation. It should always be
  // successful.
  virtual void Shutdown() = 0;

  // Synchronously prepares a TPM for use by Chromium OS. Typically this is done
  // by the platform firmware and, in that case, this method has no effect.
  virtual TPM_RC InitializeTpm() = 0;

  // Synchronously allocates the PCRs in the TPM. Currently we allocate
  // the first 16 PCRs to use the SHA-256 hash algorithm.
  // NOTE: PCR allocation only takes place at the next TPM_Startup call.
  // NOTE: This command needs platform authorization and PP assertion.
  virtual TPM_RC AllocatePCR(const std::string& platform_password) = 0;

  // Prepares the TPM resources necessary for pinweaver-csme.
  virtual TPM_RC PrepareForPinWeaver() = 0;

  // Performs steps needed for taking ownership, which can be done before
  // a signal that an ownership can be attempted is received.
  // This operation is an optional optimization: if PrepareForOwnership
  // is not called, TakeOwnership will later run through those preparational
  // steps, if needed.
  virtual TPM_RC PrepareForOwnership() = 0;

  // Synchronously takes ownership of the TPM with the given passwords as
  // authorization values.
  virtual TPM_RC TakeOwnership(const std::string& owner_password,
                               const std::string& endorsement_password,
                               const std::string& lockout_password) = 0;

  // Changes the owner password from `old_password` to `new_password`.
  virtual TPM_RC ChangeOwnerPassword(const std::string& old_password,
                                     const std::string& new_password) = 0;

  // Stir the tpm random generation module with some random entropy data.
  // |delegate| specifies an optional authorization delegate to be used.
  virtual TPM_RC StirRandom(const std::string& entropy_data,
                            AuthorizationDelegate* delegate) = 0;

  // This method returns |num_bytes| of random data generated by the tpm.
  // |delegate| specifies an optional authorization delegate to be used.
  virtual TPM_RC GenerateRandom(size_t num_bytes,
                                AuthorizationDelegate* delegate,
                                std::string* random_data) = 0;

  // This method extends the pcr specified by |pcr_index| with the SHA256
  // hash of |extend_data|. The exact action performed is
  // TPM2_PCR_Extend(Sha256(extend_data));
  // |delegate| specifies an optional authorization delegate to be used.
  virtual TPM_RC ExtendPCR(int pcr_index,
                           const std::string& extend_data,
                           AuthorizationDelegate* delegate) = 0;

  virtual TPM_RC ExtendPCRForCSME(int pcr_index,
                                  const std::string& extend_data) = 0;

  // This method reads the pcr specified by |pcr_index| and returns its value
  // in |pcr_value|. NOTE: it assumes we are using SHA256 as our hash alg.
  virtual TPM_RC ReadPCR(int pcr_index, std::string* pcr_value) = 0;

  virtual TPM_RC ReadPCRFromCSME(int pcr_index, std::string* pcr_value) = 0;

  // This method performs an encryption operation using a LOADED RSA key
  // referrenced by its handle |key_handle|. The |plaintext| is then encrypted
  // to give us the |ciphertext|. |scheme| refers to the encryption scheme
  // to be used. By default keys use OAEP, but can also use TPM_ALG_RSAES.
  // |delegate| specifies an optional authorization delegate to be used.
  virtual TPM_RC AsymmetricEncrypt(TPM_HANDLE key_handle,
                                   TPM_ALG_ID scheme,
                                   TPM_ALG_ID hash_alg,
                                   const std::string& plaintext,
                                   AuthorizationDelegate* delegate,
                                   std::string* ciphertext) = 0;

  // This method performs a decryption operating using a loaded RSA key
  // referenced by its handle |key_handle|. The |ciphertext| is then decrypted
  // to give us the |plaintext|. |scheme| refers to the decryption scheme
  // used. Valid schemes are: TPM_ALG_NULL, TPM_ALG_OAEP, TPM_ALG_RSAES.
  // |delegate| is an AuthorizationDelegate used to authorize this command.
  virtual TPM_RC AsymmetricDecrypt(TPM_HANDLE key_handle,
                                   TPM_ALG_ID scheme,
                                   TPM_ALG_ID hash_alg,
                                   const std::string& ciphertext,
                                   AuthorizationDelegate* delegate,
                                   std::string* plaintext) = 0;

  // This method performs the ECDH ZGen operation with an unrestricted
  // decryption key referenced by |key_handle|. |in_point| is the input point,
  // |out_point| is the output point. |delegate| is an AuthorizationDelegate
  // used to authorize this command.
  virtual TPM_RC ECDHZGen(TPM_HANDLE key_handle,
                          const TPM2B_ECC_POINT& in_point,
                          AuthorizationDelegate* delegate,
                          TPM2B_ECC_POINT* out_point) = 0;

  // This method takes an unrestricted signing key referenced by |key_handle|
  // and uses it to sign a hash: if |generate_hash| is true then get the hash
  // of |plaintext| using |hash_alg|, otherwise |plaintext| is already the hash
  // to sign. The signature produced is returned using the |signature| argument.
  // |scheme| is used to specify the signature scheme used. By default it is
  // TPM_ALG_RSASSA, but TPM_ALG_RSAPPS and TPM_ALG_ECDSA can be specified.
  // |hash_alg| is the algorithm used in the signing operation. It is by default
  // TPM_ALG_SHA256. |delegate| is an AuthorizationDelegate used to authorize
  // this command.
  virtual TPM_RC Sign(TPM_HANDLE key_handle,
                      TPM_ALG_ID scheme,
                      TPM_ALG_ID hash_alg,
                      const std::string& plaintext,
                      bool generate_hash,
                      AuthorizationDelegate* delegate,
                      std::string* signature) = 0;
  // This method is identical to Sign() above except it returns the result
  // in TPMT_SIGNATURE type, not in string type.
  virtual TPM_RC RawSign(TPM_HANDLE key_handle,
                         TPM_ALG_ID scheme,
                         TPM_ALG_ID hash_alg,
                         const std::string& plaintext,
                         bool generate_hash,
                         AuthorizationDelegate* delegate,
                         TPMT_SIGNATURE* auth) = 0;

  // Dead code removed at CL:1366670 (https://crrev.com/c/1366670)
  // It's because we doesn't use Verify() in the reality.
  // We sign-with-TPM -> verify-in-software at this moment.
  //
  // This method verifies that the signature produced on the plaintext was
  // performed by |key_handle|. |scheme| and |hash| refer to the signature
  // scheme used to produce the signature: if |generate_hash| is true, the
  // hash of |plaintext| is signed, otherwise |plaintext| is already the hash
  // to sign. The signature scheme is by default TPM_ALG_RSASSA with
  // TPM_ALG_SHA256 but can take the value of TPM_ALG_RSAPPS with other hash
  // algorithms supported by the tpm. Returns TPM_RC_SUCCESS when the signature
  // is correct. |delegate| specifies an optional authorization delegate to be
  // used.
  // virtual TPM_RC Verify(TPM_HANDLE key_handle,
  //                       TPM_ALG_ID scheme,
  //                       TPM_ALG_ID hash_alg,
  //                       const std::string& plaintext,
  //                       bool generate_hash,
  //                       const std::string& signature,
  //                       AuthorizationDelegate* delegate) = 0;

  // This method is used to check if a key was created in the TPM. |key_handle|
  // refers to a loaded Tpm2.0 object, and |creation_blob| is the blob
  // generated when the object was created. Returns TPM_RC_SUCCESS iff the
  // object was created in the TPM.
  virtual TPM_RC CertifyCreation(TPM_HANDLE key_handle,
                                 const std::string& creation_blob) = 0;

  // This method is used to change the authorization value associated with a
  // |key_handle| to |new_password|. |delegate| is an AuthorizationDelegate
  // that is loaded with the old authorization value of |key_handle|.
  // When |key_blob| is not null, it is populated with the new encrypted key
  // blob. Note: the key must be unloaded and reloaded to use the
  // new authorization value.
  virtual TPM_RC ChangeKeyAuthorizationData(TPM_HANDLE key_handle,
                                            const std::string& new_password,
                                            AuthorizationDelegate* delegate,
                                            std::string* key_blob) = 0;

  // This method imports an external RSA key of |key_type| into the TPM.
  // |modulus| and |prime_factor| are interpreted as raw bytes in big-endian
  // order. If the out argument |key_blob| is not null, it is populated with
  // the imported key, which can then be loaded into the TPM.
  virtual TPM_RC ImportRSAKey(AsymmetricKeyUsage key_type,
                              const std::string& modulus,
                              uint32_t public_exponent,
                              const std::string& prime_factor,
                              const std::string& password,
                              AuthorizationDelegate* delegate,
                              std::string* key_blob) = 0;

  // This method imports an external ECC key of |key_type| into the TPM.
  // |public_point_x| and |public_point_y| are the coordinates of the public key
  // point on the curve |curve_id|. |private_value| is the private key.
  // |public_point_x|, |public_point_y|, and |private_value| are interpreted as
  // raw bytes in big-endian. |password| is the authorization value for the
  // imported key. If the out argument |key_blob| is not null, it is populated
  // with the imported key, which can then be loaded into the TPM.
  virtual TPM_RC ImportECCKey(AsymmetricKeyUsage key_type,
                              TPMI_ECC_CURVE curve_id,
                              const std::string& public_point_x,
                              const std::string& public_point_y,
                              const std::string& private_value,
                              const std::string& password,
                              AuthorizationDelegate* delegate,
                              std::string* key_blob) = 0;

  // This method imports an external ECC key of |key_type| into the TPM with
  // policy digest. |public_point_x| and |public_point_y| are the coordinates of
  // the public key point on the curve |curve_id|. |private_value| is the
  // private key. |public_point_x|, |public_point_y|, and |private_value| are
  // interpreted as raw bytes in big-endian. If the out argument |key_blob| is
  // not null, it is populated with the imported key, which can then be loaded
  // into the TPM.
  virtual TPM_RC ImportECCKeyWithPolicyDigest(AsymmetricKeyUsage key_type,
                                              TPMI_ECC_CURVE curve_id,
                                              const std::string& public_point_x,
                                              const std::string& public_point_y,
                                              const std::string& private_value,
                                              const std::string& policy_digest,
                                              AuthorizationDelegate* delegate,
                                              std::string* key_blob) = 0;

  // This method uses the TPM to generates an RSA key of type |key_type|.
  // |modulus_bits| is used to specify the size of the modulus, and
  // |public_exponent| specifies the exponent of the key. After this function
  // terminates, |key_blob| contains a key blob that can be loaded into the TPM.
  // |policy_digest| specifies an optional policy to use to authorize this key.
  // |use_only_policy_authorization| specifies if we can use HmacSession in
  // addition to PolicySession to authorize use of this key.
  // |creation_pcr_indexes| allows the caller to specify a list of pcr indexes
  // in the creation data.
  // If the |creation_blob| out param is defined, it will contain the
  // serialized creation structures generated by the TPM.
  // This can be used to verify the state of the TPM during key creation.
  // NOTE: if |use_only_policy_authorization| is set to true,
  // parameter_encryption must be disabled when the key is used.
  virtual TPM_RC CreateRSAKeyPair(
      AsymmetricKeyUsage key_type,
      int modulus_bits,
      uint32_t public_exponent,
      const std::string& password,
      const std::string& policy_digest,
      bool use_only_policy_authorization,
      const std::vector<uint32_t>& creation_pcr_indexes,
      AuthorizationDelegate* delegate,
      std::string* key_blob,
      std::string* creation_blob) = 0;

  // This method uses the TPM to generates an ECC key of type |key_type|.
  // |curve_id| is the TPM curve ID of EC curve used for generating the key.
  // |password| is the authorization value to use to authorize the generated
  // key.
  // |policy_digest| specifies an optional policy to use to authorize the
  // generated key.
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
  // state of the TPM during key creation. NOTE: if
  // |use_only_policy_authorization| is set to true, parameter_encryption must
  // be disabled when the key is used.
  virtual TPM_RC CreateECCKeyPair(
      AsymmetricKeyUsage key_type,
      TPMI_ECC_CURVE curve_id,
      const std::string& password,
      const std::string& policy_digest,
      bool use_only_policy_authorization,
      const std::vector<uint32_t>& creation_pcr_indexes,
      AuthorizationDelegate* delegate,
      std::string* key_blob,
      std::string* creation_blob) = 0;

  // This method is performs as the same as `CreateECCKeyPair`, except that the
  // generated key is restricted.
  virtual TPM_RC CreateRestrictedECCKeyPair(
      AsymmetricKeyUsage key_type,
      TPMI_ECC_CURVE curve_id,
      const std::string& password,
      const std::string& policy_digest,
      bool use_only_policy_authorization,
      const std::vector<uint32_t>& creation_pcr_indexes,
      AuthorizationDelegate* delegate,
      std::string* key_blob,
      std::string* creation_blob) = 0;

  // This method loads a pregenerated TPM key into the TPM. |key_blob| contains
  // the blob returned by a key creation function. The loaded key's handle is
  // returned using |key_handle|.
  virtual TPM_RC LoadKey(const std::string& key_blob,
                         AuthorizationDelegate* delegate,
                         TPM_HANDLE* key_handle) = 0;

  // This method loads the public part of an external RSA key into the TPM. Key
  // is of type |key_type|. Algorithm scheme and hashing algorithm are passed
  // via |scheme| and |hash_alg|. |modulus| is interpreted as raw bytes in
  // big-endian order. |public_exponent| specifies the exponent of the key. The
  // loaded key's handle is returned using |key_handle|.
  virtual TPM_RC LoadRSAPublicKey(AsymmetricKeyUsage key_type,
                                  TPM_ALG_ID scheme,
                                  TPM_ALG_ID hash_alg,
                                  const std::string& modulus,
                                  uint32_t public_exponent,
                                  AuthorizationDelegate* delegate,
                                  TPM_HANDLE* key_handle) = 0;

  // This methods loads the public part of an external ECC key to TPM. Key is
  // is of type |key_type|. Algorithm scheme and hash algorithm are passed via
  // |scheme| and |hash_alg|.
  virtual TPM_RC LoadECPublicKey(AsymmetricKeyUsage key_type,
                                 TPM_ECC_CURVE curve_id,
                                 TPM_ALG_ID scheme,
                                 TPM_ALG_ID hash_alg,
                                 const std::string& x,
                                 const std::string& y,
                                 AuthorizationDelegate* delegate,
                                 TPM_HANDLE* key_handle) = 0;

  // This function sets |name| to the name of the object referenced by
  // |handle|. This function only works on Transient and Permanent objects.
  virtual TPM_RC GetKeyName(TPM_HANDLE handle, std::string* name) = 0;

  // This function returns the public area of a handle in the tpm.
  virtual TPM_RC GetKeyPublicArea(TPM_HANDLE handle,
                                  TPMT_PUBLIC* public_data) = 0;

  // This method seals |data_to_seal| to the TPM. The |sealed_data| can be
  // retrieved by fulfilling the policy represented by |policy_digest|. The
  // session used to unseal the data will need to have the
  // EntityAuthorizationValue set to |auth_value| if non-empty.
  // |require_admin_with_policy| specifies if we can use HmacSession in
  // addition to PolicySession to authorize use of this data.
  // NOTE: if |require_admin_with_policy| is set to true,
  // parameter_encryption must be disabled when unsealing the data.
  virtual TPM_RC SealData(const std::string& data_to_seal,
                          const std::string& policy_digest,
                          const std::string& auth_value,
                          bool require_admin_with_policy,
                          AuthorizationDelegate* delegate,
                          std::string* sealed_data) = 0;

  // This method is used to retrieve data that was sealed to the TPM.
  // |sealed_data| refers to sealed data returned from SealData.
  virtual TPM_RC UnsealData(const std::string& sealed_data,
                            AuthorizationDelegate* delegate,
                            std::string* unsealed_data) = 0;

  virtual TPM_RC UnsealDataWithHandle(TPM_HANDLE object_handle,
                                      AuthorizationDelegate* delegate,
                                      std::string* unsealed_data) = 0;

  // This method sets up a given HmacSession with parameter encryption set to
  // true. Returns an TPM_RC_SUCCESS on success.
  virtual TPM_RC StartSession(HmacSession* session) = 0;

  // Adds pcr values to the given |policy_session|.
  // The policy is bound to a given map of pcr_index -> pcr_value in |pcr_map|.
  // If some values in the map are empty, the method uses the current value of
  // the pcr for the corresponding indexes. If |use_auth_value| is set to true
  // then a authorization value will be required when using the digest. In this
  // case PolicyAuthValue is called on session first, and PolicyPCR is called
  // after this. Those two calls must be made in the same order when we need to
  // reveal the secret guarded by the authorization value.
  virtual TPM_RC AddPcrValuesToPolicySession(
      const std::map<uint32_t, std::string>& pcr_map,
      bool use_auth_value,
      PolicySession* policy_session) = 0;

  // Calculates the policy digest for a given pcr_map. Uses current value of
  // the pcr for empty values.
  virtual TPM_RC GetPolicyDigestForPcrValues(
      const std::map<uint32_t, std::string>& pcr_map,
      bool use_auth_value,
      std::string* policy_digest) = 0;

  // This method defines a non-volatile storage area in the TPM, referenced
  // by |index| of size |num_bytes|. This command needs owner authorization.
  // The |attributes| of the space must be specified as a combination of
  // TPMA_NV_* values. Optionally, an |authorization_value| and / or
  // |policy_digest| can be specified which will be associated with the space.
  // These values must either be a valid SHA256 digest (or empty).
  virtual TPM_RC DefineNVSpace(uint32_t index,
                               size_t num_bytes,
                               TPMA_NV attributes,
                               const std::string& authorization_value,
                               const std::string& policy_digest,
                               AuthorizationDelegate* delegate) = 0;

  // This method destroys the non-volatile space referred to by |index|.
  // This command needs owner authorization.
  virtual TPM_RC DestroyNVSpace(uint32_t index,
                                AuthorizationDelegate* delegate) = 0;

  // This method locks the non-volatile space referred to by |index|. The caller
  // needs indicate whether they want to |lock_read| and / or |lock_write|. They
  // also need to indicate if they are |using_owner_authorization|.
  virtual TPM_RC LockNVSpace(uint32_t index,
                             bool lock_read,
                             bool lock_write,
                             bool using_owner_authorization,
                             AuthorizationDelegate* delegate) = 0;

  // This method writes |nvram_data| to the non-volatile space referenced by
  // |index|, at |offset| bytes from the start of the non-volatile space. The
  // caller needs to indicate if they are |using_owner_authorization|. If
  // |extend| is set, the value will be extended and offset ignored.
  virtual TPM_RC WriteNVSpace(uint32_t index,
                              uint32_t offset,
                              const std::string& nvram_data,
                              bool using_owner_authorization,
                              bool extend,
                              AuthorizationDelegate* delegate) = 0;

  // Increments non-volatile counter at |index|.
  virtual TPM_RC IncrementNVCounter(uint32_t index,
                                    bool using_owner_authorization,
                                    AuthorizationDelegate* delegate) = 0;

  // This method reads |num_bytes| of data from the |offset| located at the
  // non-volatile space defined by |index|. This method returns an error if
  // |length| + |offset| is larger than the size of the defined non-volatile
  // space. The caller needs to indicate if they are |using_owner_authorization|
  virtual TPM_RC ReadNVSpace(uint32_t index,
                             uint32_t offset,
                             size_t num_bytes,
                             bool using_owner_authorization,
                             std::string* nvram_data,
                             AuthorizationDelegate* delegate) = 0;

  // This function sets |name| to the name of the non-volatile space referenced
  // by |index|.
  virtual TPM_RC GetNVSpaceName(uint32_t index, std::string* name) = 0;

  // This function returns the public area of an non-volatile space defined in
  // the TPM.
  virtual TPM_RC GetNVSpacePublicArea(uint32_t index,
                                      TPMS_NV_PUBLIC* public_data) = 0;

  // Lists all defined NV indexes.
  virtual TPM_RC ListNVSpaces(std::vector<uint32_t>* index_list) = 0;

  // Sets dictionary attack parameters. Requires lockout authorization.
  // Parameters map directly to TPM2_DictionaryAttackParameters in the TPM 2.0
  // specification.
  virtual TPM_RC SetDictionaryAttackParameters(
      uint32_t max_tries,
      uint32_t recovery_time,
      uint32_t lockout_recovery,
      AuthorizationDelegate* delegate) = 0;

  // Reset dictionary attack lockout. Requires lockout authorization.
  virtual TPM_RC ResetDictionaryAttackLock(AuthorizationDelegate* delegate) = 0;

  // Gets the endorsement key of a given |key_type| and |auth_policy|. On
  // success returns TPM_RC_SUCCESS and populates |key_handle|. Requires
  // endorsement authorization to create the key.
  virtual TPM_RC GetAuthPolicyEndorsementKey(
      TPM_ALG_ID key_type,
      const std::string& auth_policy,
      AuthorizationDelegate* endorsement_delegate,
      TPM_HANDLE* key_handle,
      TPM2B_NAME* key_name) = 0;

  // Gets the endorsement key  of a given |key_type| and use the default EK
  // template, creating the key as needed If the |key_type| is RSA, the key will
  // be made persistent. On success returns TPM_RC_SUCCESS and populates
  // |key_handle|. Requires endorsement authorization to create the key and
  // owner authorization to make the key persistent (RSA only). The
  // |owner_delegate| is ignored if |key_type| is not RSA or if the key is
  // already persistent.
  virtual TPM_RC GetEndorsementKey(TPM_ALG_ID key_type,
                                   AuthorizationDelegate* endorsement_delegate,
                                   AuthorizationDelegate* owner_delegate,
                                   TPM_HANDLE* key_handle) = 0;

  // Creates an asymmetric restricted signing key of the given |key_type|.
  // On success returns TPM_RC_SUCCESS and populates |key_blob|.
  virtual TPM_RC CreateIdentityKey(TPM_ALG_ID key_type,
                                   AuthorizationDelegate* delegate,
                                   std::string* key_blob) = 0;

  // For TPMs with updateable firmware: Declate the current firmware
  // version stable and invalidate previous versions, if any.
  // Returns the result of sending the appropriate command to the TPM.
  // For TPMs with fixed firmware: NOP, always returns TPM_RC_SUCCESS.
  virtual TPM_RC DeclareTpmFirmwareStable() = 0;

  // Reads the RSA certificate from nvram space and extracts the public key
  // modulus into |ekm|. Returns TPM_RC_SUCCESS on success.
  virtual TPM_RC GetPublicRSAEndorsementKeyModulus(std::string* ekm) = 0;

  // For TPMs that support it: allow setting the CCD password if |allow_pwd|
  // is true, prohibit otherwise.
  // Returns the result of sending the appropriate command to the TPM.
  // For TPMs that don't support it: NOP, always returns TPM_RC_SUCCESS.
  // Rationale for this behavior: All TPM revisions that need restricting CCD
  // password implement this command. If the command is not implemented, the
  // TPM firmware has no notion of restricting the CCD password and doesn't need
  // a signal to lock things down at login.
  virtual TPM_RC ManageCCDPwd(bool allow_pwd) = 0;

  // Reads TPM alerts information from the chip.
  // If alerts->chip_family equals to kFamilyUndefined then
  // this operation is not supported by the chip.
  // Returns TPM_RC_SUCCESS on success.
  virtual TPM_RC GetAlertsData(TpmAlertsData* alerts) = 0;

  // Input parameter:
  //    |request_version| is the pinweaver protocol version that cryptohome
  //        knows about.
  // Output parameters:
  //    |protocol_version| is the current protocol version used by pinweaver.
  // Returns TPM_RC_SUCCESS if PinWeaver is supported.
  virtual TPM_RC PinWeaverIsSupported(uint8_t request_version,
                                      uint8_t* protocol_version) = 0;

  // Create an empty Merkle tree with the given parameters.
  // On success:
  //   returns VENDOR_RC_SUCCESS
  //   |result_code| is set to EC_SUCCESS (0).
  //   |root_hash| is set to the root hash of the empty tree with the given
  //       parameters.
  // On failure:
  //   returns VENDOR_RC_SUCCESS
  //   |result_code| is set to one of pw_error_codes_enum.
  //   |root_hash| is set to the root hash of the empty tree with the given.
  //       parameters.
  virtual TPM_RC PinWeaverResetTree(uint8_t protocol_version,
                                    uint8_t bits_per_level,
                                    uint8_t height,
                                    uint32_t* result_code,
                                    std::string* root_hash) = 0;

  // Insert a leaf to the Merkle tree where:
  //   |protocol_version| is the protocol version used to communicate with
  //       pinweaver.
  //   |label| is the location of the leaf in the tree.
  //   |h_aux| is the auxiliary hashes started from the bottom of the tree
  //       working toward the root in index order.
  //   |le_secret| is the low entropy secret that is limited by the delay
  //       schedule.
  //   |he_secret| is the high entropy secret that is protected by GSC and
  //       returned on successful authentication.
  //   |reset_secret| is the high entropy secret used to reset the attempt
  //       counters and authenticate without following the delay schedule.
  //   |delay_schedule| is constructed of (attempt_count, time_delay) with at
  //       most PW_SCHED_COUNT entries.
  //   |valid_pcr_criteria| is list of at most PW_MAX_PCR_CRITERIA_COUNT entries
  //       where each entry represents a bitmask of PCR indexes and the expected
  //       digest corresponding to those PCR.
  //   |expiration_delay| is the expiration window of the leaf, in seconds.
  //   Nullopt means the leaf doesn't expire.
  // On success:
  //   returns VENDOR_RC_SUCCESS
  //   |result_code| is set to EC_SUCCESS (0).
  //   |root_hash| is set to the updated root hash of the tree.
  //   |cred_metadata| is set to the wrapped leaf data.
  //   |mac| is set to the HMAC used in the Merkle tree calculations.
  // On failure:
  //   returns VENDOR_RC_SUCCESS
  //   |result_code| is set to one of pw_error_codes_enum.
  //   |root_hash| is set to the unchanged root hash of the tree.
  //   |cred_metadata| and |mac| are both empty.
  virtual TPM_RC PinWeaverInsertLeaf(
      uint8_t protocol_version,
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
      std::string* mac) = 0;

  // Remove a leaf from the Merkle tree where:
  //   |protocol_version| is the protocol version used to communicate with
  //       pinweaver.
  //   |label| is the location of the leaf in the tree.
  //   |h_aux| is the auxiliary hashes started from the bottom of the tree
  //       working toward the root in index order.
  //   |mac| is set to the HMAC used in the Merkle tree calculations.
  // On success:
  //   returns VENDOR_RC_SUCCESS
  //   |result_code| is set to EC_SUCCESS (0).
  //   |root_hash| is set to the updated root hash of the tree.
  // On failure:
  //   returns VENDOR_RC_SUCCESS
  //   |result_code| is set to one of pw_error_codes_enum.
  //   |root_hash| is set to the unchanged root hash of the tree.
  virtual TPM_RC PinWeaverRemoveLeaf(uint8_t protocol_version,
                                     uint64_t label,
                                     const std::string& h_aux,
                                     const std::string& mac,
                                     uint32_t* result_code,
                                     std::string* root_hash) = 0;

  // Attempts to authenticate a leaf from the Merkle tree where:
  //   |protocol_version| is the protocol version used to communicate with
  //       pinweaver.
  //   |le_secret| is the low entropy secret that is limited by the delay
  //       schedule.
  //   |h_aux| is the auxiliary hashes started from the bottom of the tree
  //       working toward the root in index order.
  //   |cred_metadata| is set to the wrapped leaf data.
  // On auth success:
  //   returns VENDOR_RC_SUCCESS
  //   |result_code| is set to EC_SUCCESS (0).
  //   |root_hash| is set to the updated root hash of the tree.
  //   |he_secret| is the high entropy secret that is protected by GSC and
  //       returned on successful authentication.
  //   |reset_secret| is the reset secret that is protected by GSC and
  //       returned on successful authentication.
  //   |cred_metadata_out| is set to the updated wrapped leaf data.
  //   |mac_out| is set to the updated HMAC used in the Merkle tree
  //       calculations.
  //   |seconds_to_wait| is 0
  // On auth fail:
  //   returns VENDOR_RC_SUCCESS
  //   |result_code| is set to PW_ERR_LOWENT_AUTH_FAILED.
  //   |root_hash| is set to the updated root hash of the tree.
  //   |cred_metadata_out| is set to the updated wrapped leaf data.
  //   |mac_out| is set to the updated HMAC used in the Merkle tree
  //        calculations.
  //   |seconds_to_wait| is 0
  //   |he_secret| and |reset_secret| are empty.
  // On rate limited:
  //   returns VENDOR_RC_SUCCESS
  //   |result_code| is set to PW_ERR_RATE_LIMIT_REACHED.
  //   |root_hash| is set to the unchanged root hash of the tree.
  //   |seconds_to_wait| is set to the seconds required before an authentication
  //        attempt can be made.
  //   |he_secret|, |reset_secret|, |cred_metadata_out|, and |mac| are all
  //   empty.
  // On error:
  //   returns VENDOR_RC_SUCCESS
  //   |result_code| is set to one of pw_error_codes_enum.
  //   |root_hash| is set to the unchanged root hash of the tree.
  //   |seconds_to_wait| is 0
  //   |he_secret|, |reset_secret|, |cred_metadata_out|, and |mac| are all
  //   empty.
  //
  // Note that for the invalid fields |seconds_to_wait| will be zero and the
  // rest will be cleared (e.g. zero length), so it isn't necessary to check
  // |result_code| to determine if fields are valid or not.
  virtual TPM_RC PinWeaverTryAuth(uint8_t protocol_version,
                                  const brillo::SecureBlob& le_secret,
                                  const std::string& h_aux,
                                  const std::string& cred_metadata,
                                  uint32_t* result_code,
                                  std::string* root_hash,
                                  uint32_t* seconds_to_wait,
                                  brillo::SecureBlob* he_secret,
                                  brillo::SecureBlob* reset_secret,
                                  std::string* cred_metadata_out,
                                  std::string* mac_out) = 0;

  // Attempts to reset a leaf from the Merkle tree where:
  //   |protocol_version| is the protocol version used to communicate with
  //       pinweaver.
  //   |reset_secret| is the high entropy secret used to reset the attempt
  //       counters and authenticate without following the delay schedule.
  //   |strong_reset| is whether the expiration timestamp should be extended
  //       to |expiration_delay| seconds from now too, in addition to resetting
  //       the attempt counter.
  //   |h_aux| is the auxiliary hashes started from the bottom of the tree
  //       working toward the root in index order.
  //   |cred_metadata| is set to the wrapped leaf data.
  // On auth success:
  //   returns VENDOR_RC_SUCCESS
  //   |result_code| is set to EC_SUCCESS (0).
  //   |root_hash| is set to the updated root hash of the tree.
  //   |cred_metadata_out| is set to the updated wrapped leaf data.
  //   |mac_out| is set to the updated HMAC used in the Merkle tree
  //       calculations.
  // On auth fail or error:
  //   returns VENDOR_RC_SUCCESS
  //   |result_code| is set to one of pw_error_codes_enum.
  //   |root_hash| is set to the unchanged root hash of the tree.
  //   |he_secret|, |cred_metadata_out|, and |mac| are all empty.
  virtual TPM_RC PinWeaverResetAuth(uint8_t protocol_version,
                                    const brillo::SecureBlob& reset_secret,
                                    bool strong_reset,
                                    const std::string& h_aux,
                                    const std::string& cred_metadata,
                                    uint32_t* result_code,
                                    std::string* root_hash,
                                    std::string* cred_metadata_out,
                                    std::string* mac_out) = 0;

  // Retrieves the log of recent operations where:
  //   |protocol_version| is the protocol version used to communicate with
  //       pinweaver.
  //   |root| is the last known root hash.
  // On success:
  //   returns VENDOR_RC_SUCCESS
  //   |result_code| is set to EC_SUCCESS (0).
  //   |root_hash| is set to the unchanged root hash of the tree.
  //   |log| is set to operations since |root| (inclusive) or the entire log if
  //       |root| isn't found.
  // On error:
  //   returns VENDOR_RC_SUCCESS
  //   |result_code| is set to one of pw_error_codes_enum.
  //   |root_hash| is set to the unchanged root hash of the tree.
  //   |log| is empty.
  virtual TPM_RC PinWeaverGetLog(
      uint8_t protocol_version,
      const std::string& root,
      uint32_t* result_code,
      std::string* root_hash,
      std::vector<trunks::PinWeaverLogEntry>* log) = 0;

  // Attempts to replay a previous transaction from the PinWeaver log where:
  //   |log_root| is the root hash of the log entry to be replayed.
  //   |h_aux| is the auxiliary hashes started from the bottom of the tree
  //       working toward the root in index order.
  //   |cred_metadata| is set to the wrapped leaf data.
  // On success:
  //   returns VENDOR_RC_SUCCESS
  //   |result_code| is set to EC_SUCCESS (0).
  //   |root_hash| is set to the unchanged root hash of the tree.
  //   |cred_metadata_out| is set to the updated wrapped leaf data.
  //   |mac_out| is set to the updated HMAC used in the Merkle tree
  //       calculations.
  // On error:
  //   returns VENDOR_RC_SUCCESS
  //   |result_code| is set to one of pw_error_codes_enum.
  //   |root_hash| is set to the unchanged root hash of the tree.
  virtual TPM_RC PinWeaverLogReplay(uint8_t protocol_version,
                                    const std::string& log_root,
                                    const std::string& h_aux,
                                    const std::string& cred_metadata,
                                    uint32_t* result_code,
                                    std::string* root_hash,
                                    std::string* cred_metadata_out,
                                    std::string* mac_out) = 0;

  // Retrieves the current PinWeaver server system info.
  // On success:
  //   returns VENDOR_RC_SUCCESS
  //   |result_code| is set to EC_SUCCESS (0).
  //   |root_hash| is set to the unchanged root hash of the tree.
  //   |boot_count| is set to the current boot count of the PinWeaver server.
  //   |seconds_since_boot| is set to the current PinWeaver server timer value,
  //       which is equivalent to how many seconds had passed since last boot.
  // On error:
  //   returns VENDOR_RC_SUCCESS
  //   |result_code| is set to one of pw_error_codes_enum.
  //   |root_hash| is set to the unchanged root hash of the tree.
  virtual TPM_RC PinWeaverSysInfo(uint8_t protocol_version,
                                  uint32_t* result_code,
                                  std::string* root_hash,
                                  uint32_t* boot_count,
                                  uint64_t* seconds_since_boot) = 0;

  // Establishes the Pk of the specified auth channel with the server.
  //   |protocol_version| is the protocol version used to communicate with
  //       pinweaver.
  //   |auth_channel| is the auth channel to establish the Pk.
  //   |client_public_key| is the ECDH public key of the client, which is
  //       a point on the P256 curve.
  // On success:
  //   returns VENDOR_RC_SUCCESS
  //   |result_code| is set to EC_SUCCESS (0).
  //   |root_hash| is set to the unchanged root hash of the tree.
  //   |server_public_key| is set to the ECDH public key of the server, which is
  //       a point on the P256 curve.
  // On error:
  //   returns VENDOR_RC_SUCCESS
  //   |result_code| is set to one of pw_error_codes_enum.
  //   |root_hash| is set to the unchanged root hash of the tree.
  //   |server_public_key| is empty.
  virtual TPM_RC PinWeaverGenerateBiometricsAuthPk(
      uint8_t protocol_version,
      uint8_t auth_channel,
      const PinWeaverEccPoint& client_public_key,
      uint32_t* result_code,
      std::string* root_hash,
      PinWeaverEccPoint* server_public_key) = 0;

  // Inserts a biometrics rate-limiter to the Merkle tree where:
  //   |protocol_version| is the protocol version used to communicate with
  //       pinweaver.
  //   |auth_channel| is the auth channel of the rate-limiter.
  //   |label| is the location of the leaf in the tree.
  //   |h_aux| is the auxiliary hashes started from the bottom of the tree
  //       working toward the root in index order.
  //   |reset_secret| is the high entropy secret used to reset the attempt
  //       counters and authenticate without following the delay schedule.
  //   |delay_schedule| is constructed of (attempt_count, time_delay) with at
  //       most PW_SCHED_COUNT entries.
  //   |valid_pcr_criteria| is list of at most PW_MAX_PCR_CRITERIA_COUNT entries
  //       where each entry represents a bitmask of PCR indexes and the expected
  //       digest corresponding to those PCR.
  //   |expiration_delay| is the expiration window of the leaf, in seconds.
  //       Nullopt means the leaf doesn't expire.
  // On success:
  //   returns VENDOR_RC_SUCCESS
  //   |result_code| is set to EC_SUCCESS (0).
  //   |root_hash| is set to the updated root hash of the tree.
  //   |cred_metadata| is set to the wrapped leaf data.
  //   |mac| is set to the HMAC used in the Merkle tree calculations.
  // On failure:
  //   returns VENDOR_RC_SUCCESS
  //   |result_code| is set to one of pw_error_codes_enum.
  //   |root_hash| is set to the unchanged root hash of the tree.
  //   |cred_metadata| and |mac| are both empty.
  virtual TPM_RC PinWeaverCreateBiometricsAuthRateLimiter(
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
      std::string* mac) = 0;

  // Tries to start an authentication attempt with a rate-limiter
  // from the Merkle tree where:
  //   |protocol_version| is the protocol version used to communicate with
  //       pinweaver.
  //   |auth_channel| is the auth channel of the rate-limiter.
  //   |client_nonce| is the nonce used for establish the session key used for
  //       encrypting the returned HEC.
  //   |h_aux| is the auxiliary hashes started from the bottom of the tree
  //       working toward the root in index order.
  //   |cred_metadata| is set to the wrapped leaf data.
  // On auth success:
  //   returns VENDOR_RC_SUCCESS
  //   |result_code| is set to EC_SUCCESS (0).
  //   |root_hash| is set to the updated root hash of the tree.
  //   |server_nonce| is the nonce used for establish the session key used for
  //       encrypting the returned HEC.
  //   |encrypted_high_entropy_secret| is the high entropy secret that is
  //       protected by GSC and returned on successful authentication. It
  //       is encrypted with the session key derived from the client nonce,
  //       server nonce, and Pk of that auth channel.
  //   |iv| is the IV used for the AES-CTR encryption of the HEC.
  //   |cred_metadata_out| is set to the updated wrapped leaf data.
  //   |mac_out| is set to the updated HMAC used in the Merkle tree
  //       calculations.
  // On auth fail:
  //   returns VENDOR_RC_SUCCESS
  //   |result_code| is set to PW_ERR_LOWENT_AUTH_FAILED.
  //   |root_hash| is set to the updated root hash of the tree.
  //   |cred_metadata_out| is set to the updated wrapped leaf data.
  //   |mac_out| is set to the updated HMAC used in the Merkle tree
  //        calculations.
  //   other output fields are empty.
  // On error:
  //   returns VENDOR_RC_SUCCESS
  //   |result_code| is set to one of pw_error_codes_enum.
  //   |root_hash| is set to the unchanged root hash of the tree.
  //   other output fields are empty.
  virtual TPM_RC PinWeaverStartBiometricsAuth(
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
      std::string* mac_out) = 0;

  // Blocks future PinWeaverGenerateBiometricsAuthPk commands at server side
  // until the server restarts (normally a GSC reboot).
  // On success:
  //   returns VENDOR_RC_SUCCESS
  //   |result_code| is set to EC_SUCCESS (0).
  //   |root_hash| is set to the unchanged root hash of the tree.
  // On error:
  //   returns VENDOR_RC_SUCCESS
  //   |result_code| is set to one of pw_error_codes_enum.
  //   |root_hash| is set to the unchanged root hash of the tree.
  virtual TPM_RC PinWeaverBlockGenerateBiometricsAuthPk(
      uint8_t protocol_version,
      uint32_t* result_code,
      std::string* root_hash) = 0;

  // Generates a U2F credential, where:
  //   |version| is the version of the generated |key_handle|.
  //   |app_id| is the identifier of the relying party requesting the credential
  //       generation, which is often the domain name or its hash.
  //   |user_secret| is a secret provided from userland to the TPM, to separate
  //       access to credentials of different users on the same device.
  //   |consume| is whether user presence should be consumed (usually meaning
  //       the power button touch state is reset) after processing this command.
  //   |up_required| is whether user presence is required (usually meaning the
  //       the power button is touched recently) to process this command.
  //   |auth_time_secret_hash| is a hash used for checking user verification
  //       during signing time, and should be non-null iff |version| > 0.
  // On success:
  //   returns VENDOR_RC_SUCCESS
  //   |public_key| is set to the public key of the generated credential.
  //   |key_handle| is set to the key handle of the generated credential. This
  //       contains no sensitive data.
  virtual TPM_RC U2fGenerate(
      uint8_t version,
      const brillo::Blob& app_id,
      const brillo::SecureBlob& user_secret,
      bool consume,
      bool up_required,
      const std::optional<brillo::Blob>& auth_time_secret_hash,
      brillo::Blob* public_key,
      brillo::Blob* key_handle) = 0;

  // Signs a hash using a U2F credential, where:
  //   |version| is the version of |key_handle|.
  //   |app_id| is the identifier of the relying party requesting the signature,
  //       which is often the domain name or its hash.
  //   |user_secret| is a secret provided from userland to the TPM, to separate
  //       access to credentials of different users on the same device.
  //   |auth_time_secret| is a secret used for checking user verification, and
  //       shouldn't be provided if |version| = 0.
  //   |hash_to_sign| is the hash to sign, and should be provided iff
  //       |check_only| is false.
  //   |check_only| is whether the caller only wants to check for validity of
  //       the key handle, instead of signing anything.
  //   |consume| is whether user presence should be consumed (usually
  //       meaning the power button touch state is reset) after processing this
  //       command.
  //   |up_required| is whether user presence is required (usually meaning the
  //       the power button is touched recently) to process this command.
  //   |key_handle| is the key handle of the credential to sign the hash with.
  // On success:
  //   returns VENDOR_RC_SUCCESS
  //   |sig_r| and |sig_s| are set to the the r/s fields of the ECDSA signature.
  virtual TPM_RC U2fSign(
      uint8_t version,
      const brillo::Blob& app_id,
      const brillo::SecureBlob& user_secret,
      const std::optional<brillo::SecureBlob>& auth_time_secret,
      const std::optional<brillo::Blob>& hash_to_sign,
      bool check_only,
      bool consume,
      bool up_required,
      const brillo::Blob& key_handle,
      brillo::Blob* sig_r,
      brillo::Blob* sig_s) = 0;

  // Attests a U2F credential using the TPM's G2F key, where:
  //   |user_secret| is a secret provided from userland to the TPM, to separate
  //       access to credentials of different users on the same device.
  //   |format| is the format of |data|, the attestation message.
  // On success:
  //   returns VENDOR_RC_SUCCESS
  //   |sig_r| and |sig_s| are set to the the r/s fields of the ECDSA signature.
  virtual TPM_RC U2fAttest(const brillo::SecureBlob& user_secret,
                           uint8_t format,
                           const brillo::Blob& data,
                           brillo::Blob* sig_r,
                           brillo::Blob* sig_s) = 0;

  // Retrieves cached RSU device id.
  virtual TPM_RC GetRsuDeviceId(std::string* device_id) = 0;

  virtual TPM_RC GetRoVerificationStatus(ap_ro_status* status) = 0;

  // Returns true for TPMs running GSC.
  virtual bool IsGsc() = 0;

  // Send an arbitrary command to the TPM and wait for the response.
  // Returns the response packet.
  virtual std::string SendCommandAndWait(const std::string& command) = 0;

  // This method creates an RSA/ECC decryption key to be used for salting
  // sessions.
  virtual TPM_RC CreateSaltingKey(TPM_HANDLE* key, TPM2B_NAME* key_name) = 0;

  // Get Ti50 metrics: filesystem init time, filesystem size, AP RO verification
  // time, and AP RO verifiction status.
  virtual TPM_RC GetTi50Stats(uint32_t* fs_init_time,
                              uint32_t* fs_size,
                              uint32_t* aprov_time,
                              uint32_t* aprov_status) = 0;
};

}  // namespace trunks

#endif  // TRUNKS_TPM_UTILITY_H_
