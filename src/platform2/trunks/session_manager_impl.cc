// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/session_manager_impl.h"

#include <iterator>
#include <memory>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/secure_blob.h>
#include <crypto/openssl_util.h>
#include <crypto/libcrypto-compat.h>
#include <crypto/scoped_openssl_types.h>
#include <libhwsec-foundation/utility/crypto.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#if defined(OPENSSL_IS_BORINGSSL)
#include <openssl/mem.h>
#endif
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include "trunks/error_codes.h"
#include "trunks/openssl_utility.h"
#include "trunks/tpm_constants.h"
#include "trunks/tpm_generated.h"
#include "trunks/tpm_utility.h"

namespace {

constexpr size_t kWellKnownExponent = 0x10001;

// The required attributes for the salting key.
constexpr uint32_t kGoodSaltingKeyAttribute = trunks::kSensitiveDataOrigin |
                                              trunks::kUserWithAuth |
                                              trunks::kNoDA | trunks::kDecrypt;

// The label constant for RSAES-OAEP and ECDH session secret generation, defined
// in the TPM 2.0 specs, Part 1, Annex B.10.2 and C.6.2.
constexpr char kSessionKeyLabelValue[] = "SECRET\0";
constexpr size_t kSessionKeyLabelLength = sizeof(kSessionKeyLabelValue) - 1;

constexpr size_t kSessionSecretSize = SHA256_DIGEST_SIZE;

// Curve ID of the ECC salting key, used in OpenSSL and equivalent to
// TPM_ECC_NIST_P256 in TPM2.
constexpr int kEccCurveID = NID_X9_62_prime256v1;

// Retry limit of ECDH ECC point generation and Z point computation.
constexpr int kEcdhKeyGenRetryLimit = 3;
static_assert(kEcdhKeyGenRetryLimit > 0,
              "ECDH keygen retry limit should be greater than 0.");

// Generates an ephemeral ECC key pair and stores the public part in
// |ephemeral_point|. Computes the Z point and stores it in |z_point|, using
// the public part of salting key, |salting_key_pub|, and the ephemeral ECC
// key. |ephemeral_point| and |z_point| can be used to create a secure ECDH
// channel. Returns if all operations succeeded.
//
// Check the TPM 2.0 specs Part 1, Annex C.6.1 for the definition of Z point.
bool GenerateEcdhKeys(const trunks::TPMS_ECC_POINT& salting_key_pub,
                      trunks::TPMS_ECC_POINT* ephemeral_point,
                      trunks::TPMS_ECC_POINT* z_point) {
  crypto::ScopedEC_KEY ephemeral_key(EC_KEY_new_by_curve_name(kEccCurveID));
  if (!ephemeral_key.get()) {
    LOG(ERROR) << "Failed to create an ephemeral ECC key object: "
               << hwsec_foundation::utility::GetOpensslError();
    return false;
  }
  if (!EC_KEY_generate_key(ephemeral_key.get())) {
    LOG(ERROR) << "Failed to generate an ephemeral ECC key: "
               << hwsec_foundation::utility::GetOpensslError();
    return false;
  }

  const EC_POINT* ephemeral_key_pub =
      EC_KEY_get0_public_key(ephemeral_key.get());
  const BIGNUM* ephemeral_key_pri =
      EC_KEY_get0_private_key(ephemeral_key.get());

  const crypto::ScopedEC_GROUP ec_group(
      EC_GROUP_new_by_curve_name(kEccCurveID));
  if (!ec_group.get()) {
    LOG(ERROR) << "Failed to generate EC_GROUP for the "
               << "ephemeral key and z point: "
               << hwsec_foundation::utility::GetOpensslError();
    return false;
  }

  crypto::ScopedEC_POINT z_ec_point(EC_POINT_new(ec_group.get()));
  crypto::ScopedEC_POINT salting_key_ec_point(EC_POINT_new(ec_group.get()));
  if (!TpmToOpensslEccPoint(salting_key_pub, *ec_group.get(),
                            salting_key_ec_point.get())) {
    LOG(ERROR) << "Failed to get EC_POINT for the ECC salting key.";
    return false;
  }

  if (!EC_POINT_mul(ec_group.get(), z_ec_point.get(),
                    nullptr /* unused multiplier */, salting_key_ec_point.get(),
                    ephemeral_key_pri, nullptr /* unused context */)) {
    LOG(ERROR) << "Failed to compute the Z point.";
    return false;
  }

  if (EC_POINT_is_at_infinity(ec_group.get(), z_ec_point.get())) {
    // There is a small chance that the product Z is the infinity point. Returns
    // false here and the caller may try again.
    LOG(WARNING) << "The Z point is at infinity. Need to try again.";
    return false;
  }

  if (!OpensslToTpmEccPoint(*ec_group.get(), *ephemeral_key_pub,
                            trunks::kEccKeySize, ephemeral_point)) {
    LOG(ERROR) << "Failed to convert the ephemeral key.";
    return false;
  }

  if (!OpensslToTpmEccPoint(*ec_group.get(), *z_ec_point.get(),
                            trunks::kEccKeySize, z_point)) {
    LOG(ERROR) << "Failed to convert the Z point.";
    return false;
  }

  return true;
}

// Generates a plaintext |salt| and encrypts the salt using TPM's RSA salting
// key |public_area| with PKCS1_OAEP padding. The encrypted salt is stored in
// |encrypted_salt|. The salt generation and encryption follows the TPM 2.0
// specs Part 1, Annex B.10.2. The pointers |salt| and |encrypted_salt| must
// be initialized first. Returns TPM_RC_SUCCESS on success or other values on
// an error.
//
// Currently only supports RSA-2048, and the generated |salt| will be 256-bit
// long.
trunks::TPM_RC GenerateRsaSessionSalt(const trunks::TPMT_PUBLIC& public_area,
                                      brillo::SecureBlob* salt,
                                      std::string* encrypted_salt) {
  const uint16_t rsa_key_size = public_area.unique.rsa.size;
  if (rsa_key_size != 256) {
    LOG(ERROR) << "Invalid RSA salting key length: "
               << public_area.unique.rsa.size;
    return trunks::TRUNKS_RC_SESSION_SETUP_ERROR;
  }

  *salt = hwsec_foundation::utility::CreateSecureRandomBlob(kSessionSecretSize);
  if (salt->size() != kSessionSecretSize) {
    LOG(ERROR) << "Error generating a cryptographically random salt.";
    return trunks::TRUNKS_RC_SESSION_SETUP_ERROR;
  }

  crypto::ScopedRSA salting_key_rsa(RSA_new());
  crypto::ScopedBIGNUM n(BN_new()), e(BN_new());
  if (!salting_key_rsa || !n || !e) {
    LOG(ERROR) << "Failed to allocate RSA or BIGNUM: "
               << hwsec_foundation::utility::GetOpensslError();
    return trunks::TRUNKS_RC_SESSION_SETUP_ERROR;
  }

  if (!BN_set_word(e.get(), kWellKnownExponent) ||
      !BN_bin2bn(public_area.unique.rsa.buffer, rsa_key_size, n.get())) {
    LOG(ERROR) << "Error setting public area of rsa key: "
               << hwsec_foundation::utility::GetOpensslError();
    return trunks::TRUNKS_RC_SESSION_SETUP_ERROR;
  }
  if (!RSA_set0_key(salting_key_rsa.get(), n.release(), e.release(), nullptr)) {
    LOG(ERROR) << "Failed to set exponent or modulus.";
    return trunks::TRUNKS_RC_SESSION_SETUP_ERROR;
  }

  crypto::ScopedEVP_PKEY salting_key(EVP_PKEY_new());
  if (!salting_key) {
    LOG(ERROR) << "Failed to allocate EVP_PKEY: "
               << hwsec_foundation::utility::GetOpensslError();
    return trunks::TRUNKS_RC_SESSION_SETUP_ERROR;
  }
  if (!EVP_PKEY_set1_RSA(salting_key.get(), salting_key_rsa.get())) {
    LOG(ERROR) << "Error setting up EVP_PKEY: "
               << hwsec_foundation::utility::GetOpensslError();
    return trunks::TRUNKS_RC_SESSION_SETUP_ERROR;
  }

  // EVP_PKEY_CTX_set0_rsa_oaep_label takes ownership so we need to malloc.
  uint8_t* oaep_label =
      static_cast<uint8_t*>(OPENSSL_malloc(kSessionKeyLabelLength));
  memcpy(oaep_label, kSessionKeyLabelValue, kSessionKeyLabelLength);
  crypto::ScopedEVP_PKEY_CTX salt_encrypt_context(
      EVP_PKEY_CTX_new(salting_key.get(), nullptr));
  if (!salt_encrypt_context ||
      !EVP_PKEY_encrypt_init(salt_encrypt_context.get()) ||
      !EVP_PKEY_CTX_set_rsa_padding(salt_encrypt_context.get(),
                                    RSA_PKCS1_OAEP_PADDING) ||
      !EVP_PKEY_CTX_set_rsa_oaep_md(salt_encrypt_context.get(), EVP_sha256()) ||
      !EVP_PKEY_CTX_set_rsa_mgf1_md(salt_encrypt_context.get(), EVP_sha256()) ||
      !EVP_PKEY_CTX_set0_rsa_oaep_label(salt_encrypt_context.get(), oaep_label,
                                        kSessionKeyLabelLength)) {
    LOG(ERROR) << "Error setting up salt encrypt context: "
               << hwsec_foundation::utility::GetOpensslError();
    return trunks::TRUNKS_RC_SESSION_SETUP_ERROR;
  }
  size_t out_length = EVP_PKEY_size(salting_key.get());
  encrypted_salt->resize(out_length);
  if (!EVP_PKEY_encrypt(salt_encrypt_context.get(),
                        reinterpret_cast<uint8_t*>(std::data(*encrypted_salt)),
                        &out_length, salt->data(), salt->size())) {
    LOG(ERROR) << "Error encrypting salt: "
               << hwsec_foundation::utility::GetOpensslError();
    return trunks::TRUNKS_RC_SESSION_SETUP_ERROR;
  }
  encrypted_salt->resize(out_length);
  return trunks::TPM_RC_SUCCESS;
}

// Generates an ephemeral ECC key, serializes its public part, and stores it
// in |serialized_ephemeral_point|. The serialized public part is treated as
// the "encryptedSalt" in the TPM command TPM2_StartAuthSession() (TPM 2.0
// specs Part 3, Section 11.1.1). Also, follows the specs Part 1, Section
// 11.4.9.3 and Annex C.6.1 and C.6.2 and use the salting key |public_area| to
// compute |seed|. The seed is used as a session secret, similar to "salt" in
// RSA-encrypted sessions. The pointers |serialized_ephemeral_point| and
// |seed| must be initialized first. Returns TPM_RC_SUCCESS on success or
// other values on an error.
//
// The TPM will be able to recover the session secret, seed, from the
// ephemeral public point and the private part of the salting key.
trunks::TPM_RC GenerateEccSessionSalt(const trunks::TPMT_PUBLIC& public_area,
                                      brillo::SecureBlob* seed,
                                      std::string* serialized_ephemeral_point) {
  if (public_area.name_alg != trunks::TPM_ALG_SHA256 ||
      public_area.unique.ecc.x.size != trunks::kEccKeySize ||
      public_area.unique.ecc.y.size != trunks::kEccKeySize) {
    LOG(ERROR) << "Invalid ECC salting key attributes.";
    return trunks::TRUNKS_RC_SESSION_SETUP_ERROR;
  }

  // Generates an ephemeral key pair, computes Z point from the private
  // ephemeral key and TPM's public salting key, and gets the public ephemeral
  // point and Z point.
  const trunks::TPMS_ECC_POINT& salting_key_pub_point = public_area.unique.ecc;
  trunks::TPMS_ECC_POINT ephemeral_point;
  trunks::TPMS_ECC_POINT z_point;

  for (int try_count = 0; try_count < kEcdhKeyGenRetryLimit; ++try_count) {
    if (GenerateEcdhKeys(salting_key_pub_point, &ephemeral_point, &z_point)) {
      break;
    }

    if (try_count == kEcdhKeyGenRetryLimit - 1) {
      LOG(ERROR) << "Couldn't generate ECC points for ECDH session after "
                 << kEcdhKeyGenRetryLimit << " attempts. Giving up.";
      return trunks::TRUNKS_RC_SESSION_SETUP_ERROR;
    }

    LOG(WARNING) << "Error generating ECC points for ECDH session. "
                    "Trying again...";
  }

  trunks::TPM_RC result =
      Serialize_TPMS_ECC_POINT(ephemeral_point, serialized_ephemeral_point);
  if (result != trunks::TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error serializing initiator's public point: "
               << trunks::GetErrorString(result);
    return result;
  }

  // Follows TPM 2.0 specs Part 1, Annex C.6.1 and computes the session secret,
  // seed, using a KDFe. Part 4, Section 10.2.13.8.3 shows an example of generic
  // KDFe implementation. That implementation is ported and simplified below. We
  // assume the hash algorithm to be SHA-256, as specified in the salting key's
  // public_area.name_alg. Its digest length equals the seed length, so we only
  // need to run the hashes for one iteration.

  // Big-Endian 32-bit 1.
  uint8_t marshaled_counter[4] = {0, 0, 0, 1};
  const trunks::TPM2B_ECC_PARAMETER& z_value = z_point.x;
  const trunks::TPM2B_ECC_PARAMETER& party_u_info = ephemeral_point.x;
  const trunks::TPM2B_ECC_PARAMETER& party_v_info = salting_key_pub_point.x;

  seed->resize(kSessionSecretSize);

  crypto::ScopedEVP_MD_CTX ctx(EVP_MD_CTX_new());
  const EVP_MD* digest_type = EVP_sha256();
  unsigned int final_seed_size = 0;
  if (!EVP_DigestInit(ctx.get(), digest_type) ||
      !EVP_DigestUpdate(ctx.get(), marshaled_counter,
                        std::size(marshaled_counter)) ||
      !EVP_DigestUpdate(ctx.get(), z_value.buffer, z_value.size) ||
      !EVP_DigestUpdate(ctx.get(), kSessionKeyLabelValue,
                        kSessionKeyLabelLength) ||
      !EVP_DigestUpdate(ctx.get(), party_u_info.buffer, party_u_info.size) ||
      !EVP_DigestUpdate(ctx.get(), party_v_info.buffer, party_v_info.size) ||
      !EVP_DigestFinal(ctx.get(),
                       reinterpret_cast<unsigned char*>(seed->data()),
                       &final_seed_size) ||
      final_seed_size != seed->size()) {
    LOG(ERROR) << "Error creating a SHA-256 digest: "
               << hwsec_foundation::utility::GetOpensslError();
    return trunks::TRUNKS_RC_SESSION_SETUP_ERROR;
  }

  return trunks::TPM_RC_SUCCESS;
}

}  // namespace

namespace trunks {

SessionManagerImpl::SessionManagerImpl(const TrunksFactory& factory)
    : factory_(factory),
      session_handle_(kUninitializedHandle),
      temp_salting_key_(factory) {
  crypto::EnsureOpenSSLInit();
}

SessionManagerImpl::~SessionManagerImpl() {
  CloseSession();
}

void SessionManagerImpl::CloseSession() {
  if (session_handle_ == kUninitializedHandle) {
    return;
  }
  TPM_RC result = factory_.GetTpm()->FlushContextSync(session_handle_, nullptr);
  if (result != TPM_RC_SUCCESS) {
    LOG(WARNING) << "Error closing tpm session: " << GetErrorString(result);
  }
  session_handle_ = kUninitializedHandle;
}

TPM_RC SessionManagerImpl::StartSession(
    TPM_SE session_type,
    TPMI_DH_ENTITY bind_entity,
    const std::string& bind_authorization_value,
    bool salted,
    bool enable_encryption,
    HmacAuthorizationDelegate* delegate) {
  CHECK(delegate);
  // If we already have an active session, close it.
  CloseSession();

  brillo::SecureBlob salt;
  std::string encrypted_salt;
  TPMI_DH_OBJECT tpm_key = TPM_RH_NULL;

  if (salted) {
    TPM_RC salt_result = GenerateSessionSalt(&tpm_key, &salt, &encrypted_salt);
    if (salt_result != TPM_RC_SUCCESS) {
      LOG(ERROR) << "Error creating session secret: "
                 << GetErrorString(salt_result);
      return salt_result;
    }
  }

  TPM2B_ENCRYPTED_SECRET encrypted_secret =
      Make_TPM2B_ENCRYPTED_SECRET(encrypted_salt);

  TPMI_ALG_HASH hash_algorithm = TPM_ALG_SHA256;
  TPMT_SYM_DEF symmetric_algorithm;
  if (enable_encryption) {
    symmetric_algorithm.algorithm = TPM_ALG_AES;
    symmetric_algorithm.key_bits.aes = 128;
    symmetric_algorithm.mode.aes = TPM_ALG_CFB;
  } else {
    symmetric_algorithm.algorithm = TPM_ALG_NULL;
  }

  TPM2B_NONCE nonce_caller;
  TPM2B_NONCE nonce_tpm;
  // We use sha1_digest_size here because that is the minimum length
  // needed for the nonce.
  nonce_caller.size = SHA1_DIGEST_SIZE;
  CHECK_EQ(RAND_bytes(nonce_caller.buffer, nonce_caller.size), 1)
      << "Error generating a cryptographically random nonce.";

  Tpm* tpm = factory_.GetTpm();
  // Then we use TPM2_StartAuthSession to start a session with the TPM.
  // The TPM returns the tpm_nonce and the session_handle referencing the
  // created session.
  // The TPM2 command below needs no authorization. This is why we can use
  // the empty string "", when referring to the handle names for the salting
  // key and the bind entity.
  TPM_RC tpm_result = tpm->StartAuthSessionSync(
      tpm_key,
      "",  // salt_handle_name.
      bind_entity,
      "",  // bind_entity_name.
      nonce_caller, encrypted_secret, session_type, symmetric_algorithm,
      hash_algorithm, &session_handle_, &nonce_tpm,
      nullptr);  // No Authorization.
  if (tpm_result) {
    LOG(ERROR) << "Error creating an authorization session: "
               << GetErrorString(tpm_result);
    return tpm_result;
  }
  bool hmac_result = delegate->InitSession(
      session_handle_, nonce_tpm, nonce_caller, salt.to_string(),
      bind_authorization_value, enable_encryption);
  if (!hmac_result) {
    LOG(ERROR) << "Failed to initialize an authorization session delegate.";
    return TPM_RC_FAILURE;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC SessionManagerImpl::GenerateSessionSalt(TPMI_DH_OBJECT* tpm_key,
                                               brillo::SecureBlob* salt,
                                               std::string* encrypted_salt) {
  TPM2B_PUBLIC public_data;
  TPMT_PUBLIC& public_area = public_data.public_area;

  if (!temp_salting_key_.get()) {
    *tpm_key = kSaltingKey;
    TPM_RC result =
        factory_.GetTpmCache()->GetSaltingKeyPublicArea(&public_area);

    bool shall_create_temp_salting_key = false;
    if (GetFormatOneError(result) == TPM_RC_HANDLE) {
      LOG(WARNING) << "No valid salting key.";
      shall_create_temp_salting_key = true;
    } else if (result != TPM_RC_SUCCESS) {
      LOG(ERROR) << "Error fetching salting key public info: "
                 << GetErrorString(result);
      return result;
    } else if ((public_area.object_attributes & kGoodSaltingKeyAttribute) !=
               kGoodSaltingKeyAttribute) {
      LOG(WARNING) << "The salting key doesn't have correct attributes.";
      shall_create_temp_salting_key = true;
    }

    if (shall_create_temp_salting_key) {
      result = CreateTempSaltingKey();
      if (result != TPM_RC_SUCCESS) {
        LOG(ERROR) << "Error creating temp salting key: "
                   << GetErrorString(result);
        return result;
      }
    }
  }

  if (temp_salting_key_.get() && temp_salting_key_public_data_.has_value()) {
    *tpm_key = temp_salting_key_.get();
    public_data = temp_salting_key_public_data_.value();
  }

  const TPMI_ALG_PUBLIC& salting_key_type = public_area.type;

  TPM_RC result;

  if (salting_key_type == TPM_ALG_RSA) {
    result = GenerateRsaSessionSalt(public_area, salt, encrypted_salt);
  } else if (salting_key_type == TPM_ALG_ECC) {
    result = GenerateEccSessionSalt(public_area, salt, encrypted_salt);
  } else {
    LOG(ERROR) << "Unsupported salting key type: " << salting_key_type;
    return TRUNKS_RC_SESSION_SETUP_ERROR;
  }

  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error generating a session salt: " << GetErrorString(result);
    return result;
  }

  return TPM_RC_SUCCESS;
}

TPM_RC SessionManagerImpl::CreateTempSaltingKey() {
  TPM_HANDLE key_handle;
  TPM2B_NAME key_name;
  std::unique_ptr<TpmUtility> utility = factory_.GetTpmUtility();
  TPM_RC result = utility->CreateSaltingKey(&key_handle, &key_name);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error creating temp salting key: "
               << GetErrorString(result);
    return result;
  }

  temp_salting_key_.reset(key_handle);

  TPM2B_PUBLIC public_data;
  TPM2B_NAME unused_out_name;
  TPM2B_NAME unused_qualified_name;
  result = factory_.GetTpm()->ReadPublicSync(
      key_handle, /*object_handle_name=*/"", &public_data, &unused_out_name,
      &unused_qualified_name,
      /*authorization_delegate=*/nullptr);

  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error fetching temp salting key public info: "
               << GetErrorString(result);
    return result;
  }

  temp_salting_key_public_data_ = std::move(public_data);

  return TPM_RC_SUCCESS;
}

}  // namespace trunks
