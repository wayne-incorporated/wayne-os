// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chaps/session_impl.h"

#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <brillo/secure_blob.h>
#include <crypto/libcrypto-compat.h>
#include <crypto/scoped_openssl_types.h>
#include <libhwsec/frontend/chaps/frontend.h>
#include <libhwsec-foundation/status/status_chain_macros.h>
#include <openssl/bio.h>
#include <openssl/des.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>

#include "chaps/chaps.h"
#include "chaps/chaps_factory.h"
#include "chaps/chaps_utility.h"
#include "chaps/object.h"
#include "chaps/object_pool.h"
#include "pkcs11/cryptoki.h"

using brillo::SecureBlob;
using hwsec::TPMError;
using hwsec_foundation::status::MakeStatus;
using ScopedASN1_OCTET_STRING =
    crypto::ScopedOpenSSL<ASN1_OCTET_STRING, ASN1_OCTET_STRING_free>;
using std::hex;
using std::map;
using std::set;
using std::string;
using std::vector;

using AllowSoftwareGen = hwsec::ChapsFrontend::AllowSoftwareGen;
using AllowDecrypt = hwsec::ChapsFrontend::AllowDecrypt;
using AllowSign = hwsec::ChapsFrontend::AllowSign;

namespace chaps {

namespace {

using chaps::OperationType::kDecrypt;
using chaps::OperationType::kDigest;
using chaps::OperationType::kEncrypt;
using chaps::OperationType::kSign;
using chaps::OperationType::kVerify;

const int kDefaultAuthDataBytes = 20;
const int kMaxCipherBlockBytes = 16;
const int kMaxRSAOutputBytes = 2048;
const int kMaxDigestOutputBytes = EVP_MAX_MD_SIZE;
const int kMinRSAKeyBits = 512;
const int kMaxRSAKeyBits = kMaxRSAOutputBytes * 8;

string GenerateRandomSoftware(int num_bytes) {
  string random(num_bytes, 0);
  RAND_bytes(ConvertStringToByteBuffer(random.data()), num_bytes);
  return random;
}

brillo::SecureBlob GenerateRandomSecureBlobSoftware(int num_bytes) {
  brillo::SecureBlob random(num_bytes);
  RAND_bytes(random.data(), num_bytes);
  return random;
}

CK_RV ResultToRV(chaps::ObjectPool::Result result, CK_RV fail_rv) {
  switch (result) {
    case chaps::ObjectPool::Result::Success:
      return CKR_OK;
    case chaps::ObjectPool::Result::Failure:
      return fail_rv;
    case chaps::ObjectPool::Result::WaitForPrivateObjects:
      return CKR_WOULD_BLOCK_FOR_PRIVATE_OBJECTS;
  }
}

const char* OperationToString(OperationType operation) {
  switch (operation) {
    case kEncrypt:
      return "Encrypt";
    case kDecrypt:
      return "Decrypt";
    case kDigest:
      return "Digest";
    case kSign:
      return "Sign";
    case kVerify:
      return "Verify";
    case kNumOperationTypes:
    default:
      return "Unknown";
  }
}

bool IsSuccess(chaps::ObjectPool::Result result) {
  return result == chaps::ObjectPool::Result::Success;
}

class MechanismInfo {
 public:
  explicit MechanismInfo(CK_MECHANISM_TYPE mechanism);
  bool IsSupported() const;
  bool IsOperationValid(chaps::OperationType op) const;
  bool IsForKeyType(CK_KEY_TYPE keytype) const;

 private:
  struct MechanismInfoData {
    bool is_supported;
    set<chaps::OperationType> operation;
    CK_KEY_TYPE key_type;
  };

  static MechanismInfoData GetSupportedMechanismInfo(
      CK_MECHANISM_TYPE mechanism);

  MechanismInfoData data_;
};

MechanismInfo::MechanismInfo(CK_MECHANISM_TYPE mechanism)
    : data_(GetSupportedMechanismInfo(mechanism)) {}

bool MechanismInfo::IsSupported() const {
  return data_.is_supported;
}

bool MechanismInfo::IsOperationValid(chaps::OperationType op) const {
  return IsSupported() && data_.operation.count(op) > 0;
}

bool MechanismInfo::IsForKeyType(CK_KEY_TYPE keytype) const {
  return IsSupported() && data_.key_type == keytype;
}

MechanismInfo::MechanismInfoData MechanismInfo::GetSupportedMechanismInfo(
    CK_MECHANISM_TYPE mechanism) {
  switch (mechanism) {
    // DES
    case CKM_DES_ECB:
    case CKM_DES_CBC:
    case CKM_DES_CBC_PAD:
      return {true, {kEncrypt, kDecrypt}, CKK_DES};

    // DES3
    case CKM_DES3_ECB:
    case CKM_DES3_CBC:
    case CKM_DES3_CBC_PAD:
      return {true, {kEncrypt, kDecrypt}, CKK_DES3};

    // AES
    case CKM_AES_ECB:
    case CKM_AES_CBC:
    case CKM_AES_CBC_PAD:
      return {true, {kEncrypt, kDecrypt}, CKK_AES};

    // RSA PKCS v1.5
    case CKM_RSA_PKCS:
      return {true, {kEncrypt, kDecrypt, kSign, kVerify}, CKK_RSA};
    case CKM_MD5_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
      return {true, {kSign, kVerify}, CKK_RSA};

    // RSA RSS
    case CKM_RSA_PKCS_PSS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
    case CKM_SHA224_RSA_PKCS_PSS:
      return {true, {kSign, kVerify}, CKK_RSA};

    // ECC
    case CKM_ECDSA:
    case CKM_ECDSA_SHA1:
    case CKM_ECDSA_SHA256:
    case CKM_ECDSA_SHA384:
    case CKM_ECDSA_SHA512:
      return {true, {kSign, kVerify}, CKK_EC};

    // HMAC
    case CKM_MD5_HMAC:
    case CKM_SHA_1_HMAC:
    case CKM_SHA256_HMAC:
    case CKM_SHA384_HMAC:
    case CKM_SHA512_HMAC:
      return {true, {kSign, kVerify}, CKK_GENERIC_SECRET};

    // Digest
    case CKM_MD5:
    case CKM_SHA_1:
    case CKM_SHA256:
    case CKM_SHA384:
    case CKM_SHA512:
      return {true, {kDigest}, CKK_INVALID_KEY_TYPE};

    default:
      return {false, {}, CKK_INVALID_KEY_TYPE};
  }
}

bool IsHMAC(CK_MECHANISM_TYPE mechanism) {
  return MechanismInfo(mechanism).IsForKeyType(CKK_GENERIC_SECRET);
}

// Returns true if the given block cipher (AES/DES) mechanism uses padding.
bool IsPaddingEnabled(CK_MECHANISM_TYPE mechanism) {
  switch (mechanism) {
    case CKM_DES_CBC_PAD:
    case CKM_DES3_CBC_PAD:
    case CKM_AES_CBC_PAD:
      return true;

    default:
      return false;
  }
}

bool IsRSA(CK_MECHANISM_TYPE mechanism) {
  return MechanismInfo(mechanism).IsForKeyType(CKK_RSA);
}

bool IsECC(CK_MECHANISM_TYPE mechanism) {
  return MechanismInfo(mechanism).IsForKeyType(CKK_EC);
}

bool IsMechanismValidForOperation(chaps::OperationType operation,
                                  CK_MECHANISM_TYPE mechanism) {
  return MechanismInfo(mechanism).IsOperationValid(operation);
}

CK_OBJECT_CLASS GetExpectedObjectClass(chaps::OperationType operation,
                                       CK_KEY_TYPE key_type) {
  bool use_private_key = operation == kSign || operation == kDecrypt;
  switch (key_type) {
    case CKK_DES:
    case CKK_DES3:
    case CKK_AES:
      return CKO_SECRET_KEY;
    case CKK_RSA:
    case CKK_EC:
      return use_private_key ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
    case CKK_GENERIC_SECRET:
      return CKO_SECRET_KEY;

    default:
      // Never used
      NOTREACHED();
      return -1;
  }
}

// Check |object_class| and |key_type| is valid for |mechanism| and |operation|
bool IsValidKeyType(chaps::OperationType operation,
                    CK_MECHANISM_TYPE mechanism,
                    CK_OBJECT_CLASS object_class,
                    CK_KEY_TYPE key_type) {
  return MechanismInfo(mechanism).IsForKeyType(key_type) &&
         object_class == GetExpectedObjectClass(operation, key_type);
}

const EVP_CIPHER* GetOpenSSLCipher(CK_MECHANISM_TYPE mechanism,
                                   size_t key_size) {
  switch (mechanism) {
    case CKM_DES_ECB:
      return EVP_des_ecb();
    case CKM_DES_CBC:
    case CKM_DES_CBC_PAD:
      return EVP_des_cbc();
    case CKM_DES3_ECB:
      return EVP_des_ede3();
    case CKM_DES3_CBC:
    case CKM_DES3_CBC_PAD:
      return EVP_des_ede3_cbc();
    case CKM_AES_ECB:
      switch (key_size) {
        case 16:
          return EVP_aes_128_ecb();
        case 24:
          return EVP_aes_192_ecb();
        default:
          return EVP_aes_256_ecb();
      }
      break;
    case CKM_AES_CBC:
    case CKM_AES_CBC_PAD:
      switch (key_size) {
        case 16:
          return EVP_aes_128_cbc();
        case 24:
          return EVP_aes_192_cbc();
        default:
          return EVP_aes_256_cbc();
      }
      break;
  }
  return nullptr;
}

string GetDERDigestInfo(CK_MECHANISM_TYPE mechanism) {
  return GetDigestAlgorithmEncoding(chaps::GetDigestAlgorithm(mechanism));
}

// TODO(menghuan): Move Create*KeyFromObject to the member function of object.
crypto::ScopedEC_KEY CreateECCPublicKeyFromObject(const Object* key_object) {
  // Start parsing EC_PARAMS
  string ec_params = key_object->GetAttributeString(CKA_EC_PARAMS);
  crypto::ScopedEC_KEY key = chaps::CreateECCKeyFromEC_PARAMS(ec_params);
  if (key == nullptr)
    return nullptr;

  // Start parsing EC_POINT
  // DER decode EC_POINT to OCT_STRING
  string pub_data = key_object->GetAttributeString(CKA_EC_POINT);
  const unsigned char* buf = chaps::ConvertStringToByteBuffer(pub_data.data());
  ScopedASN1_OCTET_STRING os(
      d2i_ASN1_OCTET_STRING(nullptr, &buf, pub_data.size()));
  if (os == nullptr)
    return nullptr;

  // Convert OCT_STRING to *EC_KEY
  buf = os->data;
  EC_KEY* key_ptr = key.get();
  key_ptr = o2i_ECPublicKey(&key_ptr, &buf, os->length);
  if (key_ptr == nullptr)
    return nullptr;
  CHECK_EQ(key_ptr, key.get());

  if (!EC_KEY_check_key(key.get())) {
    LOG(ERROR) << __func__
               << ": Bad key created from object. OpenSSL key check fail.";
    return nullptr;
  }

  return key;
}

crypto::ScopedEC_KEY CreateECCPrivateKeyFromObject(const Object* key_object) {
  // Parse EC_PARAMS
  string ec_params = key_object->GetAttributeString(CKA_EC_PARAMS);
  crypto::ScopedEC_KEY key = chaps::CreateECCKeyFromEC_PARAMS(ec_params);
  if (key == nullptr)
    return nullptr;

  crypto::ScopedBIGNUM d(BN_new());
  if (!d) {
    LOG(ERROR) << "Failed to allocate BIGNUM.";
    return nullptr;
  }

  if (!chaps::ConvertToBIGNUM(key_object->GetAttributeString(CKA_VALUE),
                              d.get())) {
    LOG(ERROR) << "Failed to convert CKA_VALUE to BIGNUM.";
    return nullptr;
  }

  if (!EC_KEY_set_private_key(key.get(), d.get()))
    return nullptr;

  // OpenSSL will not set public key field. Need to manually compute.
  const EC_GROUP* group = EC_KEY_get0_group(key.get());
  if (group == nullptr)
    return nullptr;

  crypto::ScopedEC_POINT pub_key(EC_POINT_new(group));
  EC_POINT_mul(group, pub_key.get(), d.get(), nullptr, nullptr, nullptr);
  if (!EC_KEY_set_public_key(key.get(), pub_key.get()))
    return nullptr;

  if (!EC_KEY_check_key(key.get())) {
    LOG(ERROR) << __func__
               << ": Bad key created from object. OpenSSL key check fail.";
    return nullptr;
  }

  return key;
}

crypto::ScopedRSA CreateRSAKeyFromObject(const chaps::Object* key_object) {
  crypto::ScopedRSA rsa(RSA_new());
  if (!rsa) {
    LOG(ERROR) << "Failed to allocate RSA or BIGNUM for key.";
    return nullptr;
  }
  if (key_object->GetObjectClass() == CKO_PUBLIC_KEY) {
    crypto::ScopedBIGNUM rsa_n(BN_new()), rsa_e(BN_new());
    if (!rsa_n || !rsa_e) {
      LOG(ERROR) << "Failed to allocate RSA or BIGNUM for key.";
      return nullptr;
    }
    string n = key_object->GetAttributeString(CKA_MODULUS);
    string e = key_object->GetAttributeString(CKA_PUBLIC_EXPONENT);
    if (!chaps::ConvertToBIGNUM(n, rsa_n.get()) ||
        !chaps::ConvertToBIGNUM(e, rsa_e.get())) {
      LOG(ERROR) << "Failed to convert modulus or exponent for key.";
      return nullptr;
    }
    if (!RSA_set0_key(rsa.get(), rsa_n.release(), rsa_e.release(), nullptr)) {
      LOG(ERROR) << "Failed to set modulus or exponent for RSA.";
      return nullptr;
    }
  } else {  // key_object->GetObjectClass() == CKO_PRIVATE_KEY
    crypto::ScopedBIGNUM rsa_n(BN_new()), rsa_e(BN_new()), rsa_d(BN_new()),
        rsa_p(BN_new()), rsa_q(BN_new()), rsa_dmp1(BN_new()),
        rsa_dmq1(BN_new()), rsa_iqmp(BN_new());
    if (!rsa_n || !rsa_e || !rsa_d || !rsa_p || !rsa_q || !rsa_dmp1 ||
        !rsa_dmq1 || !rsa_iqmp) {
      LOG(ERROR) << "Failed to allocate BIGNUM for private key.";
      return nullptr;
    }
    string n = key_object->GetAttributeString(CKA_MODULUS);
    string e = key_object->GetAttributeString(CKA_PUBLIC_EXPONENT);
    string d = key_object->GetAttributeString(CKA_PRIVATE_EXPONENT);
    string p = key_object->GetAttributeString(CKA_PRIME_1);
    string q = key_object->GetAttributeString(CKA_PRIME_2);
    string dmp1 = key_object->GetAttributeString(CKA_EXPONENT_1);
    string dmq1 = key_object->GetAttributeString(CKA_EXPONENT_2);
    string iqmp = key_object->GetAttributeString(CKA_COEFFICIENT);
    if (!chaps::ConvertToBIGNUM(n, rsa_n.get()) ||
        !chaps::ConvertToBIGNUM(e, rsa_e.get()) ||
        !chaps::ConvertToBIGNUM(d, rsa_d.get()) ||
        !chaps::ConvertToBIGNUM(p, rsa_p.get()) ||
        !chaps::ConvertToBIGNUM(q, rsa_q.get()) ||
        !chaps::ConvertToBIGNUM(dmp1, rsa_dmp1.get()) ||
        !chaps::ConvertToBIGNUM(dmq1, rsa_dmq1.get()) ||
        !chaps::ConvertToBIGNUM(iqmp, rsa_iqmp.get())) {
      LOG(ERROR) << "Failed to convert parameters for private key.";
      return nullptr;
    }
    if (!RSA_set0_key(rsa.get(), rsa_n.release(), rsa_e.release(),
                      rsa_d.release()) ||
        !RSA_set0_factors(rsa.get(), rsa_p.release(), rsa_q.release()) ||
        !RSA_set0_crt_params(rsa.get(), rsa_dmp1.release(), rsa_dmq1.release(),
                             rsa_iqmp.release())) {
      LOG(ERROR) << "Failed to set parameters for private key RSA.";
      return nullptr;
    }
  }
  return rsa;
}

// TODO(crbug/916023): Move OpenSSL utility to cross daemon library.
// Return the length (in bytes) of group order of the EC key |key| or 0 on error
// which is aligned with OpenSSL design.
size_t GetGroupOrderLengthFromEcKey(const crypto::ScopedEC_KEY& key) {
  crypto::ScopedBIGNUM order(BN_new());
  if (!order) {
    LOG(ERROR) << "Failed to allocate BIGNUM for EC key order.";
    return 0;
  }

  const EC_GROUP* group = EC_KEY_get0_group(key.get());
  if (group == nullptr)
    return 0;

  if (!EC_GROUP_get_order(group, order.get(), nullptr))
    return 0;

  return BN_num_bytes(order.get());
}

// RSA Sign/Verify Helper
class RSASignerVerifier {
 public:
  // Just a default destructor, nothing more, nothing less.
  // Note: It's here because this is a base class, and we want to avoid having
  // non-virtual destructor in base class.
  virtual ~RSASignerVerifier() = default;

  // Sign |context->data_| with |rsa|.
  virtual bool Sign(crypto::ScopedRSA rsa,
                    SessionImpl::OperationContext* context) = 0;

  // Verify |signature| of |digest| against |rsa|.
  virtual CK_RV Verify(crypto::ScopedRSA rsa,
                       SessionImpl::OperationContext* context,
                       const string& digest,
                       const string& signature) = 0;

  static std::unique_ptr<RSASignerVerifier> GetForMechanism(
      CK_MECHANISM_TYPE mechanism);
};

// Sign/Verify helper for PKCS#1 v1.5
class RSASignerVerifierImplPKCS115 : public RSASignerVerifier {
 public:
  virtual ~RSASignerVerifierImplPKCS115() = default;

  bool Sign(crypto::ScopedRSA rsa,
            SessionImpl::OperationContext* context) final {
    if (RSA_size(rsa.get()) > kMaxRSAOutputBytes) {
      LOG(ERROR) << __func__ << ": RSA Key size is too large for PKCS#1 v1.5.";
      return false;
    }
    uint8_t buffer[kMaxRSAOutputBytes];
    // Emulate RSASSA by performing raw RSA (decrypting) with RSA_PKCS1_PADDING
    string input = GetDERDigestInfo(context->mechanism_) + context->data_;
    int length = RSA_private_encrypt(
        input.length(), ConvertStringToByteBuffer(input.data()), buffer,
        rsa.get(), RSA_PKCS1_PADDING);  // Adds PKCS #1 type 1 padding.
    if (length == -1) {
      LOG(ERROR) << __func__ << ": RSA_private_encrypt failed for PKCS#1 v1.5: "
                 << GetOpenSSLError();
      return false;
    }
    // Set the signature in context->data_.
    context->data_ = string(reinterpret_cast<char*>(buffer), length);
    return true;
  };

  CK_RV Verify(crypto::ScopedRSA rsa,
               SessionImpl::OperationContext* context,
               const string& digest,
               const string& signature) final {
    if (RSA_size(rsa.get()) > kMaxRSAOutputBytes) {
      LOG(ERROR) << __func__ << ": RSA Key size is too large for PKCS#1 v1.5.";
      return CKR_KEY_SIZE_RANGE;
    }
    uint8_t buffer[kMaxRSAOutputBytes];

    int length = RSA_public_decrypt(
        signature.length(), ConvertStringToByteBuffer(signature.data()), buffer,
        rsa.get(), RSA_PKCS1_PADDING);  // Strips PKCS #1 type 1 padding.
    if (length == -1) {
      LOG(ERROR) << __func__ << ": RSA_public_decrypt failed for PKCS#1 v1.5: "
                 << GetOpenSSLError();
      return CKR_SIGNATURE_INVALID;
    }
    string signed_data = GetDERDigestInfo(context->mechanism_) + digest;
    if (static_cast<size_t>(length) != signed_data.length() ||
        0 != brillo::SecureMemcmp(buffer, signed_data.data(), length)) {
      return CKR_SIGNATURE_INVALID;
    }
    return CKR_OK;
  };
};

// Sign/Verify helper for RSA PSS
class RSASignerVerifierImplPSS : public RSASignerVerifier {
 public:
  virtual ~RSASignerVerifierImplPSS() = default;

  bool Sign(crypto::ScopedRSA rsa,
            SessionImpl::OperationContext* context) final {
    if (RSA_size(rsa.get()) > kMaxRSAOutputBytes) {
      LOG(ERROR) << __func__ << ": RSA Key size is too large for RSA PSS.";
      return false;
    }
    uint8_t buffer[kMaxRSAOutputBytes];
    DigestAlgorithm digest_algorithm = GetDigestAlgorithm(context->mechanism_);
    // Parse the RSA PSS Parameters.
    const CK_RSA_PKCS_PSS_PARAMS* pss_params = nullptr;
    const EVP_MD* mgf1_hash = nullptr;
    if (!ParseRSAPSSParams(context->parameter_, digest_algorithm, &pss_params,
                           &mgf1_hash, &digest_algorithm)) {
      LOG(ERROR) << __func__ << ": Failed to parse RSA PSS parameters.";
      return false;
    }

    string padded_data(RSA_size(rsa.get()), 0);
    if (RSA_padding_add_PKCS1_PSS_mgf1(
            rsa.get(), reinterpret_cast<unsigned char*>(std::data(padded_data)),
            reinterpret_cast<const unsigned char*>(std::data(context->data_)),
            GetOpenSSLDigest(digest_algorithm), mgf1_hash,
            pss_params->sLen) != 1) {
      LOG(ERROR) << __func__ << ": Failed to produce the PSA PSS paddings.";
      return false;
    }
    int length = RSA_private_encrypt(
        padded_data.length(), ConvertStringToByteBuffer(padded_data.data()),
        buffer, rsa.get(), RSA_NO_PADDING);
    if (length == -1) {
      LOG(ERROR) << __func__
                 << ": RSA_private_encrypt failed: " << GetOpenSSLError();
      return false;
    }
    // Set the signature in context->data_.
    context->data_ = string(reinterpret_cast<char*>(buffer), length);
    return true;
  };

  CK_RV Verify(crypto::ScopedRSA rsa,
               SessionImpl::OperationContext* context,
               const string& digest,
               const string& signature) final {
    if (RSA_size(rsa.get()) > kMaxRSAOutputBytes) {
      LOG(ERROR) << __func__ << ": RSA Key size is too large for RSA PSS.";
      return CKR_KEY_SIZE_RANGE;
    }

    DigestAlgorithm digest_algorithm = GetDigestAlgorithm(context->mechanism_);
    uint8_t buffer[kMaxRSAOutputBytes];

    // Parse the RSA PSS Parameters.
    const CK_RSA_PKCS_PSS_PARAMS* pss_params = nullptr;
    const EVP_MD* mgf1_hash = nullptr;
    if (!ParseRSAPSSParams(context->parameter_, digest_algorithm, &pss_params,
                           &mgf1_hash, &digest_algorithm)) {
      LOG(ERROR) << __func__ << ": Failed to parse RSA PSS parameters.";
      return CKR_SIGNATURE_INVALID;
    }

    int expected_size = EVP_MD_size(GetOpenSSLDigest(digest_algorithm));
    if (digest.size() != expected_size) {
      LOG(ERROR) << __func__ << ": Size mismatch with RSAPSS, expected "
                 << expected_size << ", actual " << digest.size();
      return CKR_SIGNATURE_INVALID;
    }

    int length = RSA_public_decrypt(signature.length(),
                                    ConvertStringToByteBuffer(signature.data()),
                                    buffer, rsa.get(), RSA_NO_PADDING);
    if (length == -1) {
      LOG(ERROR) << __func__
                 << ": RSA_public_decrypt failed: " << GetOpenSSLError();
      return CKR_SIGNATURE_INVALID;
    }
    if (RSA_verify_PKCS1_PSS_mgf1(
            rsa.get(), reinterpret_cast<const unsigned char*>(digest.data()),
            GetOpenSSLDigest(digest_algorithm), mgf1_hash, buffer,
            pss_params->sLen) != 1) {
      LOG(ERROR) << __func__ << ": Incorrect PSS padding.";
      return CKR_SIGNATURE_INVALID;
    }
    return CKR_OK;
  };
};

std::unique_ptr<RSASignerVerifier> RSASignerVerifier::GetForMechanism(
    CK_MECHANISM_TYPE mechanism) {
  auto scheme = GetSigningSchemeForMechanism(mechanism);
  switch (scheme) {
    case RsaPaddingScheme::RSASSA_PKCS1_V1_5:
      return std::make_unique<RSASignerVerifierImplPKCS115>();
    case RsaPaddingScheme::RSASSA_PSS:
      return std::make_unique<RSASignerVerifierImplPSS>();
    default:
      LOG(ERROR) << __func__ << ": Invalid mechanism "
                 << static_cast<int64_t>(mechanism);
      return nullptr;
  }
}

hwsec::DigestAlgorithm ChapsToHwsecDigestAlg(DigestAlgorithm alg) {
  switch (alg) {
    case DigestAlgorithm::MD5:
      return hwsec::DigestAlgorithm::kMd5;
    case DigestAlgorithm::SHA1:
      return hwsec::DigestAlgorithm::kSha1;
    case DigestAlgorithm::SHA256:
      return hwsec::DigestAlgorithm::kSha256;
    case DigestAlgorithm::SHA384:
      return hwsec::DigestAlgorithm::kSha384;
    case DigestAlgorithm::SHA512:
      return hwsec::DigestAlgorithm::kSha512;
    default:
      return hwsec::DigestAlgorithm::kNoDigest;
  }
}

std::optional<hwsec::SigningOptions::RsaPaddingScheme>
ChapsToHwsecRsaPaddingScheme(RsaPaddingScheme scheme) {
  switch (scheme) {
    case RsaPaddingScheme::RSASSA_PKCS1_V1_5:
      return hwsec::SigningOptions::RsaPaddingScheme::kPkcs1v15;
    case RsaPaddingScheme::RSASSA_PSS:
      return hwsec::SigningOptions::RsaPaddingScheme::kRsassaPss;
    default:
      return std::nullopt;
  }
}

hwsec::DigestAlgorithm GetHwsecDigestForMGF(const CK_RSA_PKCS_MGF_TYPE mgf) {
  switch (mgf) {
    case CKG_MGF1_SHA1:
      return hwsec::DigestAlgorithm::kSha1;
    case CKG_MGF1_SHA224:
      return hwsec::DigestAlgorithm::kSha224;
    case CKG_MGF1_SHA256:
      return hwsec::DigestAlgorithm::kSha256;
    case CKG_MGF1_SHA384:
      return hwsec::DigestAlgorithm::kSha384;
    case CKG_MGF1_SHA512:
      return hwsec::DigestAlgorithm::kSha512;
    default:
      return hwsec::DigestAlgorithm::kNoDigest;
  }
}

std::optional<hwsec::SigningOptions::PssParams> GetHwsecPssParams(
    const std::string& mechanism_parameter, DigestAlgorithm& digest_algorithm) {
  const CK_RSA_PKCS_PSS_PARAMS* pss_params = nullptr;
  const EVP_MD* mgf1_hash = nullptr;
  // Check the parameters
  if (!ParseRSAPSSParams(mechanism_parameter, digest_algorithm, &pss_params,
                         &mgf1_hash, &digest_algorithm)) {
    LOG(ERROR) << "Failed to parse RSA PSS parameters.";
    return std::nullopt;
  }

  return hwsec::SigningOptions::PssParams{
      .mgf1_algorithm = GetHwsecDigestForMGF(pss_params->mgf),
      .salt_length = pss_params->sLen,
  };
}

hwsec::SigningOptions ToHwsecSigningOptions(
    CK_MECHANISM_TYPE signing_mechanism,
    const std::string& mechanism_parameter) {
  // Parse the various parameters for this method.
  DigestAlgorithm digest_algorithm = GetDigestAlgorithm(signing_mechanism);
  // Parse RSA PSS Parameters if applicable.
  const RsaPaddingScheme padding_scheme =
      GetSigningSchemeForMechanism(signing_mechanism);
  std::optional<hwsec::SigningOptions::PssParams> pss_params;

  if (padding_scheme == RsaPaddingScheme::RSASSA_PSS) {
    pss_params = GetHwsecPssParams(mechanism_parameter, digest_algorithm);
  }

  return hwsec::SigningOptions{
      .digest_algorithm = ChapsToHwsecDigestAlg(digest_algorithm),
      .rsa_padding_scheme = ChapsToHwsecRsaPaddingScheme(padding_scheme),
      .pss_params = std::move(pss_params),
  };
}

}  // namespace

SessionImpl::SessionImpl(int slot_id,
                         ObjectPool* token_object_pool,
                         const hwsec::ChapsFrontend* hwsec,
                         ChapsFactory* factory,
                         HandleGenerator* handle_generator,
                         bool is_read_only,
                         ChapsMetrics* chaps_metrics)
    : factory_(factory),
      find_results_valid_(false),
      is_read_only_(is_read_only),
      slot_id_(slot_id),
      token_object_pool_(token_object_pool),
      hwsec_(hwsec),
      chaps_metrics_(chaps_metrics) {
  CHECK(token_object_pool_);
  CHECK(factory_);
  CHECK(chaps_metrics_);
  // If the hwsec is nullptr, means it's not ready to use.
  if (hwsec_ == nullptr) {
    LOG(WARNING) << "HWSec is not available";
  }
  session_object_pool_.reset(
      factory_->CreateObjectPool(handle_generator, nullptr, nullptr));
  CHECK(session_object_pool_.get());
}

SessionImpl::~SessionImpl() {
  for (OperationContext& context : operation_context_) {
    if (context.is_valid_) {
      LOG(WARNING) << "Valid context exists when session is closing.";
      if (context.cleanup_) {
        context.cleanup_.RunAndReset();
      }
    }
  }

  if (!object_count_map_.empty()) {
    LOG(WARNING) << "Remaining object exists.";
  }
}

int SessionImpl::GetSlot() const {
  return slot_id_;
}

CK_STATE SessionImpl::GetState() const {
  return is_read_only_ ? CKS_RO_USER_FUNCTIONS : CKS_RW_USER_FUNCTIONS;
}

bool SessionImpl::IsReadOnly() const {
  return is_read_only_;
}

bool SessionImpl::IsOperationActive(OperationType type) const {
  CHECK(type < kNumOperationTypes);
  return operation_context_[type].is_valid_;
}

CK_RV SessionImpl::CreateObject(const CK_ATTRIBUTE_PTR attributes,
                                int num_attributes,
                                int* new_object_handle) {
  return CreateObjectInternal(attributes, num_attributes, nullptr,
                              new_object_handle);
}

CK_RV SessionImpl::CopyObject(const CK_ATTRIBUTE_PTR attributes,
                              int num_attributes,
                              int object_handle,
                              int* new_object_handle) {
  const Object* orig_object = nullptr;
  if (!GetObject(object_handle, &orig_object))
    return CKR_OBJECT_HANDLE_INVALID;
  CHECK(orig_object);
  return CreateObjectInternal(attributes, num_attributes, orig_object,
                              new_object_handle);
}

CK_RV SessionImpl::DestroyObject(int object_handle) {
  const Object* object = nullptr;
  if (!GetObject(object_handle, &object))
    return CKR_OBJECT_HANDLE_INVALID;
  CHECK(object);
  ObjectPool* pool =
      object->IsTokenObject() ? token_object_pool_ : session_object_pool_.get();
  return ResultToRV(pool->Delete(object), CKR_GENERAL_ERROR);
}

bool SessionImpl::GetObject(int object_handle, const Object** object) {
  CHECK(object);
  if (token_object_pool_->FindByHandle(object_handle, object) ==
      ObjectPool::Result::Success)
    return true;
  return session_object_pool_->FindByHandle(object_handle, object) ==
         ObjectPool::Result::Success;
}

bool SessionImpl::GetModifiableObject(int object_handle, Object** object) {
  CHECK(object);
  const Object* const_object;
  if (!GetObject(object_handle, &const_object))
    return false;
  ObjectPool* pool = const_object->IsTokenObject() ? token_object_pool_
                                                   : session_object_pool_.get();
  *object = pool->GetModifiableObject(const_object);
  return true;
}

CK_RV SessionImpl::FlushModifiableObject(Object* object) {
  CHECK(object);
  ObjectPool* pool =
      object->IsTokenObject() ? token_object_pool_ : session_object_pool_.get();
  return ResultToRV(pool->Flush(object), CKR_FUNCTION_FAILED);
}

CK_RV SessionImpl::FindObjectsInit(const CK_ATTRIBUTE_PTR attributes,
                                   int num_attributes) {
  if (find_results_valid_)
    return CKR_OPERATION_ACTIVE;
  std::unique_ptr<Object> search_template(factory_->CreateObject());
  CHECK(search_template.get());
  search_template->SetAttributes(attributes, num_attributes);
  vector<const Object*> objects;
  if (!search_template->IsAttributePresent(CKA_TOKEN) ||
      search_template->IsTokenObject()) {
    auto res = token_object_pool_->Find(search_template.get(), &objects);
    if (!IsSuccess(res))
      return ResultToRV(res, CKR_GENERAL_ERROR);
  }
  if (!search_template->IsAttributePresent(CKA_TOKEN) ||
      !search_template->IsTokenObject()) {
    auto res = session_object_pool_->Find(search_template.get(), &objects);
    if (!IsSuccess(res))
      return ResultToRV(res, CKR_GENERAL_ERROR);
  }
  find_results_.clear();
  find_results_offset_ = 0;
  find_results_valid_ = true;
  for (size_t i = 0; i < objects.size(); ++i) {
    find_results_.push_back(objects[i]->handle());
  }
  return CKR_OK;
}

CK_RV SessionImpl::FindObjects(int max_object_count,
                               vector<int>* object_handles) {
  CHECK(object_handles);
  if (!find_results_valid_)
    return CKR_OPERATION_NOT_INITIALIZED;
  size_t end_offset =
      find_results_offset_ + static_cast<size_t>(max_object_count);
  if (end_offset > find_results_.size())
    end_offset = find_results_.size();
  for (size_t i = find_results_offset_; i < end_offset; ++i) {
    object_handles->push_back(find_results_[i]);
  }
  find_results_offset_ += object_handles->size();
  return CKR_OK;
}

CK_RV SessionImpl::FindObjectsFinal() {
  if (!find_results_valid_)
    return CKR_OPERATION_NOT_INITIALIZED;
  find_results_valid_ = false;
  return CKR_OK;
}

CK_RV SessionImpl::OperationInit(OperationType operation,
                                 CK_MECHANISM_TYPE mechanism,
                                 const string& mechanism_parameter,
                                 const Object* key) {
  CHECK(operation < kNumOperationTypes);
  CK_RV result =
      OperationInitRaw(operation, mechanism, mechanism_parameter, key);
  chaps_metrics_->ReportChapsSessionStatus(OperationToString(operation),
                                           static_cast<int>(result));

  return result;
}

CK_RV SessionImpl::OperationInitRaw(OperationType operation,
                                    CK_MECHANISM_TYPE mechanism,
                                    const string& mechanism_parameter,
                                    const Object* key) {
  CHECK(operation < kNumOperationTypes);

  OperationContext* context = &operation_context_[operation];
  if (context->is_valid_) {
    LOG(ERROR) << "Operation is already active.";
    return CKR_OPERATION_ACTIVE;
  }

  context->Clear();
  context->mechanism_ = mechanism;
  context->parameter_ = mechanism_parameter;

  if (!IsMechanismValidForOperation(operation, mechanism)) {
    LOG(ERROR) << "Mechanism not supported: 0x" << hex << mechanism;
    return CKR_MECHANISM_INVALID;
  }

  if (operation == kSign || operation == kVerify || operation == kEncrypt ||
      operation == kDecrypt) {
    // Make sure the key is valid for the mechanism.
    CHECK(key);
    if (!IsValidKeyType(
            operation, mechanism, key->GetObjectClass(),
            key->GetAttributeInt(CKA_KEY_TYPE, CK_UNAVAILABLE_INFORMATION))) {
      LOG(ERROR) << "Key type mismatch.";
      return CKR_KEY_TYPE_INCONSISTENT;
    }
    if (!key->GetAttributeBool(GetRequiredKeyUsage(operation), false)) {
      LOG(ERROR) << "Key function not permitted.";
      return CKR_KEY_FUNCTION_NOT_PERMITTED;
    }
    if (IsRSA(mechanism)) {
      // Refuse to use RSA keys with unsupported sizes that may have been
      // created in an earlier version of chaps.
      int key_size = key->GetAttributeString(CKA_MODULUS).length() * 8;
      if (key_size < kMinRSAKeyBits || key_size > kMaxRSAKeyBits) {
        LOG(ERROR) << "Key size not supported: " << key_size;
        return CKR_KEY_SIZE_RANGE;
      }
    }
  }

  if (operation == kEncrypt || operation == kDecrypt) {
    if (mechanism == CKM_RSA_PKCS) {
      context->key_ = key;
      context->is_valid_ = true;
    } else {
      return CipherInit((operation == kEncrypt), mechanism, mechanism_parameter,
                        key);
    }
  } else if (operation == kSign || operation == kVerify ||
             operation == kDigest) {
    // It is valid for GetOpenSSLDigestForMechanism to return NULL (e.g.
    // CKM_RSA_PKCS).
    const EVP_MD* digest = GetOpenSSLDigestForMechanism(mechanism);
    if (IsHMAC(mechanism)) {
      string key_material = key->GetAttributeString(CKA_VALUE);
      context->hmac_context_.reset(HMAC_CTX_new());
      if (!context->hmac_context_) {
        LOG(ERROR) << "Failed to allocate HMAC context";
        return CKR_FUNCTION_FAILED;
      }
      HMAC_Init_ex(context->hmac_context_.get(), key_material.data(),
                   key_material.length(), digest, nullptr);
      context->is_hmac_ = true;
    } else if (digest) {
      context->digest_context_.reset(EVP_MD_CTX_new());
      if (!context->digest_context_) {
        LOG(ERROR) << "Failed to allocate EVP_MD context";
        return CKR_FUNCTION_FAILED;
      }
      EVP_DigestInit_ex(context->digest_context_.get(), digest, nullptr);
      context->is_digest_ = true;
    }
    if (IsRSA(mechanism) || IsECC(mechanism))
      context->key_ = key;
    context->is_valid_ = true;
  } else {
    NOTREACHED();
    return CKR_FUNCTION_FAILED;
  }

  UpdateObjectCount(context);

  return CKR_OK;
}

CK_RV SessionImpl::OperationUpdate(OperationType operation,
                                   const string& data_in,
                                   int* required_out_length,
                                   string* data_out) {
  CHECK(operation < kNumOperationTypes);
  CK_RV result =
      OperationUpdateRaw(operation, data_in, required_out_length, data_out);
  chaps_metrics_->ReportChapsSessionStatus(OperationToString(operation),
                                           static_cast<int>(result));
  return result;
}

CK_RV SessionImpl::OperationUpdateRaw(OperationType operation,
                                      const string& data_in,
                                      int* required_out_length,
                                      string* data_out) {
  CHECK(operation < kNumOperationTypes);
  OperationContext* context = &operation_context_[operation];
  if (!context->is_valid_) {
    return CKR_OPERATION_NOT_INITIALIZED;
  }
  if (context->is_finished_) {
    LOG(ERROR) << "Operation is finished.";
    OperationCancel(operation);
    return CKR_OPERATION_ACTIVE;
  }
  context->is_incremental_ = true;
  return OperationUpdateInternal(operation, data_in, required_out_length,
                                 data_out);
}

CK_RV SessionImpl::OperationUpdateInternal(OperationType operation,
                                           const string& data_in,
                                           int* required_out_length,
                                           string* data_out) {
  CHECK(operation < kNumOperationTypes);
  OperationContext* context = &operation_context_[operation];
  if (context->is_cipher_) {
    CK_RV rv = CipherUpdate(context, data_in, required_out_length, data_out);
    if ((rv != CKR_OK) && (rv != CKR_BUFFER_TOO_SMALL))
      OperationCancel(operation);
    return rv;
  } else if (context->is_digest_) {
    EVP_DigestUpdate(context->digest_context_.get(), data_in.data(),
                     data_in.length());
  } else if (context->is_hmac_) {
    HMAC_Update(context->hmac_context_.get(),
                ConvertStringToByteBuffer(data_in.c_str()), data_in.length());
  } else {
    // We don't need to process now; just queue the data.
    context->data_ += data_in;
  }
  if (required_out_length)
    *required_out_length = 0;
  return CKR_OK;
}

void SessionImpl::OperationCancel(OperationType operation) {
  CHECK(operation < kNumOperationTypes);
  OperationContext* context = &operation_context_[operation];
  if (!context->is_valid_) {
    LOG(ERROR) << "Operation is not initialized.";
    return;
  }
  // Drop the context and any associated data.
  context->Clear();
}

CK_RV SessionImpl::OperationFinal(OperationType operation,
                                  int* required_out_length,
                                  string* data_out) {
  CHECK(required_out_length);
  CHECK(data_out);
  CHECK(operation < kNumOperationTypes);
  CK_RV result = OperationFinalRaw(operation, required_out_length, data_out);
  chaps_metrics_->ReportChapsSessionStatus(OperationToString(operation),
                                           static_cast<int>(result));
  return result;
}

CK_RV SessionImpl::OperationFinalRaw(OperationType operation,
                                     int* required_out_length,
                                     string* data_out,
                                     bool clear_context) {
  CHECK(required_out_length);
  CHECK(data_out);
  CHECK(operation < kNumOperationTypes);
  OperationContext* context = &operation_context_[operation];
  if (!context->is_valid_) {
    LOG(ERROR) << "Operation is not initialized.";
    return CKR_OPERATION_NOT_INITIALIZED;
  }
  if (!context->is_incremental_ && context->is_finished_) {
    LOG(ERROR) << "Operation is not incremental.";
    OperationCancel(operation);
    return CKR_OPERATION_ACTIVE;
  }
  context->is_incremental_ = true;
  return OperationFinalInternal(operation, required_out_length, data_out,
                                clear_context);
}

CK_RV SessionImpl::OperationFinalInternal(OperationType operation,
                                          int* required_out_length,
                                          string* data_out,
                                          bool clear_context) {
  CHECK(operation < kNumOperationTypes);

  OperationContext* context = &operation_context_[operation];

  base::ScopedClosureRunner context_clear_runner(base::DoNothing());
  if (clear_context) {
    context_clear_runner.ReplaceClosure(
        base::BindOnce(&OperationContext::Clear, base::Unretained(context)));
  }

  // Complete the operation if it has not already been done.
  if (!context->is_finished_) {
    if (context->is_cipher_) {
      CK_RV result = CipherFinal(context);
      if (result != CKR_OK)
        return result;
    } else if (context->is_digest_) {
      unsigned char buffer[kMaxDigestOutputBytes];
      unsigned int out_length = 0;
      EVP_DigestFinal_ex(context->digest_context_.get(), buffer, &out_length);
      context->data_ = string(reinterpret_cast<char*>(buffer), out_length);
    } else if (context->is_hmac_) {
      unsigned char buffer[kMaxDigestOutputBytes];
      unsigned int out_length = 0;
      HMAC_Final(context->hmac_context_.get(), buffer, &out_length);
      context->data_ = string(reinterpret_cast<char*>(buffer), out_length);
    }

    // Some RSA/ECC mechanisms use a digest so it's important to finish the
    // digest before finishing the RSA/ECC computation.
    if (IsRSA(context->mechanism_)) {
      if (operation == kEncrypt) {
        if (!RSAEncrypt(context))
          return CKR_FUNCTION_FAILED;
      } else if (operation == kDecrypt) {
        if (!RSADecrypt(context))
          return CKR_FUNCTION_FAILED;
      } else if (operation == kSign) {
        if (!RSASign(context))
          return CKR_FUNCTION_FAILED;
      }
    } else if (IsECC(context->mechanism_)) {
      if (operation == kSign) {
        if (!ECCSign(context))
          return CKR_FUNCTION_FAILED;
      }
    }
    context->is_finished_ = true;
  }
  CK_RV result = GetOperationOutput(context, required_out_length, data_out);
  if (result == CKR_BUFFER_TOO_SMALL) {
    // We'll keep the context valid so a subsequent call can pick up the data.
    context->is_valid_ = true;
    context_clear_runner.ReplaceClosure(base::DoNothing());
  }
  return result;
}

CK_RV SessionImpl::VerifyFinal(const string& signature) {
  OperationContext* context = &operation_context_[kVerify];
  // Call the generic OperationFinal so any digest or HMAC computation gets
  // finalized.
  int max_out_length = std::numeric_limits<int>::max();
  string data_out;
  CK_RV result = OperationFinalRaw(kVerify, &max_out_length, &data_out,
                                   /*clear_context=*/false);
  chaps_metrics_->ReportChapsSessionStatus(OperationToString(kVerify),
                                           static_cast<int>(result));
  if (result != CKR_OK)
    return result;

  base::ScopedClosureRunner context_clear_runner(
      base::BindOnce(&OperationContext::Clear, base::Unretained(context)));

  // We only support 3 Verify mechanisms, HMAC, RSA and ECC.
  if (context->is_hmac_) {
    // The data_out contents will be the computed HMAC. To verify an HMAC, it is
    // recomputed and literally compared.
    if (signature.length() != data_out.length())
      return CKR_SIGNATURE_LEN_RANGE;

    if (0 != brillo::SecureMemcmp(signature.data(), data_out.data(),
                                  signature.length()))
      return CKR_SIGNATURE_INVALID;

    return CKR_OK;
  } else if (IsRSA(context->mechanism_)) {
    // The data_out contents will be the computed digest.
    return RSAVerify(context, data_out, signature);
  } else if (IsECC(context->mechanism_)) {
    // The data_out contents will be the computed digest.
    return ECCVerify(context, data_out, signature);
  } else {
    NOTREACHED();
    return false;
  }
}

CK_RV SessionImpl::OperationSinglePart(OperationType operation,
                                       const string& data_in,
                                       int* required_out_length,
                                       string* data_out) {
  CHECK(operation < kNumOperationTypes);
  CK_RV result =
      OperationSinglePartRaw(operation, data_in, required_out_length, data_out);
  chaps_metrics_->ReportChapsSessionStatus(OperationToString(operation),
                                           static_cast<int>(result));
  return result;
}

CK_RV SessionImpl::OperationSinglePartRaw(OperationType operation,
                                          const string& data_in,
                                          int* required_out_length,
                                          string* data_out) {
  CHECK(operation < kNumOperationTypes);
  OperationContext* context = &operation_context_[operation];
  if (!context->is_valid_) {
    LOG(ERROR) << "Operation is not initialized.";
    return CKR_OPERATION_NOT_INITIALIZED;
  }
  if (context->is_incremental_) {
    LOG(ERROR) << "Operation is incremental.";
    OperationCancel(operation);
    return CKR_OPERATION_ACTIVE;
  }
  CK_RV result = CKR_OK;
  if (!context->is_finished_) {
    string update, final;
    int max = std::numeric_limits<int>::max();
    result = OperationUpdateInternal(operation, data_in, &max, &update);
    if (result != CKR_OK) {
      return result;
    }
    max = std::numeric_limits<int>::max();
    result = OperationFinalInternal(operation, &max, &final);
    if (result != CKR_OK) {
      return result;
    }
    context->data_ = update + final;
    context->is_finished_ = true;
  }
  base::ScopedClosureRunner context_clear_runner(
      base::BindOnce(&OperationContext::Clear, base::Unretained(context)));
  result = GetOperationOutput(context, required_out_length, data_out);
  if (result == CKR_BUFFER_TOO_SMALL) {
    // We'll keep the context valid so a subsequent call can pick up the data.
    context->is_valid_ = true;
    context_clear_runner.ReplaceClosure(base::DoNothing());
  }
  return result;
}

CK_RV SessionImpl::GenerateKey(CK_MECHANISM_TYPE mechanism,
                               const string& mechanism_parameter,
                               const CK_ATTRIBUTE_PTR attributes,
                               int num_attributes,
                               int* new_key_handle) {
  CHECK(new_key_handle);
  std::unique_ptr<Object> object(factory_->CreateObject());
  CHECK(object.get());
  CK_RV result = object->SetAttributes(attributes, num_attributes);
  if (result != CKR_OK)
    return result;
  CK_KEY_TYPE key_type = 0;
  string key_material;
  switch (mechanism) {
    case CKM_DES_KEY_GEN: {
      key_type = CKK_DES;
      if (!GenerateDESKey(&key_material))
        return CKR_FUNCTION_FAILED;
      break;
    }
    case CKM_DES3_KEY_GEN: {
      key_type = CKK_DES3;
      string des[3];
      for (int i = 0; i < 3; ++i) {
        if (!GenerateDESKey(&des[i]))
          return CKR_FUNCTION_FAILED;
      }
      key_material = des[0] + des[1] + des[2];
      break;
    }
    case CKM_AES_KEY_GEN: {
      key_type = CKK_AES;
      if (!object->IsAttributePresent(CKA_VALUE_LEN))
        return CKR_TEMPLATE_INCOMPLETE;
      CK_ULONG key_length = object->GetAttributeInt(CKA_VALUE_LEN, 0);
      if (key_length != 16 && key_length != 24 && key_length != 32)
        return CKR_KEY_SIZE_RANGE;
      key_material = GenerateRandomSoftware(key_length);
      break;
    }
    case CKM_GENERIC_SECRET_KEY_GEN: {
      key_type = CKK_GENERIC_SECRET;
      if (!object->IsAttributePresent(CKA_VALUE_LEN))
        return CKR_TEMPLATE_INCOMPLETE;
      CK_ULONG key_length = object->GetAttributeInt(CKA_VALUE_LEN, 0);
      if (key_length < 1)
        return CKR_KEY_SIZE_RANGE;
      key_material = GenerateRandomSoftware(key_length);
      break;
    }
    default: {
      LOG(ERROR) << "GenerateKey: Mechanism not supported: " << hex
                 << mechanism;
      return CKR_MECHANISM_INVALID;
    }
  }
  object->SetAttributeInt(CKA_CLASS, CKO_SECRET_KEY);
  object->SetAttributeInt(CKA_KEY_TYPE, key_type);
  object->SetAttributeString(CKA_VALUE, key_material);
  object->SetAttributeBool(CKA_LOCAL, true);
  object->SetAttributeInt(CKA_KEY_GEN_MECHANISM, mechanism);
  result = object->FinalizeNewObject();
  if (result != CKR_OK)
    return result;
  ObjectPool* pool =
      object->IsTokenObject() ? token_object_pool_ : session_object_pool_.get();
  auto pool_res = pool->Insert(object.get());
  if (!IsSuccess(pool_res))
    return ResultToRV(pool_res, CKR_FUNCTION_FAILED);
  *new_key_handle = object.release()->handle();
  return CKR_OK;
}

CK_RV SessionImpl::GenerateKeyPair(CK_MECHANISM_TYPE mechanism,
                                   const string& mechanism_parameter,
                                   const CK_ATTRIBUTE_PTR public_attributes,
                                   int num_public_attributes,
                                   const CK_ATTRIBUTE_PTR private_attributes,
                                   int num_private_attributes,
                                   int* new_public_key_handle,
                                   int* new_private_key_handle) {
  CHECK(new_public_key_handle);
  CHECK(new_private_key_handle);

  // Create public/private key objects
  std::unique_ptr<Object> public_object(factory_->CreateObject());
  CHECK(public_object.get());
  std::unique_ptr<Object> private_object(factory_->CreateObject());
  CHECK(private_object.get());

  // copy attributes
  // TODO(menghuan): don't copy the attribute that doesn't support
  CK_RV result =
      public_object->SetAttributes(public_attributes, num_public_attributes);
  if (result != CKR_OK)
    return result;
  result =
      private_object->SetAttributes(private_attributes, num_private_attributes);
  if (result != CKR_OK)
    return result;

  // Get the object pool
  ObjectPool* public_pool =
      (public_object->IsTokenObject() ? token_object_pool_
                                      : session_object_pool_.get());
  ObjectPool* private_pool =
      (private_object->IsTokenObject() ? token_object_pool_
                                       : session_object_pool_.get());

  switch (mechanism) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
      result = GenerateRSAKeyPair(public_object.get(), private_object.get());
      break;
    case CKM_EC_KEY_PAIR_GEN:
      result = GenerateECCKeyPair(public_object.get(), private_object.get());
      break;
    default:
      LOG(ERROR) << __func__ << ": Mechanism not supported: " << hex
                 << mechanism;
      return CKR_MECHANISM_INVALID;
  }
  if (result != CKR_OK) {
    return result;
  }

  // Set the general attributes for public / private key
  public_object->SetAttributeInt(CKA_CLASS, CKO_PUBLIC_KEY);
  private_object->SetAttributeInt(CKA_CLASS, CKO_PRIVATE_KEY);

  // The CKA_KEY_GEN_MECHANISM attribute identifies the key generation mechanism
  // used to generate the key material. It contains a valid value only if the
  // CKA_LOCAL attribute has the value CK_TRUE. If CKA_LOCAL has the value
  // CK_FALSE, the value of the attribute is CK_UNAVAILABLE_INFORMATION.
  public_object->SetAttributeBool(CKA_LOCAL, true);
  private_object->SetAttributeBool(CKA_LOCAL, true);
  public_object->SetAttributeInt(CKA_KEY_GEN_MECHANISM, mechanism);
  private_object->SetAttributeInt(CKA_KEY_GEN_MECHANISM, mechanism);

  // Finalize the objects
  result = public_object->FinalizeNewObject();
  if (result != CKR_OK) {
    LOG(ERROR) << __func__ << ": Fail to finalize public object.";
    return result;
  }
  result = private_object->FinalizeNewObject();
  if (result != CKR_OK) {
    LOG(ERROR) << __func__ << ": Fail to finalize private object.";
    return result;
  }
  auto pool_res = public_pool->Insert(public_object.get());
  if (!IsSuccess(pool_res)) {
    LOG(ERROR) << __func__ << ": Fail to insert public object to public pool.";
    return ResultToRV(pool_res, CKR_FUNCTION_FAILED);
  }
  pool_res = private_pool->Insert(private_object.get());
  if (!IsSuccess(pool_res)) {
    LOG(ERROR) << __func__
               << ": Fail to insert private object to private pool.";
    // Remove inserted public object.
    // The object will be destroy in Delete(), we should release uniptr.
    public_pool->Delete(public_object.release());
    return ResultToRV(pool_res, CKR_FUNCTION_FAILED);
  }
  *new_public_key_handle = public_object.release()->handle();
  *new_private_key_handle = private_object.release()->handle();
  return CKR_OK;
}

CK_RV SessionImpl::SeedRandom(const string& seed) {
  RAND_seed(seed.data(), seed.length());
  return CKR_OK;
}

CK_RV SessionImpl::GenerateRandom(int num_bytes, string* random_data) {
  *random_data = GenerateRandomSoftware(num_bytes);
  return CKR_OK;
}

bool SessionImpl::IsPrivateLoaded() {
  return token_object_pool_->IsPrivateLoaded();
}

CK_RV SessionImpl::CipherInit(bool is_encrypt,
                              CK_MECHANISM_TYPE mechanism,
                              const string& mechanism_parameter,
                              const Object* key) {
  string key_material = key->GetAttributeString(CKA_VALUE);
  const EVP_CIPHER* cipher_type =
      GetOpenSSLCipher(mechanism, key_material.size());
  if (!cipher_type) {
    LOG(ERROR) << "Mechanism not supported: 0x" << hex << mechanism;
    return CKR_MECHANISM_INVALID;
  }
  // The mechanism parameter is the IV for cipher modes which require an IV,
  // otherwise it is expected to be empty.
  if (static_cast<int>(mechanism_parameter.size()) !=
      EVP_CIPHER_iv_length(cipher_type)) {
    LOG(ERROR) << "IV length is invalid: " << mechanism_parameter.size();
    return CKR_MECHANISM_PARAM_INVALID;
  }
  if (static_cast<int>(key_material.size()) !=
      EVP_CIPHER_key_length(cipher_type)) {
    LOG(ERROR) << "Key size not supported: " << key_material.size();
    return CKR_KEY_SIZE_RANGE;
  }

  OperationType operation = is_encrypt ? kEncrypt : kDecrypt;
  OperationContext* context = &operation_context_[operation];
  context->cipher_context_.reset(EVP_CIPHER_CTX_new());
  if (!context->cipher_context_) {
    LOG(ERROR) << "Failed to allocate EVP_CIPHER context";
    return CKR_FUNCTION_FAILED;
  }

  if (!EVP_CipherInit_ex(context->cipher_context_.get(), cipher_type, nullptr,
                         ConvertStringToByteBuffer(key_material.c_str()),
                         ConvertStringToByteBuffer(mechanism_parameter.c_str()),
                         is_encrypt)) {
    LOG(ERROR) << "EVP_CipherInit failed: " << GetOpenSSLError();
    return CKR_FUNCTION_FAILED;
  }
  EVP_CIPHER_CTX_set_padding(context->cipher_context_.get(),
                             IsPaddingEnabled(mechanism));
  context->is_valid_ = true;
  context->is_cipher_ = true;
  return CKR_OK;
}

CK_RV SessionImpl::CipherUpdate(OperationContext* context,
                                const string& data_in,
                                int* required_out_length,
                                string* data_out) {
  CHECK(required_out_length);
  CHECK(data_out);
  // If we have output already waiting, we don't need to process input.
  if (context->data_.empty()) {
    int in_length = data_in.length();
    int out_length = in_length + kMaxCipherBlockBytes;
    context->data_.resize(out_length);
    if (!EVP_CipherUpdate(
            context->cipher_context_.get(),
            ConvertStringToByteBuffer(context->data_.c_str()), &out_length,
            ConvertStringToByteBuffer(data_in.c_str()), in_length)) {
      context->Clear();
      LOG(ERROR) << "EVP_CipherUpdate failed: " << GetOpenSSLError();
      return CKR_FUNCTION_FAILED;
    }
    context->data_.resize(out_length);
  }
  return GetOperationOutput(context, required_out_length, data_out);
}

CK_RV SessionImpl::CipherFinal(OperationContext* context) {
  if (context->data_.empty()) {
    int out_length = kMaxCipherBlockBytes * 2;
    context->data_.resize(out_length);
    if (!EVP_CipherFinal_ex(context->cipher_context_.get(),
                            ConvertStringToByteBuffer(context->data_.c_str()),
                            &out_length)) {
      LOG(ERROR) << "EVP_CipherFinal failed: " << GetOpenSSLError();
      return CKR_FUNCTION_FAILED;
    }
    context->data_.resize(out_length);
  }
  return CKR_OK;
}

CK_RV SessionImpl::CreateObjectInternal(const CK_ATTRIBUTE_PTR attributes,
                                        int num_attributes,
                                        const Object* copy_from_object,
                                        int* new_object_handle) {
  CHECK(new_object_handle);
  CHECK(attributes || num_attributes == 0);
  std::unique_ptr<Object> object(factory_->CreateObject());
  CHECK(object.get());
  CK_RV result = CKR_OK;
  if (copy_from_object) {
    result = object->Copy(copy_from_object);
    if (result != CKR_OK)
      return result;
  }
  result = object->SetAttributes(attributes, num_attributes);
  if (result != CKR_OK)
    return result;

  bool is_token_object = object->IsTokenObject();
  if (is_token_object) {
    result = WrapPrivateKey(object.get());
    if (result != CKR_OK)
      return result;
  }

  // Finalize the object, whether it's new or copied.
  if (copy_from_object) {
    result = object->FinalizeCopyObject();
  } else {
    result = object->FinalizeNewObject();
  }
  if (result != CKR_OK) {
    return result;
  }

  ObjectPool* pool =
      is_token_object ? token_object_pool_ : session_object_pool_.get();
  auto pool_res = pool->Insert(object.get());
  if (!IsSuccess(pool_res))
    return ResultToRV(pool_res, CKR_GENERAL_ERROR);
  *new_object_handle = object.release()->handle();
  return CKR_OK;
}

bool SessionImpl::GenerateDESKey(string* key_material) {
  static const int kDESKeySizeBytes = 8;
  bool done = false;
  while (!done) {
    string tmp = GenerateRandomSoftware(kDESKeySizeBytes);
    DES_cblock des;
    memcpy(&des, tmp.data(), kDESKeySizeBytes);
    if (!DES_is_weak_key(&des)) {
      DES_set_odd_parity(&des);
      *key_material = string(reinterpret_cast<char*>(des), kDESKeySizeBytes);
      done = true;
    }
  }
  return true;
}

CK_RV SessionImpl::GenerateRSAKeyPair(Object* public_object,
                                      Object* private_object) {
  // CKA_PUBLIC_EXPONENT is optional. The default is 65537 (0x10001).
  string public_exponent("\x01\x00\x01", 3);
  if (public_object->IsAttributePresent(CKA_PUBLIC_EXPONENT))
    public_exponent = public_object->GetAttributeString(CKA_PUBLIC_EXPONENT);
  public_object->SetAttributeString(CKA_PUBLIC_EXPONENT, public_exponent);
  private_object->SetAttributeString(CKA_PUBLIC_EXPONENT, public_exponent);

  // CKA_MODULUS_BITS is requried
  if (!public_object->IsAttributePresent(CKA_MODULUS_BITS))
    return CKR_TEMPLATE_INCOMPLETE;
  CK_ULONG modulus_bits = public_object->GetAttributeInt(CKA_MODULUS_BITS, 0);
  if (modulus_bits < kMinRSAKeyBits || modulus_bits > kMaxRSAKeyBits)
    return CKR_KEY_SIZE_RANGE;

  // Set CKA_KEY_TYPE
  public_object->SetAttributeInt(CKA_KEY_TYPE, CKK_RSA);
  private_object->SetAttributeInt(CKA_KEY_TYPE, CKK_RSA);

  bool is_using_hwsec =
      private_object->IsTokenObject() &&
      !private_object->GetAttributeBool(kForceSoftwareAttribute, false) &&
      hwsec_ && hwsec_->IsRSAModulusSupported(modulus_bits).ok();

  // Check if we are able to back this key with the HWSec.
  if (is_using_hwsec) {
    // Use HWSec to generate RSA key
    if (!GenerateRSAKeyPairHwsec(modulus_bits, public_exponent, public_object,
                                 private_object))
      return CKR_FUNCTION_FAILED;
  } else {
    // Use software to generate RSA key
    if (!GenerateRSAKeyPairSoftware(modulus_bits, public_exponent,
                                    public_object, private_object))
      return CKR_FUNCTION_FAILED;
  }
  return CKR_OK;
}

bool SessionImpl::GenerateRSAKeyPairSoftware(int modulus_bits,
                                             const string& public_exponent,
                                             Object* public_object,
                                             Object* private_object) {
  if (public_exponent.length() > sizeof(uint32_t) || public_exponent.empty())
    return false;
  crypto::ScopedRSA key(RSA_new());
  crypto::ScopedBIGNUM e(BN_new());
  if (!key || !e) {
    LOG(ERROR) << "Failed to allocate RSA or BIGNUM for exponent.";
    return false;
  }
  if (!ConvertToBIGNUM(public_exponent, e.get())) {
    LOG(ERROR) << "Failed to convert exponent to BIGNUM.";
    return false;
  }
  if (!RSA_generate_key_ex(key.get(), modulus_bits, e.get(), nullptr)) {
    LOG(ERROR) << "Failed to generate key pair.";
    return false;
  }

  const BIGNUM* key_n;
  const BIGNUM* key_d;
  const BIGNUM* key_p;
  const BIGNUM* key_q;
  const BIGNUM* key_dmp1;
  const BIGNUM* key_dmq1;
  const BIGNUM* key_iqmp;
  RSA_get0_key(key.get(), &key_n, nullptr, &key_d);
  RSA_get0_factors(key.get(), &key_p, &key_q);
  RSA_get0_crt_params(key.get(), &key_dmp1, &key_dmq1, &key_iqmp);
  string n = ConvertFromBIGNUM(key_n);
  string d = ConvertFromBIGNUM(key_d);
  string p = ConvertFromBIGNUM(key_p);
  string q = ConvertFromBIGNUM(key_q);
  string dmp1 = ConvertFromBIGNUM(key_dmp1);
  string dmq1 = ConvertFromBIGNUM(key_dmq1);
  string iqmp = ConvertFromBIGNUM(key_iqmp);
  public_object->SetAttributeString(CKA_MODULUS, n);
  private_object->SetAttributeString(CKA_MODULUS, n);
  private_object->SetAttributeString(CKA_PRIVATE_EXPONENT, d);
  private_object->SetAttributeString(CKA_PRIME_1, p);
  private_object->SetAttributeString(CKA_PRIME_2, q);
  private_object->SetAttributeString(CKA_EXPONENT_1, dmp1);
  private_object->SetAttributeString(CKA_EXPONENT_2, dmq1);
  private_object->SetAttributeString(CKA_COEFFICIENT, iqmp);
  return true;
}

bool SessionImpl::GenerateRSAKeyPairHwsec(int modulus_bits,
                                          const string& public_exponent,
                                          Object* public_object,
                                          Object* private_object) {
  if (!hwsec_) {
    LOG(ERROR) << "No HWSec frontend available in GenerateRSAKeyPairHwsec.";
    return false;
  }

  brillo::Blob exponent = brillo::BlobFromString(public_exponent);
  brillo::SecureBlob auth_data =
      GenerateRandomSecureBlobSoftware(kDefaultAuthDataBytes);

  AllowSoftwareGen allow_soft_gen =
      private_object->GetAttributeBool(kAllowSoftwareGenAttribute, false)
          ? AllowSoftwareGen::kAllow
          : AllowSoftwareGen::kNotAllow;

  AllowDecrypt allow_decrypt =
      private_object->GetAttributeBool(CKA_DECRYPT, false)
          ? AllowDecrypt::kAllow
          : AllowDecrypt::kNotAllow;

  AllowSign allow_sign = private_object->GetAttributeBool(CKA_SIGN, false)
                             ? AllowSign::kAllow
                             : AllowSign::kNotAllow;

  ASSIGN_OR_RETURN(
      const hwsec::ChapsFrontend::CreateKeyResult& result,
      hwsec_->GenerateRSAKey(modulus_bits, exponent, auth_data, allow_soft_gen,
                             allow_decrypt, allow_sign),
      _.WithStatus<TPMError>(
           "Failed to generate RSA key in GenerateRSAKeyPairHwsec")
          .LogError()
          .As(false));

  // Get public key information from HWSec
  ASSIGN_OR_RETURN(const hwsec::RSAPublicInfo& info,
                   hwsec_->GetRSAPublicKey(result.key.GetKey()),
                   _.WithStatus<TPMError>(
                        "Failed to get RSA key info in GenerateRSAKeyPairHwsec")
                       .LogError()
                       .As(false));

  public_object->SetAttributeString(CKA_MODULUS,
                                    brillo::BlobToString(info.modulus));
  private_object->SetAttributeString(CKA_MODULUS,
                                     brillo::BlobToString(info.modulus));
  private_object->SetAttributeString(kAuthDataAttribute, auth_data.to_string());
  private_object->SetAttributeString(kKeyBlobAttribute,
                                     brillo::BlobToString(result.key_blob));
  return true;
}

CK_RV SessionImpl::GenerateECCKeyPair(Object* public_object,
                                      Object* private_object) {
  // CKA_EC_PARAMS is requried
  if (!public_object->IsAttributePresent(CKA_EC_PARAMS))
    return CKR_TEMPLATE_INCOMPLETE;

  crypto::ScopedEC_KEY key = CreateECCKeyFromEC_PARAMS(
      public_object->GetAttributeString(CKA_EC_PARAMS));
  if (key == nullptr) {
    LOG(ERROR) << __func__ << ": CKA_EC_PARAMS parse fail.";
    return CKR_DOMAIN_PARAMS_INVALID;
  }

  // Set CKA_KEY_TYPE
  public_object->SetAttributeInt(CKA_KEY_TYPE, CKK_EC);
  private_object->SetAttributeInt(CKA_KEY_TYPE, CKK_EC);

  // reset CKA_EC_PARAMS for both key
  const string ec_params = GetECParametersAsString(key.get());
  if (ec_params.empty()) {
    LOG(ERROR) << __func__ << ": Fail to dump CKA_EC_PARAMS";
    return CKR_FUNCTION_FAILED;
  }
  public_object->SetAttributeString(CKA_EC_PARAMS, ec_params);
  private_object->SetAttributeString(CKA_EC_PARAMS, ec_params);

  // Get NID from key
  const EC_GROUP* group = EC_KEY_get0_group(key.get());
  if (group == nullptr)
    return CKR_FUNCTION_FAILED;
  int curve_nid = EC_GROUP_get_curve_name(group);

  bool is_using_hwsec =
      private_object->IsTokenObject() &&
      !private_object->GetAttributeBool(kForceSoftwareAttribute, false) &&
      hwsec_ && hwsec_->IsECCurveSupported(curve_nid).ok();

  bool result = false;
  if (is_using_hwsec) {
    result =
        GenerateECCKeyPairHwsec(key, curve_nid, public_object, private_object);
  } else {
    result = GenerateECCKeyPairSoftware(key, public_object, private_object);
  }
  return result ? CKR_OK : CKR_FUNCTION_FAILED;
}

bool SessionImpl::GenerateECCKeyPairHwsec(const crypto::ScopedEC_KEY& key,
                                          int curve_nid,
                                          Object* public_object,
                                          Object* private_object) {
  if (!hwsec_) {
    LOG(ERROR) << "No HWSec frontend available in GenerateECCKeyPairHwsec.";
    return false;
  }

  brillo::SecureBlob auth_data =
      GenerateRandomSecureBlobSoftware(kDefaultAuthDataBytes);

  AllowDecrypt allow_decrypt =
      private_object->GetAttributeBool(CKA_DECRYPT, false)
          ? AllowDecrypt::kAllow
          : AllowDecrypt::kNotAllow;

  AllowSign allow_sign = private_object->GetAttributeBool(CKA_SIGN, false)
                             ? AllowSign::kAllow
                             : AllowSign::kNotAllow;

  ASSIGN_OR_RETURN(
      const hwsec::ChapsFrontend::CreateKeyResult& result,
      hwsec_->GenerateECCKey(curve_nid, auth_data, allow_decrypt, allow_sign),
      _.WithStatus<TPMError>(
           "Failed to generate ECC key in GenerateECCKeyPairHwsec")
          .LogError()
          .As(false));

  // Get public key information from HWSec
  ASSIGN_OR_RETURN(const hwsec::ECCPublicInfo& info,
                   hwsec_->GetECCPublicKey(result.key.GetKey()),
                   _.WithStatus<TPMError>(
                        "Failed to get ECC key info in GenerateECCKeyPairHwsec")
                       .LogError()
                       .As(false));

  // Convert the ECC public into the DER-encoded format.

  crypto::ScopedEC_Key ecc(EC_KEY_new_by_curve_name(info.nid));
  if (!ecc) {
    LOG(ERROR) << "Failed to create EC_KEY from curve name " << info.nid << ".";
    return false;
  }

  crypto::ScopedBIGNUM x(BN_new()), y(BN_new());
  if (!x || !y) {
    LOG(ERROR) << "Failed to allocate BIGNUM.";
    return false;
  }

  if (!chaps::ConvertBlobToBIGNUM(info.x_point, x.get()) ||
      !chaps::ConvertBlobToBIGNUM(info.y_point, y.get())) {
    LOG(ERROR) << "Failed to convert to BIGNUM.";
    return false;
  }

  // EC_KEY_set_public_key_affine_coordinates will check the pointer is valid
  if (!EC_KEY_set_public_key_affine_coordinates(ecc.get(), x.get(), y.get())) {
    LOG(ERROR) << "Invalid point.";
    return false;
  }

  std::string ec_point = GetECPointAsString(ecc.get());

  // Set CKA_EC_POINT for public key
  public_object->SetAttributeString(CKA_EC_POINT, ec_point);

  // Set HWSec information for private key
  private_object->SetAttributeString(kAuthDataAttribute, auth_data.to_string());
  private_object->SetAttributeString(kKeyBlobAttribute,
                                     brillo::BlobToString(result.key_blob));

  return true;
}

bool SessionImpl::GenerateECCKeyPairSoftware(const crypto::ScopedEC_KEY& key,
                                             Object* public_object,
                                             Object* private_object) {
  if (!EC_KEY_generate_key(key.get())) {
    LOG(ERROR) << __func__
               << ": Software generate key fail. Perhaps it is not supported "
                  "by OpenSSL.";
    return false;
  }

  // Set CKA_EC_POINT for public key
  const string ec_point = GetECPointAsString(key.get());
  if (ec_point.empty()) {
    LOG(ERROR) << __func__ << ": Fail to dump EC_POINT.";
    return false;
  }
  public_object->SetAttributeString(CKA_EC_POINT, ec_point);

  // Set CKA_VALUE for private key
  const BIGNUM* privkey = EC_KEY_get0_private_key(key.get());
  private_object->SetAttributeString(CKA_VALUE, ConvertFromBIGNUM(privkey));
  return true;
}

CK_RV SessionImpl::GetOperationOutput(OperationContext* context,
                                      int* required_out_length,
                                      string* data_out) {
  int out_length = context->data_.length();
  int max_length = *required_out_length;
  *required_out_length = out_length;
  if (max_length < out_length)
    return CKR_BUFFER_TOO_SMALL;
  *data_out = context->data_;
  context->data_.clear();
  return CKR_OK;
}

CK_ATTRIBUTE_TYPE SessionImpl::GetRequiredKeyUsage(OperationType operation) {
  switch (operation) {
    case kEncrypt:
      return CKA_ENCRYPT;
    case kDecrypt:
      return CKA_DECRYPT;
    case kSign:
      return CKA_SIGN;
    case kVerify:
      return CKA_VERIFY;
    default:
      break;
  }
  return 0;
}

hwsec::StatusOr<hwsec::Key> SessionImpl::GetHwsecKey(const Object* key) {
  if (!hwsec_) {
    return MakeStatus<TPMError>("No HWSec in GetHwsecKey",
                                hwsec::TPMRetryAction::kNoRetry);
  }

  map<const Object*, hwsec::ScopedKey>::iterator it = object_key_map_.find(key);
  if (it != object_key_map_.end()) {
    return it->second.GetKey();
  }

  // Only private keys are loaded into the HWSec. All public key operations do
  // not use the HWSec (and use OpenSSL instead).
  if (key->GetObjectClass() != CKO_PRIVATE_KEY) {
    return MakeStatus<TPMError>("Invalid object class for loading into HWSec",
                                hwsec::TPMRetryAction::kNoRetry);
  }

  brillo::Blob key_blob =
      brillo::BlobFromString(key->GetAttributeString(kKeyBlobAttribute));

  brillo::SecureBlob auth_value(key->GetAttributeString(kAuthDataAttribute));

  ASSIGN_OR_RETURN(
      hwsec::ScopedKey hwsec_key, hwsec_->LoadKey(key_blob, auth_value),
      _.WithStatus<TPMError>("Failed to load the key in GetHwsecKey"));

  hwsec::Key key_handle = hwsec_key.GetKey();
  object_key_map_.emplace(key, std::move(hwsec_key));

  return key_handle;
}

void SessionImpl::UpdateObjectCount(OperationContext* context) {
  if (context->key_ != nullptr) {
    IncreaseObjectCount(context->key_);
    // We stored the context inside the session, and there is no way to transfer
    // the ownership of context outside of session. So base::Unretained(this) is
    // safe here.
    context->cleanup_ = base::ScopedClosureRunner(
        base::BindOnce(&SessionImpl::DecreaseObjectCount,
                       base::Unretained(this), context->key_));
  }
}

void SessionImpl::IncreaseObjectCount(const Object* key) {
  if (key == nullptr) {
    return;
  }

  object_count_map_[key]++;
}

void SessionImpl::DecreaseObjectCount(const Object* key) {
  if (key == nullptr) {
    return;
  }

  if ((--object_count_map_[key]) == 0) {
    object_count_map_.erase(key);
    object_key_map_.erase(key);
  }
}

bool SessionImpl::RSADecrypt(OperationContext* context) {
  if (context->key_->IsTokenObject() &&
      context->key_->IsAttributePresent(kKeyBlobAttribute)) {
    if (!hwsec_) {
      LOG(ERROR) << "No HWSec frontend available in RSADecrypt.";
      return false;
    }

    ASSIGN_OR_RETURN(hwsec::Key key, GetHwsecKey(context->key_),
                     _.LogError().As(false));

    brillo::Blob encrypted_data = brillo::BlobFromString(context->data_);
    context->data_.clear();

    ASSIGN_OR_RETURN(brillo::SecureBlob data,
                     hwsec_->Unbind(key, encrypted_data),
                     _.WithStatus<TPMError>(
                          "Failed to unbind the encrypted data in RSADecrypt")
                         .LogError()
                         .As(false));

    context->data_ = data.to_string();
  } else {
    crypto::ScopedRSA rsa = CreateRSAKeyFromObject(context->key_);
    if (!rsa) {
      LOG(ERROR) << "Failed to create RSA key for decryption.";
      return false;
    }
    uint8_t buffer[kMaxRSAOutputBytes];
    CHECK(RSA_size(rsa.get()) <= kMaxRSAOutputBytes);
    int length = RSA_private_decrypt(
        context->data_.length(),
        ConvertStringToByteBuffer(context->data_.data()), buffer, rsa.get(),
        RSA_PKCS1_PADDING);  // Strips PKCS #1 type 2 padding.
    if (length == -1) {
      LOG(ERROR) << "RSA_private_decrypt failed: " << GetOpenSSLError();
      return false;
    }
    context->data_ = ConvertByteBufferToString(buffer, length);
  }
  return true;
}

bool SessionImpl::RSAEncrypt(OperationContext* context) {
  crypto::ScopedRSA rsa = CreateRSAKeyFromObject(context->key_);
  if (!rsa) {
    LOG(ERROR) << "Failed to create RSA key for encryption.";
    return false;
  }
  uint8_t buffer[kMaxRSAOutputBytes];
  CHECK(RSA_size(rsa.get()) <= kMaxRSAOutputBytes);
  int length = RSA_public_encrypt(
      context->data_.length(), ConvertStringToByteBuffer(context->data_.data()),
      buffer, rsa.get(),
      RSA_PKCS1_PADDING);  // Adds PKCS #1 type 2 padding.
  if (length == -1) {
    LOG(ERROR) << "RSA_public_encrypt failed: " << GetOpenSSLError();
    return false;
  }
  context->data_ = ConvertByteBufferToString(buffer, length);
  return true;
}

bool SessionImpl::RSASign(OperationContext* context) {
  if (context->key_->IsTokenObject() &&
      context->key_->IsAttributePresent(kKeyBlobAttribute)) {
    if (!hwsec_) {
      LOG(ERROR) << "No HWSec frontend available in RSASign.";
      return false;
    }

    ASSIGN_OR_RETURN(hwsec::Key key, GetHwsecKey(context->key_),
                     _.LogError().As(false));

    ASSIGN_OR_RETURN(
        brillo::Blob data,
        hwsec_->Sign(
            key, brillo::BlobFromString(context->data_),
            ToHwsecSigningOptions(context->mechanism_, context->parameter_)),
        _.WithStatus<TPMError>("Failed to RSA sign the data in RASSign")
            .LogError()
            .As(false));

    context->data_ = brillo::BlobToString(data);
    return true;
  }

  // Sign the data without HWSec.
  crypto::ScopedRSA rsa = CreateRSAKeyFromObject(context->key_);
  if (!rsa) {
    LOG(ERROR) << "Failed to create RSA key for signing.";
    return false;
  }

  std::unique_ptr<RSASignerVerifier> signer =
      RSASignerVerifier::GetForMechanism(context->mechanism_);
  if (!signer) {
    return false;
  }

  return signer->Sign(std::move(rsa), context);
}

CK_RV SessionImpl::RSAVerify(OperationContext* context,
                             const string& digest,
                             const string& signature) {
  if (context->key_->GetAttributeString(CKA_MODULUS).length() !=
      signature.length())
    return CKR_SIGNATURE_LEN_RANGE;
  crypto::ScopedRSA rsa = CreateRSAKeyFromObject(context->key_);
  if (!rsa) {
    LOG(ERROR) << "Failed to create RSA key for verification.";
    return CKR_KEY_HANDLE_INVALID;
  }
  std::unique_ptr<RSASignerVerifier> verifier =
      RSASignerVerifier::GetForMechanism(context->mechanism_);
  if (!verifier)
    return CKR_ARGUMENTS_BAD;

  return verifier->Verify(std::move(rsa), context, digest, signature);
}

bool SessionImpl::ECCSign(OperationContext* context) {
  string signature;
  if (context->key_->IsTokenObject() &&
      context->key_->IsAttributePresent(kKeyBlobAttribute)) {
    if (!ECCSignHwsec(context->data_, context->mechanism_, context->key_,
                      &signature))
      return false;
  } else {
    if (!ECCSignSoftware(context->data_, context->key_, &signature))
      return false;
  }
  context->data_ = signature;
  return true;
}

bool SessionImpl::ECCSignHwsec(const std::string& input,
                               CK_MECHANISM_TYPE signing_mechanism,
                               const Object* key_object,
                               std::string* signature) {
  if (!hwsec_) {
    LOG(ERROR) << "No HWSec frontend available in ECCSignHwsec.";
    return false;
  }

  if (!(signing_mechanism == CKM_ECDSA || signing_mechanism == CKM_ECDSA_SHA1 ||
        signing_mechanism == CKM_ECDSA_SHA256 ||
        signing_mechanism == CKM_ECDSA_SHA384 ||
        signing_mechanism == CKM_ECDSA_SHA512)) {
    LOG(ERROR)
        << "Failed to sign with ECCSignHwsec because mechanism is unsupported: "
        << signing_mechanism;
    return false;
  }

  ASSIGN_OR_RETURN(hwsec::Key key, GetHwsecKey(key_object),
                   _.LogError().As(false));

  ASSIGN_OR_RETURN(
      brillo::Blob data,
      hwsec_->Sign(key, brillo::BlobFromString(input),
                   ToHwsecSigningOptions(signing_mechanism, "")),
      _.WithStatus<TPMError>("Failed to ECC sign the data in ECCSignHwsec")
          .LogError()
          .As(false));

  *signature = brillo::BlobToString(data);

  return true;
}

bool SessionImpl::ECCSignSoftware(const std::string& input,
                                  const Object* key_object,
                                  std::string* signature) {
  crypto::ScopedEC_KEY key = CreateECCPrivateKeyFromObject(key_object);
  if (key == nullptr) {
    LOG(ERROR) << __func__ << ": Load key failed.";
    return false;
  }

  // We don't use ECDSA_sign here since the output format of PKCS#11 is
  // different from OpenSSL's.
  crypto::ScopedECDSA_SIG sig(ECDSA_do_sign(
      ConvertStringToByteBuffer(input.data()), input.size(), key.get()));
  if (sig == nullptr) {
    LOG(ERROR) << __func__ << ": ECDSA failed: " << GetOpenSSLError();
    return false;
  }

  // The resulting signature is always of length |2 * nLen|, where nLen is the
  // maximum size of the EC group. The first half of the signature is r and the
  // second half is s.
  int max_length = GetGroupOrderLengthFromEcKey(key);
  if (max_length <= 0) {
    LOG(ERROR) << __func__ << ": Get the group order fail.";
    return false;
  }
  const BIGNUM* r;
  const BIGNUM* s;
  ECDSA_SIG_get0(sig.get(), &r, &s);
  *signature =
      ConvertFromBIGNUM(r, max_length) + ConvertFromBIGNUM(s, max_length);

  return true;
}

CK_RV SessionImpl::ECCVerify(OperationContext* context,
                             const string& signed_data,
                             const string& signature) {
  // Software verify with ECC key
  crypto::ScopedEC_KEY key = CreateECCPublicKeyFromObject(context->key_);
  if (key == nullptr) {
    LOG(ERROR) << __func__ << ": Load key failed.";
    return CKR_FUNCTION_FAILED;
  }

  // Parse signature back to ECDSA_SIG
  int sign_size = signature.size();
  if (sign_size % 2 != 0) {
    return CKR_SIGNATURE_LEN_RANGE;
  }
  crypto::ScopedECDSA_SIG sig(ECDSA_SIG_new());
  crypto::ScopedBIGNUM r(BN_new()), s(BN_new());
  if (!sig || !r || !s) {
    LOG(ERROR) << "Failed to allocate ECDSA_SIG or BIGNUM.";
    return CKR_FUNCTION_FAILED;
  }
  if (!ConvertToBIGNUM(signature.substr(0, sign_size / 2), r.get()) ||
      !ConvertToBIGNUM(signature.substr(sign_size / 2), s.get())) {
    LOG(ERROR) << "Failed to convert BIGNUM for ECDSA_SIG.";
    return CKR_FUNCTION_FAILED;
  }
  if (!ECDSA_SIG_set0(sig.get(), r.release(), s.release())) {
    LOG(ERROR) << "Failed to set ECDSA_SIG parameters.";
    return CKR_FUNCTION_FAILED;
  }

  // 1 for a valid signature, 0 for an invalid signature and -1 on error.
  int result = ECDSA_do_verify(ConvertStringToByteBuffer(signed_data.data()),
                               signed_data.size(), sig.get(), key.get());
  if (result < 0) {
    LOG(ERROR) << __func__ << ": ECDSA verify failed: " << GetOpenSSLError();
    return CKR_FUNCTION_FAILED;
  }
  return result ? CKR_OK : CKR_SIGNATURE_INVALID;
}

CK_RV SessionImpl::WrapRSAPrivateKey(Object* object) {
  if (!object->IsAttributePresent(CKA_PUBLIC_EXPONENT) ||
      !object->IsAttributePresent(CKA_MODULUS) ||
      !(object->IsAttributePresent(CKA_PRIME_1) ||
        object->IsAttributePresent(CKA_PRIME_2)))
    return CKR_TEMPLATE_INCOMPLETE;

  // If HWSec doesn't support, fall back to software.
  int key_size_bits = object->GetAttributeString(CKA_MODULUS).length() * 8;
  if (!hwsec_ || !hwsec_->IsRSAModulusSupported(key_size_bits).ok()) {
    LOG(WARNING) << "WARNING: " << key_size_bits
                 << "-bit private key cannot be wrapped by the HWSec.";
    return CKR_OK;
  }

  // Get prime p or q
  string prime = object->IsAttributePresent(CKA_PRIME_1)
                     ? object->GetAttributeString(CKA_PRIME_1)
                     : object->GetAttributeString(CKA_PRIME_2);

  brillo::Blob exponent =
      brillo::BlobFromString(object->GetAttributeString(CKA_PUBLIC_EXPONENT));
  brillo::Blob modulus =
      brillo::BlobFromString(object->GetAttributeString(CKA_MODULUS));
  brillo::SecureBlob prime_blob(prime);
  brillo::SecureBlob auth_data =
      GenerateRandomSecureBlobSoftware(kDefaultAuthDataBytes);

  AllowDecrypt allow_decrypt = object->GetAttributeBool(CKA_DECRYPT, false)
                                   ? AllowDecrypt::kAllow
                                   : AllowDecrypt::kNotAllow;

  AllowSign allow_sign = object->GetAttributeBool(CKA_SIGN, false)
                             ? AllowSign::kAllow
                             : AllowSign::kNotAllow;

  // TODO(menghuan): Use Software key but report and have an auto-rewrapping
  // when WrapRSAKey() fail
  ASSIGN_OR_RETURN(
      const hwsec::ChapsFrontend::CreateKeyResult& result,
      hwsec_->WrapRSAKey(exponent, modulus, prime_blob, auth_data,
                         allow_decrypt, allow_sign),
      _.WithStatus<TPMError>("Failed to wrap RSA key in WrapRSAPrivateKey")
          .LogError()
          .As(CKR_FUNCTION_FAILED));

  object->SetAttributeString(kAuthDataAttribute, auth_data.to_string());
  object->SetAttributeString(kKeyBlobAttribute,
                             brillo::BlobToString(result.key_blob));
  object->RemoveAttribute(CKA_PRIVATE_EXPONENT);
  object->RemoveAttribute(CKA_PRIME_1);
  object->RemoveAttribute(CKA_PRIME_2);
  object->RemoveAttribute(CKA_EXPONENT_1);
  object->RemoveAttribute(CKA_EXPONENT_2);
  object->RemoveAttribute(CKA_COEFFICIENT);
  return CKR_OK;
}

CK_RV SessionImpl::WrapECCPrivateKey(Object* object) {
  if (!object->IsAttributePresent(CKA_EC_PARAMS) ||
      !object->IsAttributePresent(CKA_VALUE)) {
    return CKR_TEMPLATE_INCOMPLETE;
  }

  // Get OpenSSL NID
  crypto::ScopedEC_Key key = CreateECCPrivateKeyFromObject(object);
  const EC_GROUP* group = EC_KEY_get0_group(key.get());
  if (group == nullptr) {
    return CKR_FUNCTION_FAILED;
  }
  int curve_nid = EC_GROUP_get_curve_name(group);

  // If HWSec doesn't support, fall back to software.
  if (!hwsec_ || !hwsec_->IsECCurveSupported(curve_nid).ok()) {
    return CKR_OK;
  }

  // Get public key value
  crypto::ScopedBIGNUM x(BN_new()), y(BN_new());
  if (!x || !y) {
    LOG(ERROR) << "Failed to allocate BIGNUM.";
    return CKR_FUNCTION_FAILED;
  }
  const EC_POINT* ec_point = EC_KEY_get0_public_key(key.get());
  if (ec_point == nullptr) {
    return CKR_FUNCTION_FAILED;
  }
  if (!EC_POINT_get_affine_coordinates_GF2m(group, ec_point, x.get(), y.get(),
                                            nullptr)) {
    return CKR_FUNCTION_FAILED;
  }

  brillo::Blob x_point = brillo::BlobFromString(ConvertFromBIGNUM(x.get()));
  brillo::Blob y_point = brillo::BlobFromString(ConvertFromBIGNUM(y.get()));
  brillo::SecureBlob private_value(object->GetAttributeString(CKA_VALUE));
  brillo::SecureBlob auth_data =
      GenerateRandomSecureBlobSoftware(kDefaultAuthDataBytes);

  AllowDecrypt allow_decrypt = object->GetAttributeBool(CKA_DECRYPT, false)
                                   ? AllowDecrypt::kAllow
                                   : AllowDecrypt::kNotAllow;

  AllowSign allow_sign = object->GetAttributeBool(CKA_SIGN, false)
                             ? AllowSign::kAllow
                             : AllowSign::kNotAllow;

  ASSIGN_OR_RETURN(
      const hwsec::ChapsFrontend::CreateKeyResult& result,
      hwsec_->WrapECCKey(curve_nid, x_point, y_point, private_value, auth_data,
                         allow_decrypt, allow_sign),
      _.WithStatus<TPMError>("Failed to wrap ECC key in WrapECCPrivateKey")
          .LogError()
          .As(CKR_FUNCTION_FAILED));

  object->SetAttributeString(kAuthDataAttribute, auth_data.to_string());
  object->SetAttributeString(kKeyBlobAttribute,
                             brillo::BlobToString(result.key_blob));

  object->RemoveAttribute(CKA_VALUE);
  return CKR_OK;
}

CK_RV SessionImpl::WrapPrivateKey(Object* object) {
  if (!hwsec_ || object->GetAttributeBool(kForceSoftwareAttribute, false) ||
      object->GetObjectClass() != CKO_PRIVATE_KEY ||
      object->IsAttributePresent(kKeyBlobAttribute)) {
    // This object does not need to be wrapped.
    return CKR_OK;
  }
  int key_type = object->GetAttributeInt(CKA_KEY_TYPE, 0);
  if (key_type == CKK_RSA) {
    return WrapRSAPrivateKey(object);
  } else if (key_type == CKK_EC) {
    return WrapECCPrivateKey(object);
  } else {
    // If HWSec doesn't support, fall back to software.
    LOG(WARNING) << __func__ << ": Key type " << key_type
                 << " private key cannot be wrapped by the HWSec.";
    return CKR_OK;
  }
}

SessionImpl::OperationContext::OperationContext()
    : is_valid_(false),
      is_cipher_(false),
      is_digest_(false),
      is_hmac_(false),
      is_finished_(false),
      key_(nullptr) {}

SessionImpl::OperationContext::~OperationContext() {
  Clear();
}

void SessionImpl::OperationContext::Clear() {
  cipher_context_.reset();
  digest_context_.reset();
  hmac_context_.reset();
  is_valid_ = false;
  is_cipher_ = false;
  is_digest_ = false;
  is_hmac_ = false;
  is_incremental_ = false;
  is_finished_ = false;
  key_ = nullptr;
  data_.clear();
  parameter_.clear();
  cleanup_.RunAndReset();
}

}  // namespace chaps
