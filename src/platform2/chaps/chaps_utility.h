// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_CHAPS_UTILITY_H_
#define CHAPS_CHAPS_UTILITY_H_

#include <string.h>

#include <iterator>
#include <sstream>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/logging.h>
#include <brillo/secure_blob.h>
#include <crypto/scoped_openssl_types.h>

#include "chaps/chaps.h"
#include "pkcs11/cryptoki.h"

namespace chaps {

enum class DigestAlgorithm {
  MD5 = 0,
  SHA1 = 1,
  SHA256 = 2,
  SHA384 = 3,
  SHA512 = 4,
  // Should be put the last if it is not in kDigestAlgorithmEncoding
  NoDigest
};

enum class RsaPaddingScheme {
  UNKNOWN_PADDING_SCHEME = 0,
  RSASSA_PKCS1_V1_5,
  RSASSA_PSS,
};

// These strings are the DER encodings of the DigestInfo values for the
// supported digest algorithms.  See PKCS #1 v2.1: 9.2.
const struct {
  const char* encoding;
  size_t encoding_len;
} kDigestAlgorithmEncoding[] = {
    {/* MD5 = 0 */
     "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04"
     "\x10",
     18},
    {/* SHA1 = 1 */
     "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14", 15},
    {/* SHA256 = 2 */
     "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04"
     "\x20",
     19},
    {/* SHA384 = 3 */
     "\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04"
     "\x30",
     19},
    {/* SHA512 = 4 */
     "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04"
     "\x40",
     19},
};

// Get the algorithm ID for DigestInfo structure
inline std::string GetDigestAlgorithmEncoding(DigestAlgorithm alg) {
  size_t alg_index = static_cast<size_t>(alg);
  if (alg_index >= std::size(kDigestAlgorithmEncoding)) {
    return std::string();
  }
  return std::string(kDigestAlgorithmEncoding[alg_index].encoding,
                     kDigestAlgorithmEncoding[alg_index].encoding_len);
}

// Copy*ToCharBuffer copies to a space-padded CK_UTF8CHAR buffer (not
// NULL-terminated).
inline void CopyStringToCharBuffer(const std::string& source,
                                   CK_UTF8CHAR_PTR buffer,
                                   size_t buffer_size) {
  size_t copy_size = source.length();
  if (copy_size > buffer_size)
    copy_size = buffer_size;
  memset(buffer, ' ', buffer_size);
  if (copy_size > 0)
    memcpy(buffer, source.data(), copy_size);
}

inline void CopyVectorToCharBuffer(const std::vector<uint8_t>& source,
                                   CK_UTF8CHAR_PTR buffer,
                                   size_t buffer_size) {
  size_t copy_size = source.size();
  if (copy_size > buffer_size)
    copy_size = buffer_size;
  memset(buffer, ' ', buffer_size);
  if (copy_size > 0)
    memcpy(buffer, source.data(), copy_size);
}

// RVToString stringifies a PKCS #11 return value.  E.g. CKR_OK --> "CKR_OK".
EXPORT_SPEC const char* CK_RVToString(CK_RV value);

// AttributeToString stringifies a PKCS #11 attribute type.
EXPORT_SPEC std::string AttributeToString(CK_ATTRIBUTE_TYPE attribute);

// StringToAttribute tries to parse the input string |attribute_string| into an
// attribute |output|. It'll return true iff the |attribute_string| is parsed
// into attribute.
EXPORT_SPEC bool StringToAttribute(std::string attribute_string,
                                   CK_ATTRIBUTE_TYPE* output);

// ValueToString stringifies a PKCS #11 attribute value.
std::string ValueToString(CK_ATTRIBUTE_TYPE attribute,
                          const std::vector<uint8_t>& value);

// PrintAttributes parses serialized attributes and prints in the form:
// "{attribute1[=value1], attribute2[=value2]}".
EXPORT_SPEC std::string PrintAttributes(const std::vector<uint8_t>& serialized,
                                        bool is_value_enabled);

// PrintIntVector prints a vector in array literal form.  E.g. "{0, 1, 2}".
// ** A static cast to 'int' must be possible for type T.
template <class T>
std::string PrintIntVector(const std::vector<T>& v) {
  std::stringstream ss;
  ss << "{";
  for (size_t i = 0; i < v.size(); i++) {
    if (i > 0)
      ss << ", ";
    ss << static_cast<int>(v[i]);
  }
  ss << "}";
  return ss.str();
}

// This macro logs the current function name and the CK_RV value provided.
#define LOG_CK_RV(value) \
  LOG(ERROR) << __func__ << " - " << chaps::CK_RVToString(value);

// This macro is a conditional version of LOG_CK_RV which will log only if the
// value is not CKR_OK.
#define LOG_CK_RV_ERR(value)         \
  LOG_IF(ERROR, ((value) != CKR_OK)) \
      << __func__ << " - " << chaps::CK_RVToString(value);

// This macro logs and returns the given CK_RV value.
#define LOG_CK_RV_AND_RETURN(value) \
  {                                 \
    LOG_CK_RV(value);               \
    return (value);                 \
  }

// This macro logs and returns the given CK_RV value if the given condition is
// true.
#define LOG_CK_RV_AND_RETURN_IF(condition, value) \
  if (condition)                                  \
  LOG_CK_RV_AND_RETURN(value)

// This macro logs and returns the given CK_RV value if the value is not CKR_OK.
#define LOG_CK_RV_AND_RETURN_IF_ERR(value) \
  LOG_CK_RV_AND_RETURN_IF((value) != CKR_OK, value)

// This function constructs a string object from a CK_UTF8CHAR array.  The array
// does not need to be NULL-terminated. If buffer is NULL, an empty string will
// be returned.
inline std::string ConvertCharBufferToString(CK_UTF8CHAR_PTR buffer,
                                             size_t buffer_size) {
  if (!buffer)
    return std::string();
  return std::string(reinterpret_cast<char*>(buffer), buffer_size);
}

// This function constructs a string object from a CK_BYTE array.  The array
// does not need to be NULL-terminated. If buffer is NULL, an empty string will
// be returned.
inline std::string ConvertByteBufferToString(CK_BYTE_PTR buffer,
                                             CK_ULONG buffer_size) {
  if (!buffer)
    return std::string();
  return std::string(reinterpret_cast<char*>(buffer), buffer_size);
}

// This function converts a C string to a CK_UTF8CHAR_PTR which points to the
// same buffer.
inline CK_UTF8CHAR_PTR ConvertStringToCharBuffer(const char* str) {
  return reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(str));
}

// This function converts a C string to a uint8_t* which points to the same
// buffer.
inline uint8_t* ConvertStringToByteBuffer(const char* str) {
  return reinterpret_cast<uint8_t*>(const_cast<char*>(str));
}

// This function changes the container class for an array of bytes from string
// to vector.
inline std::vector<uint8_t> ConvertByteStringToVector(const std::string& s) {
  const uint8_t* front = reinterpret_cast<const uint8_t*>(s.data());
  return std::vector<uint8_t>(front, front + s.length());
}

// This function changes the container class for an array of bytes from vector
// to string.
inline std::string ConvertByteVectorToString(const std::vector<uint8_t>& v) {
  const char* front = reinterpret_cast<const char*>(v.data());
  return std::string(front, v.size());
}

// This function constructs a vector object from a CK_BYTE array.If buffer is
// NULL, an empty vector will be returned.
inline std::vector<uint8_t> ConvertByteBufferToVector(CK_BYTE_PTR buffer,
                                                      CK_ULONG buffer_size) {
  if (!buffer)
    return std::vector<uint8_t>();
  return std::vector<uint8_t>(buffer, buffer + buffer_size);
}

// This function returns a value composed of the bytes in the given string.
// It only accepts strings whose length is the same as the size of the given
// type. The type must be default-constructible.
template <typename T>
T ExtractFromByteString(const std::string& s) {
  CHECK(s.length() == sizeof(T));
  T ret;
  memcpy(&ret, s.data(), sizeof(ret));
  return ret;
}

// This class preserves a variable that needs to be temporarily converted to
// another type.
template <class PreservedType, class TempType>
class PreservedValue {
 public:
  explicit PreservedValue(PreservedType* value) {
    CHECK(value);
    preserved_ = value;
    temp_ = static_cast<TempType>(*value);
  }
  ~PreservedValue() { *preserved_ = static_cast<PreservedType>(temp_); }
  // Allow an implicit cast to a pointer to the temporary value.
  operator TempType*() { return &temp_; }

 private:
  PreservedType* preserved_;
  TempType temp_;
};

typedef PreservedValue<CK_ULONG, uint64_t> PreservedCK_ULONG;
typedef PreservedValue<uint64_t, CK_ULONG> PreservedUint64_t;

class PreservedByteVector {
 public:
  explicit PreservedByteVector(std::vector<uint8_t>* value) {
    CHECK(value);
    preserved_ = value;
    temp_ = ConvertByteVectorToString(*value);
  }
  ~PreservedByteVector() { *preserved_ = ConvertByteStringToVector(temp_); }
  // Allow an implicit cast to a string pointer.
  operator std::string*() { return &temp_; }

 private:
  std::vector<uint8_t>* preserved_;
  std::string temp_;
};

// Computes and returns a SHA-1 hash of the given input.
EXPORT_SPEC std::string Sha1(const std::string& input);
EXPORT_SPEC brillo::SecureBlob Sha1(const brillo::SecureBlob& input);

// Computes and returns a SHA-256 hash of the given input.
EXPORT_SPEC brillo::SecureBlob Sha256(const brillo::SecureBlob& input);

// Computes and returns a SHA-512 hash of the given input.
EXPORT_SPEC brillo::SecureBlob Sha512(const brillo::SecureBlob& input);

// Initializes the OpenSSL library on construction and terminates the library on
// destruction.
class EXPORT_SPEC ScopedOpenSSL {
 public:
  ScopedOpenSSL();
  ~ScopedOpenSSL();
};

// Returns a description of the OpenSSL error stack.
EXPORT_SPEC std::string GetOpenSSLError();

// Computes a message authentication code using HMAC and SHA-512.
EXPORT_SPEC std::string HmacSha512(const std::string& input,
                                   const brillo::SecureBlob& key);

// Performs AES-256 encryption / decryption in CBC mode with PKCS padding. If
// 'iv' is left empty, a random IV will be generated and appended to the cipher-
// text on encryption.
EXPORT_SPEC bool RunCipher(bool is_encrypt,
                           const brillo::SecureBlob& key,
                           const std::string& iv,
                           const std::string& input,
                           std::string* output);

// Returns true if the given attribute type has an integral value.
EXPORT_SPEC bool IsIntegralAttribute(CK_ATTRIBUTE_TYPE type);

// TODO(crbug/916023): Move pure OpenSSL conversion wrappers to a cross daemon
// library.
//
// OpenSSL type <--> raw data string
//

// Convert OpenSSL BIGNUM |bignum| to string.
// Padding the result to at least |pad_to_length| bytes long.
// Return empty string on error.
EXPORT_SPEC std::string ConvertFromBIGNUM(const BIGNUM* bignum,
                                          int pad_to_length = 0);

// Convert string |big_integer| into pre-allocated OpenSSL BIGNUM.
// Returns false if big_integer is empty, b is nullptr, or conversion fails.
EXPORT_SPEC bool ConvertToBIGNUM(const std::string& big_integer, BIGNUM* b);

// Convert string |big_integer| into pre-allocated OpenSSL BIGNUM.
// Returns false if big_integer is empty, b is nullptr, or conversion fails.
EXPORT_SPEC bool ConvertBlobToBIGNUM(const brillo::Blob& big_integer,
                                     BIGNUM* b);

// Convert the public key consisting of |modulus| and |exponent| to an RSA
// object and return it on success, otherwise, return nullptr.
EXPORT_SPEC crypto::ScopedRSA NumberToScopedRsa(const std::string& modulus,
                                                const std::string& exponent);

//
// OpenSSL type <--> DER-encoded string
//

// Get the ECParameters from |key| and DER-encode to a string.
EXPORT_SPEC std::string GetECParametersAsString(const EC_KEY* key);
// Get the EC_Point from |key| and DER-encode to a string.
EXPORT_SPEC std::string GetECPointAsString(const EC_KEY* key);

//
// OpenSSL type <--> PKCS #11 Attributes
//

// Create a OpenSSL EC_KEY from a CKA_EC_PARAMS string (which is compatible
// with DER-encoded OpenSSL ECParameters)
EXPORT_SPEC crypto::ScopedEC_KEY CreateECCKeyFromEC_PARAMS(
    const std::string& ec_params);

// In OpenSSL 1.1, i2o_ECPublicKey now takes a const EC_KEY *, which breaks
// the function signature expectation of ConvertOpenSSLObjectToString, so
// wrap it with a helper that still takes a non-const pointer.
static inline int i2o_ECPublicKey_nc(EC_KEY* key, unsigned char** buf) {
  return i2o_ECPublicKey(key, buf);
}

// Get the chaps internal digest algorithm type from PKCS#11 mechanism type.
EXPORT_SPEC chaps::DigestAlgorithm GetDigestAlgorithm(
    CK_MECHANISM_TYPE mechanism);

// Return the OpenSSL Digest associated with the given DigestAlgorithm.
EXPORT_SPEC const EVP_MD* GetOpenSSLDigest(DigestAlgorithm alg);

// Return the OpenSSL Digest associated with the given PKCS#11 Mechanism.
EXPORT_SPEC const EVP_MD* GetOpenSSLDigestForMechanism(
    CK_MECHANISM_TYPE mechanism);

// Return the RSA padding scheme for the given |mechanism|.
EXPORT_SPEC RsaPaddingScheme
GetSigningSchemeForMechanism(const CK_MECHANISM_TYPE mechanism);

// Return the OpenSSL Digest associated with the given PKCS#11 MGF function
// identifier.
const EVP_MD* GetOpenSSLDigestForMGF(const CK_RSA_PKCS_MGF_TYPE mgf);

// This method parse the PKCS#11 mechanism parameters specified in
// |mechanism_parameter| and interpret it as CK_RSA_PKCS_PSS_PARAMS and check
// its sanity. Return false on error. Otherwise, return true and set the 3
// output parameters if the check is successful.
EXPORT_SPEC bool ParseRSAPSSParams(
    const std::string& mechanism_parameter,
    const DigestAlgorithm signing_digest_algorithm_in,
    const CK_RSA_PKCS_PSS_PARAMS** pss_params_out,
    const EVP_MD** mgf1_hash_out,
    DigestAlgorithm* digest_algorithm_out);

}  // namespace chaps

#endif  // CHAPS_CHAPS_UTILITY_H_
