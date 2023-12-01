// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "attestation/server/pkcs11_key_store.h"

#include <iterator>
#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_util.h>
#include <brillo/cryptohome.h>
#include <chaps/isolate.h>
#include <chaps/pkcs11/cryptoki.h>
#include <chaps/token_manager_client.h>
#include <crypto/libcrypto-compat.h>
#include <crypto/scoped_openssl_types.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

namespace attestation {

namespace {

std::string Sha1(const std::string& input) {
  unsigned char output[SHA_DIGEST_LENGTH];
  SHA1(reinterpret_cast<const unsigned char*>(input.data()), input.size(),
       output);
  return std::string(reinterpret_cast<char*>(output), SHA_DIGEST_LENGTH);
}

bool IsSupportedRegisterKeyType(KeyType key_type) {
  return key_type == KEY_TYPE_RSA || key_type == KEY_TYPE_ECC;
}

CK_KEY_TYPE ToPkcs11KeyType(KeyType key_type) {
  switch (key_type) {
    case KEY_TYPE_RSA:
      return CKK_RSA;
    case KEY_TYPE_ECC:
      return CKK_EC;
    default:
      LOG(DFATAL) << "Unsupported key type input: " << key_type;
      return CKK_RSA;
  }
}

typedef crypto::ScopedOpenSSL<X509, X509_free> ScopedX509;

}  // namespace

// An arbitrary application ID to identify PKCS #11 objects.
const char kApplicationID[] = "CrOS_d5bbc079d2497110feadfc97c40d718ae46f4658";

// A helper class to scope a PKCS #11 session.
class ScopedSession {
 public:
  explicit ScopedSession(CK_SLOT_ID slot) : handle_(CK_INVALID_HANDLE) {
    CK_RV rv = C_Initialize(nullptr);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
      // This may be normal in a test environment.
      LOG(INFO) << "PKCS #11 is not available.";
      return;
    }
    CK_FLAGS flags = CKF_RW_SESSION | CKF_SERIAL_SESSION;
    if (C_OpenSession(slot, flags, nullptr, nullptr, &handle_) != CKR_OK) {
      LOG(ERROR) << "Failed to open PKCS #11 session.";
      return;
    }
  }
  ScopedSession(const ScopedSession&) = delete;
  ScopedSession& operator=(const ScopedSession&) = delete;

  ~ScopedSession() {
    if (IsValid() && (C_CloseSession(handle_) != CKR_OK)) {
      LOG(WARNING) << "Failed to close PKCS #11 session.";
      handle_ = CK_INVALID_HANDLE;
    }
  }

  CK_SESSION_HANDLE handle() const { return handle_; }

  bool IsValid() const { return (handle_ != CK_INVALID_HANDLE); }

 private:
  CK_SESSION_HANDLE handle_;
};

Pkcs11KeyStore::Pkcs11KeyStore(chaps::TokenManagerClient* token_manager)
    : token_manager_(token_manager) {}

Pkcs11KeyStore::~Pkcs11KeyStore() {}

bool Pkcs11KeyStore::Read(const std::string& username,
                          const std::string& key_name,
                          std::string* key_data) {
  CK_SLOT_ID slot;
  if (!GetUserSlot(username, &slot)) {
    LOG(ERROR) << "Pkcs11KeyStore: No token for user.";
    return false;
  }
  ScopedSession session(slot);
  if (!session.IsValid()) {
    LOG(ERROR) << "Pkcs11KeyStore: Failed to open token session.";
    return false;
  }
  CK_OBJECT_HANDLE key_handle = FindObject(session.handle(), key_name);
  if (key_handle == CK_INVALID_HANDLE) {
    LOG(WARNING) << "Pkcs11KeyStore: Key does not exist: " << key_name;
    return false;
  }
  // First get the attribute with a NULL buffer which will give us the length.
  CK_ATTRIBUTE attribute = {CKA_VALUE, nullptr, 0};
  if (C_GetAttributeValue(session.handle(), key_handle, &attribute, 1) !=
      CKR_OK) {
    LOG(ERROR) << "Pkcs11KeyStore: Failed to read key data: " << key_name;
    return false;
  }
  key_data->resize(attribute.ulValueLen);
  attribute.pValue = std::data(*key_data);
  if (C_GetAttributeValue(session.handle(), key_handle, &attribute, 1) !=
      CKR_OK) {
    LOG(ERROR) << "Pkcs11KeyStore: Failed to read key data: " << key_name;
    return false;
  }
  key_data->resize(attribute.ulValueLen);
  return true;
}

bool Pkcs11KeyStore::Write(const std::string& username,
                           const std::string& key_name,
                           const std::string& key_data) {
  // Delete any existing key with the same name.
  if (!Delete(username, key_name)) {
    return false;
  }
  CK_SLOT_ID slot;
  if (!GetUserSlot(username, &slot)) {
    LOG(ERROR) << "Pkcs11KeyStore: No token for user.";
    return false;
  }
  ScopedSession session(slot);
  if (!session.IsValid()) {
    LOG(ERROR) << "Pkcs11KeyStore: Failed to open token session.";
    return false;
  }
  std::string mutable_key_name(key_name);
  std::string mutable_key_data(key_data);
  std::string mutable_application_id(kApplicationID);
  // Create a new data object for the key.
  CK_OBJECT_CLASS object_class = CKO_DATA;
  CK_BBOOL true_value = CK_TRUE;
  CK_BBOOL false_value = CK_FALSE;
  CK_ATTRIBUTE attributes[] = {
      {CKA_CLASS, &object_class, sizeof(object_class)},
      {CKA_LABEL, std::data(mutable_key_name), mutable_key_name.size()},
      {CKA_VALUE, std::data(mutable_key_data), mutable_key_data.size()},
      {CKA_APPLICATION, std::data(mutable_application_id),
       mutable_application_id.size()},
      {CKA_TOKEN, &true_value, sizeof(true_value)},
      {CKA_PRIVATE, &true_value, sizeof(true_value)},
      {CKA_MODIFIABLE, &false_value, sizeof(false_value)}};
  CK_OBJECT_HANDLE key_handle = CK_INVALID_HANDLE;
  if (C_CreateObject(session.handle(), attributes, std::size(attributes),
                     &key_handle) != CKR_OK) {
    LOG(ERROR) << "Pkcs11KeyStore: Failed to write key data: " << key_name;
    return false;
  }
  return true;
}

bool Pkcs11KeyStore::Delete(const std::string& username,
                            const std::string& key_name) {
  CK_SLOT_ID slot;
  if (!GetUserSlot(username, &slot)) {
    LOG(ERROR) << "Pkcs11KeyStore: No token for user.";
    return false;
  }
  ScopedSession session(slot);
  if (!session.IsValid()) {
    LOG(ERROR) << "Pkcs11KeyStore: Failed to open token session.";
    return false;
  }
  CK_OBJECT_HANDLE key_handle = FindObject(session.handle(), key_name);
  if (key_handle != CK_INVALID_HANDLE) {
    if (C_DestroyObject(session.handle(), key_handle) != CKR_OK) {
      LOG(ERROR) << "Pkcs11KeyStore: Failed to delete key data.";
      return false;
    }
  }
  return true;
}

bool Pkcs11KeyStore::DeleteByPrefix(const std::string& username,
                                    const std::string& key_prefix) {
  CK_SLOT_ID slot;
  if (!GetUserSlot(username, &slot)) {
    LOG(ERROR) << "Pkcs11KeyStore: No token for user.";
    return false;
  }
  ScopedSession session(slot);
  if (!session.IsValid()) {
    LOG(ERROR) << "Pkcs11KeyStore: Failed to open token session.";
    return false;
  }
  EnumObjectsCallback callback =
      base::BindRepeating(&Pkcs11KeyStore::DeleteIfMatchesPrefix,
                          base::Unretained(this), session.handle(), key_prefix);
  if (!EnumObjects(session.handle(), callback)) {
    LOG(ERROR) << "Pkcs11KeyStore: Failed to delete key data.";
    return false;
  }
  return true;
}

bool Pkcs11KeyStore::Register(const std::string& username,
                              const std::string& label,
                              KeyType key_type,
                              KeyUsage key_usage,
                              const std::string& private_key_blob,
                              const std::string& public_key_der,
                              const std::string& certificate) {
  const CK_ATTRIBUTE_TYPE kKeyBlobAttribute = CKA_VENDOR_DEFINED + 1;

  if (!IsSupportedRegisterKeyType(key_type)) {
    LOG(ERROR) << "Pkcs11KeyStore: Unsupported key type: " << key_type << ".";
    return false;
  }
  CK_SLOT_ID slot;
  if (!GetUserSlot(username, &slot)) {
    LOG(ERROR) << "Pkcs11KeyStore: No token for user.";
    return false;
  }
  ScopedSession session(slot);
  if (!session.IsValid()) {
    LOG(ERROR) << "Pkcs11KeyStore: Failed to open token session.";
    return false;
  }

  // Extract the modulus from the public key if it's RSA; or, extract the ecc
  // parameters and the ecc point if it's ECC. We do the parsing here because
  // both private and public key objects need them.
  std::string modulus;
  std::string ecc_params, ecc_point;
  // The value of the key's CKA_ID attribute as NSS would compute it using
  // PK11_MakeIDFromPubKey.
  std::string cka_id;
  const unsigned char* asn1_ptr =
      reinterpret_cast<const unsigned char*>(public_key_der.data());
  if (key_type == KEY_TYPE_RSA) {
    crypto::ScopedRSA public_key(
        d2i_RSAPublicKey(nullptr, &asn1_ptr, public_key_der.size()));
    if (!public_key.get()) {
      LOG(ERROR) << "Pkcs11KeyStore: Failed to decode RSA public key.";
      return false;
    }
    modulus.resize(RSA_size(public_key.get()), 0);
    const BIGNUM* n = nullptr;
    RSA_get0_key(public_key.get(), &n, nullptr, nullptr);
    int length =
        BN_bn2bin(n, reinterpret_cast<unsigned char*>(std::data(modulus)));
    if (length <= 0) {
      LOG(ERROR) << "Pkcs11KeyStore: Failed to extract public key modulus.";
      return false;
    }
    modulus.resize(length);
    cka_id = Sha1(modulus);
  } else if (key_type == KEY_TYPE_ECC) {
    crypto::ScopedEC_KEY public_key(
        d2i_EC_PUBKEY(nullptr, &asn1_ptr, public_key_der.size()));
    if (!public_key.get()) {
      LOG(ERROR) << "Pkcs11KeyStore: Failed to decode ECC public key.";
      return false;
    }
    int output_size = i2d_ECParameters(public_key.get(), nullptr);
    if (output_size <= 0) {
      LOG(ERROR) << "Pkcs11KeyStore: Failed to call i2d_ECParameters to get "
                    "output size.";
      return false;
    }
    std::unique_ptr<uint8_t[]> output =
        std::make_unique<uint8_t[]>(output_size);
    uint8_t* output_buffer = output.get();
    if (i2d_ECParameters(public_key.get(), &output_buffer) <= 0) {
      LOG(ERROR) << "Pkcs11KeyStore: Failed to call i2d_ECParameters.";
      return false;
    }
    ecc_params.assign(output.get(), output.get() + output_size);

    output_size = i2o_ECPublicKey(public_key.get(), nullptr);
    if (output_size <= 0) {
      LOG(ERROR) << "Pkcs11KeyStore: Failed to call i2o_ECPublicKey to get "
                    "output size.";
      return false;
    }
    output = std::make_unique<uint8_t[]>(output_size);
    output_buffer = output.get();
    if (i2o_ECPublicKey(public_key.get(), &output_buffer) <= 0) {
      LOG(ERROR) << "Pkcs11KeyStore: Failed to call i2o_ECPublicKey.";
      return false;
    }

    // CKA_EC_POINT is DER-encoded ANSI X9.62 ECPoint value. The format should
    // be 04 LEN 04 X Y, where the first 04 is the octet string tag, LEN is the
    // the content length, the second 04 identifies the uncompressed form, and X
    // and Y are the point coordinates.
    //
    // i2o_ECPublicKey() returns only the content (04 X Y)
    crypto::ScopedOpenSSL<ASN1_OCTET_STRING, ASN1_OCTET_STRING_free>
        asn1_oct_string(ASN1_OCTET_STRING_new());
    if (!asn1_oct_string) {
      LOG(ERROR) << "Pkcs11KeyStore: Failed to call ASN1_OCTET_STRING_new.";
      return false;
    }
    if (!ASN1_OCTET_STRING_set(asn1_oct_string.get(), output.get(),
                               output_size)) {
      LOG(ERROR) << "Pkcs11KeyStore: Failed to call ASN1_OCTET_STRING_set.";
      return false;
    }
    //  CKA_ID for ECC key is Sha1(04 X Y)
    cka_id = Sha1(std::string(asn1_oct_string->data,
                              asn1_oct_string->data + asn1_oct_string->length));
    output_size = i2d_ASN1_OCTET_STRING(asn1_oct_string.get(), nullptr);
    if (output_size <= 0) {
      LOG(ERROR) << "Pkcs11KeyStore: Failed to call i2d_ASN1_OCTET_STRING to "
                    "get output size.";
      return false;
    }
    output = std::make_unique<uint8_t[]>(output_size);
    output_buffer = output.get();

    if (i2d_ASN1_OCTET_STRING(asn1_oct_string.get(), &output_buffer) <= 0) {
      LOG(ERROR) << "Pkcs11KeyStore: Failed to call i2d_ASN1_OCTET_STRING.";
      return false;
    }
    ecc_point.assign(output.get(), output.get() + output_size);
  } else {
    NOTREACHED();
  }

  // Construct a PKCS #11 template for the public key object.
  CK_BBOOL true_value = CK_TRUE;
  CK_BBOOL false_value = CK_FALSE;
  CK_KEY_TYPE p11_key_type = ToPkcs11KeyType(key_type);
  CK_OBJECT_CLASS public_key_class = CKO_PUBLIC_KEY;
  std::string mutable_label(label);
  CK_ULONG modulus_bits = modulus.size() * 8;
  CK_BBOOL sign_usage = (key_usage == KEY_USAGE_SIGN);
  CK_BBOOL decrypt_usage = (key_usage == KEY_USAGE_DECRYPT);
  unsigned char public_exponent[] = {1, 0, 1};
  std::vector<CK_ATTRIBUTE> public_key_attributes = {
      {CKA_CLASS, &public_key_class, sizeof(public_key_class)},
      {CKA_TOKEN, &true_value, sizeof(true_value)},
      {CKA_DERIVE, &false_value, sizeof(false_value)},
      {CKA_WRAP, &false_value, sizeof(false_value)},
      {CKA_VERIFY, &sign_usage, sizeof(sign_usage)},
      {CKA_VERIFY_RECOVER, &false_value, sizeof(false_value)},
      {CKA_ENCRYPT, &decrypt_usage, sizeof(decrypt_usage)},
      {CKA_KEY_TYPE, &p11_key_type, sizeof(p11_key_type)},
      {CKA_ID, std::data(cka_id), cka_id.size()},
      {CKA_LABEL, std::data(mutable_label), mutable_label.size()},
  };
  if (key_type == KEY_TYPE_RSA) {
    const CK_ATTRIBUTE rsa_key_attributes[] = {
        {CKA_MODULUS_BITS, &modulus_bits, sizeof(modulus_bits)},
        {CKA_PUBLIC_EXPONENT, public_exponent, std::size(public_exponent)},
        {CKA_MODULUS, std::data(modulus), modulus.size()},
    };
    public_key_attributes.insert(public_key_attributes.end(),
                                 std::begin(rsa_key_attributes),
                                 std::end(rsa_key_attributes));
  } else if (key_type == KEY_TYPE_ECC) {
    const CK_ATTRIBUTE ecc_key_attributes[] = {
        {CKA_EC_PARAMS, const_cast<char*>(ecc_params.c_str()),
         ecc_params.length()},
        {CKA_EC_POINT, const_cast<char*>(ecc_point.c_str()),
         ecc_point.length()},
    };
    public_key_attributes.insert(public_key_attributes.end(),
                                 std::begin(ecc_key_attributes),
                                 std::end(ecc_key_attributes));
  } else {
    NOTREACHED();
  }

  CK_OBJECT_HANDLE object_handle = CK_INVALID_HANDLE;
  if (C_CreateObject(session.handle(), public_key_attributes.data(),
                     public_key_attributes.size(), &object_handle) != CKR_OK) {
    LOG(ERROR) << "Pkcs11KeyStore: Failed to create public key object.";
    return false;
  }

  // Construct a PKCS #11 template for the private key object.
  std::string mutable_private_key_blob(private_key_blob);
  CK_OBJECT_CLASS private_key_class = CKO_PRIVATE_KEY;
  std::vector<CK_ATTRIBUTE> private_key_attributes = {
      {CKA_CLASS, &private_key_class, sizeof(private_key_class)},
      {CKA_TOKEN, &true_value, sizeof(true_value)},
      {CKA_PRIVATE, &true_value, sizeof(true_value)},
      {CKA_SENSITIVE, &true_value, sizeof(true_value)},
      {CKA_EXTRACTABLE, &false_value, sizeof(false_value)},
      {CKA_DERIVE, &false_value, sizeof(false_value)},
      {CKA_UNWRAP, &false_value, sizeof(false_value)},
      {CKA_SIGN, &sign_usage, sizeof(sign_usage)},
      {CKA_SIGN_RECOVER, &false_value, sizeof(false_value)},
      {CKA_DECRYPT, &decrypt_usage, sizeof(decrypt_usage)},
      {CKA_KEY_TYPE, &p11_key_type, sizeof(p11_key_type)},
      {CKA_ID, std::data(cka_id), cka_id.size()},
      {CKA_LABEL, std::data(mutable_label), mutable_label.size()},
      {kKeyBlobAttribute, std::data(mutable_private_key_blob),
       mutable_private_key_blob.size()},
  };
  if (key_type == KEY_TYPE_RSA) {
    const CK_ATTRIBUTE rsa_key_attributes[] = {
        {CKA_PUBLIC_EXPONENT, public_exponent, std::size(public_exponent)},
        {CKA_MODULUS, std::data(modulus), modulus.size()},
    };
    private_key_attributes.insert(private_key_attributes.end(),
                                  std::begin(rsa_key_attributes),
                                  std::end(rsa_key_attributes));
  } else if (key_type == KEY_TYPE_ECC) {
    const CK_ATTRIBUTE ecc_key_attributes[] = {
        {CKA_EC_PARAMS, const_cast<char*>(ecc_params.c_str()),
         ecc_params.length()},
        {CKA_EC_POINT, const_cast<char*>(ecc_point.c_str()),
         ecc_point.length()},
    };
    private_key_attributes.insert(private_key_attributes.end(),
                                  std::begin(ecc_key_attributes),
                                  std::end(ecc_key_attributes));
  } else {
    NOTREACHED();
  }
  if (C_CreateObject(session.handle(), private_key_attributes.data(),
                     private_key_attributes.size(), &object_handle) != CKR_OK) {
    LOG(ERROR) << "Pkcs11KeyStore: Failed to create private key object.";
    return false;
  }

  if (!certificate.empty()) {
    std::string subject;
    std::string issuer;
    std::string serial_number;
    if (!GetCertificateFields(certificate, &subject, &issuer, &serial_number)) {
      LOG(WARNING) << "Pkcs11KeyStore: Failed to find certificate fields.";
    }
    // Construct a PKCS #11 template for a certificate object.
    std::string mutable_certificate = certificate;
    CK_OBJECT_CLASS certificate_class = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE certificate_type = CKC_X_509;
    CK_ATTRIBUTE certificate_attributes[] = {
        {CKA_CLASS, &certificate_class, sizeof(certificate_class)},
        {CKA_TOKEN, &true_value, sizeof(true_value)},
        {CKA_PRIVATE, &false_value, sizeof(false_value)},
        {CKA_ID, std::data(cka_id), cka_id.size()},
        {CKA_LABEL, std::data(mutable_label), mutable_label.size()},
        {CKA_CERTIFICATE_TYPE, &certificate_type, sizeof(certificate_type)},
        {CKA_SUBJECT, std::data(subject), subject.size()},
        {CKA_ISSUER, std::data(issuer), issuer.size()},
        {CKA_SERIAL_NUMBER, std::data(serial_number), serial_number.size()},
        {CKA_VALUE, std::data(mutable_certificate),
         mutable_certificate.size()}};

    if (C_CreateObject(session.handle(), certificate_attributes,
                       std::size(certificate_attributes),
                       &object_handle) != CKR_OK) {
      LOG(ERROR) << "Pkcs11KeyStore: Failed to create certificate object.";
      return false;
    }
  }

  return true;
}

bool Pkcs11KeyStore::RegisterCertificate(const std::string& username,
                                         const std::string& certificate) {
  CK_SLOT_ID slot;
  if (!GetUserSlot(username, &slot)) {
    LOG(ERROR) << "Pkcs11KeyStore: No token for user.";
    return false;
  }
  ScopedSession session(slot);
  if (!session.IsValid()) {
    LOG(ERROR) << "Pkcs11KeyStore: Failed to open token session.";
    return false;
  }

  if (DoesCertificateExist(session.handle(), certificate)) {
    LOG(INFO) << "Pkcs11KeyStore: Certificate already exists.";
    return true;
  }
  std::string subject;
  std::string issuer;
  std::string serial_number;
  if (!GetCertificateFields(certificate, &subject, &issuer, &serial_number)) {
    LOG(WARNING) << "Pkcs11KeyStore: Failed to find certificate fields.";
  }
  // Construct a PKCS #11 template for a certificate object.
  std::string mutable_certificate = certificate;
  CK_OBJECT_CLASS certificate_class = CKO_CERTIFICATE;
  CK_CERTIFICATE_TYPE certificate_type = CKC_X_509;
  CK_BBOOL true_value = CK_TRUE;
  CK_BBOOL false_value = CK_FALSE;
  CK_ATTRIBUTE certificate_attributes[] = {
      {CKA_CLASS, &certificate_class, sizeof(certificate_class)},
      {CKA_TOKEN, &true_value, sizeof(true_value)},
      {CKA_PRIVATE, &false_value, sizeof(false_value)},
      {CKA_CERTIFICATE_TYPE, &certificate_type, sizeof(certificate_type)},
      {CKA_SUBJECT, std::data(subject), subject.size()},
      {CKA_ISSUER, std::data(issuer), issuer.size()},
      {CKA_SERIAL_NUMBER, std::data(serial_number), serial_number.size()},
      {CKA_VALUE, std::data(mutable_certificate), mutable_certificate.size()}};
  CK_OBJECT_HANDLE object_handle = CK_INVALID_HANDLE;
  if (C_CreateObject(session.handle(), certificate_attributes,
                     std::size(certificate_attributes),
                     &object_handle) != CKR_OK) {
    LOG(ERROR) << "Pkcs11KeyStore: Failed to create certificate object.";
    return false;
  }
  return true;
}

CK_OBJECT_HANDLE Pkcs11KeyStore::FindObject(CK_SESSION_HANDLE session_handle,
                                            const std::string& key_name) {
  // Assemble a search template.
  std::string mutable_key_name(key_name);
  std::string mutable_application_id(kApplicationID);
  CK_OBJECT_CLASS object_class = CKO_DATA;
  CK_BBOOL true_value = CK_TRUE;
  CK_BBOOL false_value = CK_FALSE;
  CK_ATTRIBUTE attributes[] = {
      {CKA_CLASS, &object_class, sizeof(object_class)},
      {CKA_LABEL, std::data(mutable_key_name), mutable_key_name.size()},
      {CKA_APPLICATION, std::data(mutable_application_id),
       mutable_application_id.size()},
      {CKA_TOKEN, &true_value, sizeof(true_value)},
      {CKA_PRIVATE, &true_value, sizeof(true_value)},
      {CKA_MODIFIABLE, &false_value, sizeof(false_value)}};
  CK_OBJECT_HANDLE key_handle = CK_INVALID_HANDLE;
  CK_ULONG count = 0;
  if ((C_FindObjectsInit(session_handle, attributes, std::size(attributes)) !=
       CKR_OK) ||
      (C_FindObjects(session_handle, &key_handle, 1, &count) != CKR_OK) ||
      (C_FindObjectsFinal(session_handle) != CKR_OK)) {
    LOG(ERROR) << "Key search failed: " << key_name;
    return CK_INVALID_HANDLE;
  }
  if (count == 1)
    return key_handle;
  return CK_INVALID_HANDLE;
}

bool Pkcs11KeyStore::GetUserSlot(const std::string& username,
                                 CK_SLOT_ID_PTR slot) {
  const char kChapsDaemonName[] = "chaps";
  const char kChapsSystemToken[] = "/var/lib/chaps";
  base::FilePath token_path =
      username.empty()
          ? base::FilePath(kChapsSystemToken)
          : brillo::cryptohome::home::GetDaemonStorePath(
                brillo::cryptohome::home::Username(username), kChapsDaemonName);
  CK_RV rv;
  rv = C_Initialize(nullptr);
  if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
    LOG(WARNING) << __func__ << ": C_Initialize failed.";
    return false;
  }
  CK_ULONG num_slots = 0;
  rv = C_GetSlotList(CK_TRUE, nullptr, &num_slots);
  if (rv != CKR_OK) {
    LOG(WARNING) << __func__ << ": C_GetSlotList(nullptr) failed.";
    return false;
  }
  std::unique_ptr<CK_SLOT_ID[]> slot_list(new CK_SLOT_ID[num_slots]);
  rv = C_GetSlotList(CK_TRUE, slot_list.get(), &num_slots);
  if (rv != CKR_OK) {
    LOG(WARNING) << __func__ << ": C_GetSlotList failed.";
    return false;
  }
  // Look through all slots for |token_path|.
  for (CK_ULONG i = 0; i < num_slots; ++i) {
    base::FilePath slot_path;
    if (token_manager_->GetTokenPath(
            chaps::IsolateCredentialManager::GetDefaultIsolateCredential(),
            slot_list[i], &slot_path) &&
        (token_path == slot_path)) {
      *slot = slot_list[i];
      return true;
    }
  }
  LOG(WARNING) << __func__ << ": Path not found.";
  return false;
}

bool Pkcs11KeyStore::EnumObjects(
    CK_SESSION_HANDLE session_handle,
    const Pkcs11KeyStore::EnumObjectsCallback& callback) {
  std::string mutable_application_id(kApplicationID);
  // Assemble a search template.
  CK_OBJECT_CLASS object_class = CKO_DATA;
  CK_BBOOL true_value = CK_TRUE;
  CK_BBOOL false_value = CK_FALSE;
  CK_ATTRIBUTE attributes[] = {
      {CKA_CLASS, &object_class, sizeof(object_class)},
      {CKA_APPLICATION, std::data(mutable_application_id),
       mutable_application_id.size()},
      {CKA_TOKEN, &true_value, sizeof(true_value)},
      {CKA_PRIVATE, &true_value, sizeof(true_value)},
      {CKA_MODIFIABLE, &false_value, sizeof(false_value)}};
  const CK_ULONG kMaxHandles = 100;  // Arbitrary.
  CK_OBJECT_HANDLE handles[kMaxHandles];
  CK_ULONG count = 0;
  if ((C_FindObjectsInit(session_handle, attributes, std::size(attributes)) !=
       CKR_OK) ||
      (C_FindObjects(session_handle, handles, kMaxHandles, &count) != CKR_OK)) {
    LOG(ERROR) << "Key search failed.";
    return false;
  }
  while (count > 0) {
    for (CK_ULONG i = 0; i < count; ++i) {
      std::string key_name;
      if (!GetKeyName(session_handle, handles[i], &key_name)) {
        LOG(WARNING) << "Found key object but failed to get name.";
        continue;
      }
      if (!callback.Run(key_name, handles[i]))
        return false;
    }
    if (C_FindObjects(session_handle, handles, kMaxHandles, &count) != CKR_OK) {
      LOG(ERROR) << "Key search continuation failed.";
      return false;
    }
  }
  if (C_FindObjectsFinal(session_handle) != CKR_OK) {
    LOG(WARNING) << "Failed to finalize key search.";
  }
  return true;
}

bool Pkcs11KeyStore::GetKeyName(CK_SESSION_HANDLE session_handle,
                                CK_OBJECT_HANDLE object_handle,
                                std::string* key_name) {
  CK_ATTRIBUTE attribute = {CKA_LABEL, nullptr, 0};
  if (C_GetAttributeValue(session_handle, object_handle, &attribute, 1) !=
      CKR_OK) {
    LOG(ERROR) << "C_GetAttributeValue(CKA_LABEL) [length] failed.";
    return false;
  }
  key_name->resize(attribute.ulValueLen);
  attribute.pValue = std::data(*key_name);
  if (C_GetAttributeValue(session_handle, object_handle, &attribute, 1) !=
      CKR_OK) {
    LOG(ERROR) << "C_GetAttributeValue(CKA_LABEL) failed.";
    return false;
  }
  return true;
}

bool Pkcs11KeyStore::DeleteIfMatchesPrefix(CK_SESSION_HANDLE session_handle,
                                           const std::string& key_prefix,
                                           const std::string& key_name,
                                           CK_OBJECT_HANDLE object_handle) {
  if (base::StartsWith(key_name, key_prefix, base::CompareCase::SENSITIVE)) {
    if (C_DestroyObject(session_handle, object_handle) != CKR_OK) {
      LOG(ERROR) << "C_DestroyObject failed.";
      return false;
    }
  }
  return true;
}

bool Pkcs11KeyStore::GetCertificateFields(const std::string& certificate,
                                          std::string* subject,
                                          std::string* issuer,
                                          std::string* serial_number) {
  const unsigned char* asn1_ptr =
      reinterpret_cast<const unsigned char*>(certificate.data());
  ScopedX509 x509(d2i_X509(nullptr, &asn1_ptr, certificate.size()));
  if (!x509) {
    LOG(WARNING) << "Pkcs11KeyStore: Failed to decode certificate.";
    return false;
  }
  unsigned char* subject_buffer = nullptr;
  int length =
      i2d_X509_NAME(X509_get_subject_name(x509.get()), &subject_buffer);
  crypto::ScopedOpenSSLBytes scoped_subject_buffer(subject_buffer);
  if (length <= 0) {
    LOG(WARNING) << "Pkcs11KeyStore: Failed to encode certificate subject.";
    return false;
  }
  subject->assign(reinterpret_cast<char*>(subject_buffer), length);

  unsigned char* issuer_buffer = nullptr;
  length = i2d_X509_NAME(X509_get_issuer_name(x509.get()), &issuer_buffer);
  crypto::ScopedOpenSSLBytes scoped_issuer_buffer(issuer_buffer);
  if (length <= 0) {
    LOG(WARNING) << "Pkcs11KeyStore: Failed to encode certificate issuer.";
    return false;
  }
  issuer->assign(reinterpret_cast<char*>(issuer_buffer), length);

  unsigned char* serial_number_buffer = nullptr;
  // TODO(djkurtz): Use X509_get0_serialNumber once i2d_ASN1_INTEGER is
  // constified.
  length = i2d_ASN1_INTEGER(X509_get_serialNumber(x509.get()),
                            &serial_number_buffer);
  crypto::ScopedOpenSSLBytes scoped_serial_number_buffer(serial_number_buffer);
  if (length <= 0) {
    LOG(WARNING) << "Pkcs11KeyStore: Failed to encode certificate serial "
                    "number.";
    return false;
  }
  serial_number->assign(reinterpret_cast<char*>(serial_number_buffer), length);
  return true;
}

bool Pkcs11KeyStore::DoesCertificateExist(CK_SESSION_HANDLE session_handle,
                                          const std::string& certificate) {
  CK_OBJECT_CLASS object_class = CKO_CERTIFICATE;
  CK_BBOOL true_value = CK_TRUE;
  CK_BBOOL false_value = CK_FALSE;
  std::string mutable_certificate = certificate;
  CK_ATTRIBUTE attributes[] = {
      {CKA_CLASS, &object_class, sizeof(object_class)},
      {CKA_TOKEN, &true_value, sizeof(true_value)},
      {CKA_PRIVATE, &false_value, sizeof(false_value)},
      {CKA_VALUE, std::data(mutable_certificate), mutable_certificate.size()}};
  CK_OBJECT_HANDLE object_handle = CK_INVALID_HANDLE;
  CK_ULONG count = 0;
  if ((C_FindObjectsInit(session_handle, attributes, std::size(attributes)) !=
       CKR_OK) ||
      (C_FindObjects(session_handle, &object_handle, 1, &count) != CKR_OK) ||
      (C_FindObjectsFinal(session_handle) != CKR_OK)) {
    return false;
  }
  return (count > 0);
}

}  // namespace attestation
