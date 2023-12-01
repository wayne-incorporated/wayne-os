// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// The expensive PKCS #11 operations that occur during a VPN connect are C_Login
// and C_Sign.  This program replays these along with minimal overhead calls.
// The --generate switch can be used to prepare a private key to test against.

#include <stdio.h>
#include <stdlib.h>

#include <iterator>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/threading/platform_thread.h>
#include <base/time/time.h>
#include <brillo/file_utils.h>
#include <brillo/syslog_logging.h>
#include <crypto/libcrypto-compat.h>
#include <crypto/scoped_openssl_types.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "chaps/chaps_utility.h"
#include "pkcs11/cryptoki.h"

using base::TimeDelta;
using base::TimeTicks;
using chaps::ConvertStringToByteBuffer;
using std::string;
using std::unordered_map;
using std::vector;
using ScopedPKCS8_PRIV_KEY_INFO =
    crypto::ScopedOpenSSL<PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_free>;
using ScopedASN1_OCTET_STRING =
    crypto::ScopedOpenSSL<ASN1_OCTET_STRING, ASN1_OCTET_STRING_free>;
using ScopedX509 = crypto::ScopedOpenSSL<X509, X509_free>;

namespace {
const char* kKeyID = "test";

typedef enum {
  kPrivateKey,
  kPublicKey,
  kCertificate,
} CryptoObjectType;

// Initializes the library and finds an appropriate slot.
CK_SLOT_ID Initialize() {
  CK_C_INITIALIZE_ARGS args{
      .flags = CKF_LIBRARY_CANT_CREATE_OS_THREADS,
  };
  CK_RV result = C_Initialize(&args);
  LOG(INFO) << "C_Initialize: " << chaps::CK_RVToString(result);
  if (result != CKR_OK)
    exit(-1);

  CK_SLOT_ID slot_list[10];
  CK_ULONG slot_count = std::size(slot_list);
  result = C_GetSlotList(CK_TRUE, slot_list, &slot_count);
  LOG(INFO) << "C_GetSlotList: " << chaps::CK_RVToString(result);
  if (result != CKR_OK)
    exit(-1);
  if (slot_count == 0) {
    LOG(INFO) << "No slots.";
    exit(-1);
  }
  return slot_list[0];
}

// Opens a session on the given slot.
CK_SESSION_HANDLE OpenSession(CK_SLOT_ID slot) {
  CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
  CK_RV result = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                               NULL,  // Ignore callbacks.
                               NULL,  // Ignore callbacks.
                               &session);
  LOG(INFO) << "C_OpenSession: " << chaps::CK_RVToString(result);
  if (result != CKR_OK)
    exit(-1);
  return session;
}

// Opens a new session and performs a login. If force_login is set to true and
// the token is already logged in, it will be logged out and logged in again. In
// this case, the session will also be closed and reopened. In any case, the
// current, valid session is returned.
CK_SESSION_HANDLE Login(CK_SLOT_ID slot,
                        bool force_login,
                        CK_SESSION_HANDLE session) {
  CK_RV result = CKR_OK;
  bool try_again = true;
  while (try_again) {
    try_again = false;
    result = C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR) "111111", 6);
    LOG(INFO) << "C_Login: " << chaps::CK_RVToString(result);
    if (result != CKR_OK && result != CKR_USER_ALREADY_LOGGED_IN)
      exit(-1);
    if (result == CKR_USER_ALREADY_LOGGED_IN && force_login) {
      try_again = true;
      result = C_Logout(session);
      LOG(INFO) << "C_Logout: " << chaps::CK_RVToString(result);
      if (result != CKR_OK)
        exit(-1);
      result = C_CloseAllSessions(slot);
      LOG(INFO) << "C_CloseAllSessions: " << chaps::CK_RVToString(result);
      if (result != CKR_OK)
        exit(-1);
      session = OpenSession(slot);
    }
  }
  return session;
}

// Finds all objects matching the given attributes.
void Find(CK_SESSION_HANDLE session,
          CK_ATTRIBUTE attributes[],
          CK_ULONG num_attributes,
          vector<CK_OBJECT_HANDLE>* objects) {
  CK_RV result = C_FindObjectsInit(session, attributes, num_attributes);
  LOG(INFO) << "C_FindObjectsInit: " << chaps::CK_RVToString(result);
  if (result != CKR_OK)
    exit(-1);
  CK_OBJECT_HANDLE object = 0;
  CK_ULONG object_count = 1;
  while (object_count > 0) {
    result = C_FindObjects(session, &object, 1, &object_count);
    LOG(INFO) << "C_FindObjects: " << chaps::CK_RVToString(result);
    if (result != CKR_OK)
      exit(-1);
    if (object_count > 0) {
      objects->push_back(object);
    }
  }
  result = C_FindObjectsFinal(session);
  LOG(INFO) << "C_FindObjectsFinal: " << chaps::CK_RVToString(result);
  if (result != CKR_OK)
    exit(-1);
}

// Sign some data with a private key.
void Sign(CK_SESSION_HANDLE session, const string& label) {
  CK_OBJECT_CLASS class_value = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE attributes[] = {
      {CKA_CLASS, &class_value, sizeof(class_value)},
      {CKA_ID, const_cast<char*>(kKeyID), strlen(kKeyID)},
      {CKA_LABEL, const_cast<char*>(label.c_str()), label.length()},
  };
  vector<CK_OBJECT_HANDLE> objects;
  Find(session, attributes, std::size(attributes), &objects);
  if (objects.size() == 0) {
    LOG(INFO) << "No key.";
    exit(-1);
  }

  CK_MECHANISM mechanism;
  mechanism.mechanism = CKM_SHA1_RSA_PKCS;
  mechanism.pParameter = NULL;
  mechanism.ulParameterLen = 0;
  CK_RV result = C_SignInit(session, &mechanism, objects[0]);
  LOG(INFO) << "C_SignInit: " << chaps::CK_RVToString(result);
  if (result != CKR_OK)
    exit(-1);

  CK_BYTE data[200] = {0};
  CK_BYTE signature[2048] = {0};
  CK_ULONG signature_length = std::size(signature);
  result = C_Sign(session, data, std::size(data), signature, &signature_length);
  LOG(INFO) << "C_Sign: " << chaps::CK_RVToString(result);
  if (result != CKR_OK)
    exit(-1);
}

// Generates a test key pair.
void GenerateKeyPair(CK_SESSION_HANDLE session,
                     int key_size_bits,
                     const string& label,
                     bool is_temp) {
  CK_MECHANISM mechanism;
  mechanism.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
  mechanism.pParameter = NULL;
  mechanism.ulParameterLen = 0;
  CK_ULONG bits = key_size_bits;
  CK_BYTE e[] = {1, 0, 1};
  CK_BBOOL false_value = CK_FALSE;
  CK_BBOOL true_value = CK_TRUE;
  CK_ATTRIBUTE public_attributes[] = {
      {CKA_ENCRYPT, &true_value, sizeof(true_value)},
      {CKA_VERIFY, &true_value, sizeof(true_value)},
      {CKA_WRAP, &false_value, sizeof(false_value)},
      {CKA_TOKEN, &true_value, sizeof(true_value)},
      {CKA_PRIVATE, &false_value, sizeof(false_value)},
      {CKA_MODULUS_BITS, &bits, sizeof(bits)},
      {CKA_PUBLIC_EXPONENT, e, sizeof(e)},
      {CKA_ID, const_cast<char*>(kKeyID), strlen(kKeyID)},
      {CKA_LABEL, const_cast<char*>(label.c_str()), label.length()},
  };
  CK_ATTRIBUTE private_attributes[] = {
      {CKA_DECRYPT, &true_value, sizeof(true_value)},
      {CKA_SIGN, &true_value, sizeof(true_value)},
      {CKA_UNWRAP, &false_value, sizeof(false_value)},
      {CKA_SENSITIVE, &true_value, sizeof(true_value)},
      {CKA_TOKEN, &true_value, sizeof(true_value)},
      {CKA_PRIVATE, &true_value, sizeof(true_value)},
      {CKA_ID, const_cast<char*>(kKeyID), strlen(kKeyID)},
      {CKA_LABEL, const_cast<char*>(label.c_str()), label.length()},
  };
  CK_OBJECT_HANDLE public_key_handle = 0;
  CK_OBJECT_HANDLE private_key_handle = 0;
  CK_RV result = C_GenerateKeyPair(
      session, &mechanism, public_attributes, std::size(public_attributes),
      private_attributes, std::size(private_attributes), &public_key_handle,
      &private_key_handle);
  LOG(INFO) << "C_GenerateKeyPair: " << chaps::CK_RVToString(result);
  if (result != CKR_OK)
    exit(-1);
  if (is_temp) {
    result = C_DestroyObject(session, public_key_handle);
    LOG(INFO) << "C_DestroyObject: " << chaps::CK_RVToString(result);
    result = C_DestroyObject(session, private_key_handle);
    LOG(INFO) << "C_DestroyObject: " << chaps::CK_RVToString(result);
  }
}

void DestroyKeyPair(CK_SESSION_HANDLE session, const string& label) {
  CK_BBOOL false_value = CK_FALSE;
  CK_BBOOL true_value = CK_TRUE;
  CK_ATTRIBUTE public_attributes[] = {
      {CKA_PRIVATE, &false_value, sizeof(false_value)},
      {CKA_ID, const_cast<char*>(kKeyID), strlen(kKeyID)},
      {CKA_LABEL, const_cast<char*>(label.c_str()), label.length()},
  };
  CK_ATTRIBUTE private_attributes[] = {
      {CKA_PRIVATE, &true_value, sizeof(true_value)},
      {CKA_ID, const_cast<char*>(kKeyID), strlen(kKeyID)},
      {CKA_LABEL, const_cast<char*>(label.c_str()), label.length()},
  };
  vector<CK_OBJECT_HANDLE> public_objects;
  Find(session, public_attributes, std::size(public_attributes),
       &public_objects);
  vector<CK_OBJECT_HANDLE> private_objects;
  Find(session, private_attributes, std::size(private_attributes),
       &private_objects);
  if (public_objects.size() == 0 && private_objects.size() == 0) {
    LOG(INFO) << "No keypair.";
    exit(-1);
  }
  for (size_t i = 0; i < public_objects.size(); ++i) {
    CK_RV result = C_DestroyObject(session, public_objects[i]);
    LOG(INFO) << "C_DestroyObject: " << chaps::CK_RVToString(result);
    if (result != CKR_OK)
      exit(-1);
  }
  for (size_t i = 0; i < private_objects.size(); ++i) {
    CK_RV result = C_DestroyObject(session, private_objects[i]);
    LOG(INFO) << "C_DestroyObject: " << chaps::CK_RVToString(result);
    if (result != CKR_OK)
      exit(-1);
  }
}

// TODO(crbug/916023): use shared helper after isolate the OpenSSL functions
// from session_impl.c
string bn2bin(const BIGNUM* bn) {
  string bin;
  bin.resize(BN_num_bytes(bn));
  bin.resize(BN_bn2bin(bn, ConvertStringToByteBuffer(bin.data())));
  return bin;
}

string name2bin(X509_NAME* name) {
  string bin;
  bin.resize(i2d_X509_NAME(name, NULL));
  uint8_t* data_start = ConvertStringToByteBuffer(bin.data());
  i2d_X509_NAME(name, &data_start);
  return bin;
}

string asn1integer2bin(ASN1_INTEGER* serial_number) {
  string bin;
  bin.resize(i2d_ASN1_INTEGER(serial_number, NULL));
  uint8_t* data_start = ConvertStringToByteBuffer(bin.data());
  i2d_ASN1_INTEGER(serial_number, &data_start);
  return bin;
}

template <typename OpenSSLType, auto openssl_func>
string ConvertOpenSSLObjectToString(OpenSSLType* object) {
  string output;

  int expected_size = openssl_func(object, nullptr);
  if (expected_size < 0)
    return string();

  output.resize(expected_size, '\0');

  unsigned char* buf = ConvertStringToByteBuffer(output.data());
  int real_size = openssl_func(object, &buf);
  CHECK_EQ(expected_size, real_size);

  return output;
}

string ecparameters2bin(EC_KEY* key) {
  string bin;
  bin.resize(i2d_ECParameters(key, nullptr));
  uint8_t* data_start = ConvertStringToByteBuffer(bin.data());
  i2d_ECParameters(key, &data_start);
  return bin;
}

string ecpoint2bin(EC_KEY* key) {
  // Convert EC_KEY* to OCT_STRING
  const string oct_string =
      ConvertOpenSSLObjectToString<EC_KEY, chaps::i2o_ECPublicKey_nc>(key);

  // Put OCT_STRING to ASN1_OCTET_STRING
  ScopedASN1_OCTET_STRING os(ASN1_OCTET_STRING_new());
  ASN1_OCTET_STRING_set(os.get(), ConvertStringToByteBuffer(oct_string.data()),
                        oct_string.size());

  // DER encode ASN1_OCTET_STRING
  const string der_encoded =
      ConvertOpenSSLObjectToString<ASN1_OCTET_STRING, i2d_ASN1_OCTET_STRING>(
          os.get());

  return der_encoded;
}

void CreateRSAPrivateKey(CK_SESSION_HANDLE session,
                         const vector<uint8_t>& object_id,
                         string label,
                         RSA* rsa,
                         bool force_software) {
  CK_OBJECT_CLASS priv_class = CKO_PRIVATE_KEY;
  CK_KEY_TYPE key_type = CKK_RSA;
  CK_BBOOL false_value = CK_FALSE;
  CK_BBOOL true_value = CK_TRUE;
  const BIGNUM* rsa_n;
  const BIGNUM* rsa_e;
  const BIGNUM* rsa_d;
  const BIGNUM* rsa_p;
  const BIGNUM* rsa_q;
  const BIGNUM* rsa_dmp1;
  const BIGNUM* rsa_dmq1;
  const BIGNUM* rsa_iqmp;
  RSA_get0_key(rsa, &rsa_n, &rsa_e, &rsa_d);
  RSA_get0_factors(rsa, &rsa_p, &rsa_q);
  RSA_get0_crt_params(rsa, &rsa_dmp1, &rsa_dmq1, &rsa_iqmp);
  string n = bn2bin(rsa_n);
  string e = bn2bin(rsa_e);
  string d = bn2bin(rsa_d);
  string p = bn2bin(rsa_p);
  string q = bn2bin(rsa_q);
  string dmp1 = bn2bin(rsa_dmp1);
  string dmq1 = bn2bin(rsa_dmq1);
  string iqmp = bn2bin(rsa_iqmp);
  CK_BBOOL force_software_value = force_software ? CK_TRUE : CK_FALSE;

  CK_ATTRIBUTE private_attributes[] = {
      {CKA_CLASS, &priv_class, sizeof(priv_class)},
      {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
      {CKA_DECRYPT, &true_value, sizeof(true_value)},
      {CKA_SIGN, &true_value, sizeof(true_value)},
      {CKA_UNWRAP, &false_value, sizeof(false_value)},
      {CKA_SENSITIVE, &true_value, sizeof(true_value)},
      {CKA_TOKEN, &true_value, sizeof(true_value)},
      {CKA_PRIVATE, &true_value, sizeof(true_value)},
      {chaps::kForceSoftwareAttribute, &force_software_value,
       sizeof(force_software_value)},
      {CKA_ID, const_cast<uint8_t*>(object_id.data()), object_id.size()},
      {CKA_LABEL, const_cast<char*>(label.c_str()), label.length()},
      {CKA_MODULUS, const_cast<char*>(n.c_str()), n.length()},
      {CKA_PUBLIC_EXPONENT, const_cast<char*>(e.c_str()), e.length()},
      {CKA_PRIVATE_EXPONENT, const_cast<char*>(d.c_str()), d.length()},
      {CKA_PRIME_1, const_cast<char*>(p.c_str()), p.length()},
      {CKA_PRIME_2, const_cast<char*>(q.c_str()), q.length()},
      {CKA_EXPONENT_1, const_cast<char*>(dmp1.c_str()), dmp1.length()},
      {CKA_EXPONENT_2, const_cast<char*>(dmq1.c_str()), dmq1.length()},
      {CKA_COEFFICIENT, const_cast<char*>(iqmp.c_str()), iqmp.length()},
  };
  CK_OBJECT_HANDLE private_key_handle = 0;
  CK_RV result =
      C_CreateObject(session, private_attributes, std::size(private_attributes),
                     &private_key_handle);
  LOG(INFO) << "C_CreateObject: " << chaps::CK_RVToString(result);
  if (result != CKR_OK) {
    exit(-1);
  }
}

void CreateRSAPublicKey(CK_SESSION_HANDLE session,
                        const vector<uint8_t>& object_id,
                        const string label,
                        int key_size_bits,
                        RSA* rsa) {
  CK_BBOOL false_value = CK_FALSE;
  CK_BBOOL true_value = CK_TRUE;
  CK_OBJECT_CLASS pub_class = CKO_PUBLIC_KEY;
  CK_KEY_TYPE key_type = CKK_RSA;
  CK_ULONG bits = key_size_bits;
  const BIGNUM* rsa_n;
  const BIGNUM* rsa_e;
  RSA_get0_key(rsa, &rsa_n, &rsa_e, nullptr);
  string n = bn2bin(rsa_n);
  string e = bn2bin(rsa_e);
  CK_ATTRIBUTE public_attributes[] = {
      {CKA_CLASS, &pub_class, sizeof(pub_class)},
      {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
      {CKA_ENCRYPT, &true_value, sizeof(true_value)},
      {CKA_VERIFY, &true_value, sizeof(true_value)},
      {CKA_WRAP, &false_value, sizeof(false_value)},
      {CKA_TOKEN, &true_value, sizeof(true_value)},
      {CKA_PRIVATE, &false_value, sizeof(false_value)},
      {CKA_ID, const_cast<uint8_t*>(object_id.data()), object_id.size()},
      {CKA_LABEL, const_cast<char*>(label.c_str()), label.length()},
      {CKA_MODULUS_BITS, &bits, sizeof(bits)},
      {CKA_MODULUS, const_cast<char*>(n.c_str()), n.length()},
      {CKA_PUBLIC_EXPONENT, const_cast<char*>(e.c_str()), e.length()},
  };
  CK_OBJECT_HANDLE public_key_handle = 0;
  CK_RV result =
      C_CreateObject(session, public_attributes, std::size(public_attributes),
                     &public_key_handle);
  LOG(INFO) << "C_CreateObject: " << chaps::CK_RVToString(result);
  if (result != CKR_OK)
    exit(-1);
}

void CreateECCPublicKey(CK_SESSION_HANDLE session,
                        const vector<uint8_t>& object_id,
                        string label,
                        EC_KEY* ecc) {
  CK_OBJECT_CLASS pub_class = CKO_PUBLIC_KEY;
  CK_KEY_TYPE key_type = CKK_EC;
  CK_BBOOL false_value = CK_FALSE;
  CK_BBOOL true_value = CK_TRUE;

  string params = ecparameters2bin(ecc);
  string point = ecpoint2bin(ecc);

  CK_ATTRIBUTE public_attributes[] = {
      {CKA_CLASS, &pub_class, sizeof(pub_class)},
      {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
      {CKA_ENCRYPT, &true_value, sizeof(true_value)},
      {CKA_VERIFY, &true_value, sizeof(true_value)},
      {CKA_WRAP, &false_value, sizeof(false_value)},
      {CKA_TOKEN, &true_value, sizeof(true_value)},
      {CKA_PRIVATE, &false_value, sizeof(false_value)},
      {CKA_ID, const_cast<uint8_t*>(object_id.data()), object_id.size()},
      {CKA_LABEL, const_cast<char*>(label.c_str()), label.length()},
      {CKA_EC_PARAMS, const_cast<char*>(params.c_str()), params.length()},
      {CKA_EC_POINT, const_cast<char*>(point.c_str()), point.length()},
  };
  CK_OBJECT_HANDLE public_key_handle = 0;
  CK_RV result =
      C_CreateObject(session, public_attributes, std::size(public_attributes),
                     &public_key_handle);
  LOG(INFO) << "C_CreateObject: " << chaps::CK_RVToString(result);
  if (result != CKR_OK) {
    exit(-1);
  }
}

void CreateECCPrivateKey(CK_SESSION_HANDLE session,
                         const vector<uint8_t>& object_id,
                         string label,
                         EC_KEY* ecc,
                         bool force_software) {
  CK_OBJECT_CLASS priv_class = CKO_PRIVATE_KEY;
  CK_KEY_TYPE key_type = CKK_EC;
  CK_BBOOL false_value = CK_FALSE;
  CK_BBOOL true_value = CK_TRUE;
  CK_BBOOL force_software_value = force_software ? CK_TRUE : CK_FALSE;

  string d = bn2bin(EC_KEY_get0_private_key(ecc));
  string params = ecparameters2bin(ecc);

  CK_ATTRIBUTE private_attributes[] = {
      {CKA_CLASS, &priv_class, sizeof(priv_class)},
      {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
      {CKA_DECRYPT, &true_value, sizeof(true_value)},
      {CKA_SIGN, &true_value, sizeof(true_value)},
      {CKA_UNWRAP, &false_value, sizeof(false_value)},
      {CKA_SENSITIVE, &true_value, sizeof(true_value)},
      {CKA_TOKEN, &true_value, sizeof(true_value)},
      {CKA_PRIVATE, &true_value, sizeof(true_value)},
      {chaps::kForceSoftwareAttribute, &force_software_value,
       sizeof(force_software_value)},
      {CKA_ID, const_cast<uint8_t*>(object_id.data()), object_id.size()},
      {CKA_LABEL, const_cast<char*>(label.c_str()), label.length()},
      {CKA_EC_PARAMS, const_cast<char*>(params.c_str()), params.length()},
      {CKA_VALUE, const_cast<char*>(d.c_str()), d.length()},
  };
  CK_OBJECT_HANDLE private_key_handle = 0;
  CK_RV result =
      C_CreateObject(session, private_attributes, std::size(private_attributes),
                     &private_key_handle);
  LOG(INFO) << "C_CreateObject: " << chaps::CK_RVToString(result);
  if (result != CKR_OK) {
    exit(-1);
  }
}

void CreateCertificate(CK_SESSION_HANDLE session,
                       const string& value,
                       const vector<uint8_t>& object_id,
                       X509* cert) {
  string subject = name2bin(X509_get_subject_name(cert));
  string issuer = name2bin(X509_get_issuer_name(cert));
  string serial = asn1integer2bin(X509_get_serialNumber(cert));
  string label = "testing_cert";
  CK_OBJECT_CLASS clazz = CKO_CERTIFICATE;
  CK_CERTIFICATE_TYPE cert_type = CKC_X_509;
  CK_BBOOL is_true = CK_TRUE;
  CK_ATTRIBUTE attributes[] = {
      {CKA_CLASS, &clazz, sizeof(clazz)},
      {CKA_CERTIFICATE_TYPE, &cert_type, sizeof(cert_type)},
      {CKA_TOKEN, &is_true, sizeof(is_true)},
      {CKA_VALUE, const_cast<char*>(value.c_str()), value.length()},
      {CKA_ID, const_cast<uint8_t*>(object_id.data()), object_id.size()},
      {CKA_SUBJECT, const_cast<char*>(subject.c_str()), subject.length()},
      {CKA_ISSUER, const_cast<char*>(issuer.c_str()), issuer.length()},
      {CKA_SERIAL_NUMBER, const_cast<char*>(serial.c_str()), serial.length()},
      {CKA_LABEL, const_cast<char*>(label.c_str()), label.length()},
  };
  CK_OBJECT_HANDLE handle = 0;
  CK_RV result =
      C_CreateObject(session, attributes, std::size(attributes), &handle);
  LOG(INFO) << "C_CreateObject: " << chaps::CK_RVToString(result);
  if (result != CKR_OK)
    exit(-1);
}

crypto::ScopedRSA ParseRSAPublicKey(const std::string& object_data) {
  // Try decoding a PKCS#1 RSAPublicKey structure.
  const unsigned char* buf = ConvertStringToByteBuffer(object_data.data());
  crypto::ScopedRSA rsa(d2i_RSAPublicKey(NULL, &buf, object_data.length()));
  if (rsa != nullptr) {
    LOG(INFO) << "Recognized as PKCS#1 RSA RSAPublicKey.";
    return rsa;
  }

  // Try decoding a X.509 SubjectPublicKeyInfo structure.
  // Rewind the ptr just in case it was modified.
  buf = ConvertStringToByteBuffer(object_data.data());
  rsa.reset(d2i_RSA_PUBKEY(NULL, &buf, object_data.length()));
  if (rsa != nullptr) {
    LOG(INFO) << "Recognized as X.509 SubjectPublicKeyInfo RSA PUBKEY.";
    return rsa;
  }

  return nullptr;
}

crypto::ScopedRSA ParseRSAPrivateKey(const std::string& object_data) {
  // Try decoding a PKCS#1 RSAPrivateKey structure.
  const unsigned char* buf = ConvertStringToByteBuffer(object_data.data());
  crypto::ScopedRSA rsa(d2i_RSAPrivateKey(nullptr, &buf, object_data.length()));
  if (rsa != nullptr) {
    LOG(INFO) << "Recognized as PKCS#1 RSA private key";
    return rsa;
  }

  // Try decoding a PKCS#8 structure.
  // Rewind the ptr just in case it was modified.
  buf = ConvertStringToByteBuffer(object_data.data());
  ScopedPKCS8_PRIV_KEY_INFO p8(
      d2i_PKCS8_PRIV_KEY_INFO(nullptr, &buf, object_data.length()));
  if (p8 == nullptr)
    return nullptr;

  crypto::ScopedEVP_PKEY pkey(EVP_PKCS82PKEY(p8.get()));
  // See if we have a RSAPrivateKey in the PKCS#8 structure.
  if (pkey == nullptr || EVP_PKEY_base_id(pkey.get()) != EVP_PKEY_RSA)
    return nullptr;

  rsa.reset(EVP_PKEY_get1_RSA(pkey.get()));
  if (rsa == nullptr)
    return nullptr;

  LOG(INFO) << "Recognized as PKCS#8 RSA private key";
  return rsa;
}

crypto::ScopedEC_KEY ParseECCPublicKey(const std::string& object_data) {
  crypto::ScopedEC_KEY ecc;

  // Try decoding a X.509 SubjectPublicKeyInfo structure.
  const unsigned char* data_start =
      reinterpret_cast<const unsigned char*>(object_data.c_str());
  ecc.reset(d2i_EC_PUBKEY(NULL, &data_start, object_data.size()));
  if (ecc != nullptr) {
    LOG(INFO) << "Recognized as X.509 SubjectPublicKeyInfo EC PUBKEY";
    return ecc;
  }

  return nullptr;
}

crypto::ScopedEC_KEY ParseECCPrivateKey(const std::string& object_data) {
  crypto::ScopedEC_KEY ecc;

  // Try decoding a RFC 5915 ECPrivateKey structure.
  const unsigned char* data_start =
      reinterpret_cast<const unsigned char*>(object_data.c_str());
  ecc.reset(d2i_ECPrivateKey(NULL, &data_start, object_data.size()));
  if (ecc != nullptr) {
    LOG(INFO) << "Recognized as RFC 5915 ECPrivateKey";
    return ecc;
  }

  return nullptr;
}

bool ParseAndCreatePublicKey(CK_SESSION_HANDLE session,
                             const vector<uint8_t>& object_id,
                             const string& object_data) {
  // Try RSA
  crypto::ScopedRSA rsa = ParseRSAPublicKey(object_data);
  if (rsa != nullptr) {
    int key_size_bits = RSA_size(rsa.get()) * 8;
    // Round the key up to the nearest 256 bit boundary.
    key_size_bits = (key_size_bits / 256 + 1) * 256;

    CreateRSAPublicKey(session, object_id, "testing_key", key_size_bits,
                       rsa.get());
    return true;
  }

  // Try ECC
  crypto::ScopedEC_KEY ecc = ParseECCPublicKey(object_data);
  if (ecc != nullptr) {
    CreateECCPublicKey(session, object_id, "testing_key", ecc.get());
    return true;
  }

  return false;
}

bool ParseAndCreatePrivateKey(CK_SESSION_HANDLE session,
                              const vector<uint8_t>& object_id,
                              const string& object_data,
                              bool force_software) {
  // Try RSA
  crypto::ScopedRSA rsa = ParseRSAPrivateKey(object_data);
  if (rsa != nullptr) {
    CreateRSAPrivateKey(session, object_id, "testing_key", rsa.get(),
                        force_software);
    return true;
  }

  // Try ECC
  crypto::ScopedEC_KEY ecc = ParseECCPrivateKey(object_data);
  if (ecc != nullptr) {
    CreateECCPrivateKey(session, object_id, "testing_key", ecc.get(),
                        force_software);
    return true;
  }

  return false;
}

bool ParseAndCreateCertificate(CK_SESSION_HANDLE session,
                               const vector<uint8_t>& object_id,
                               const string& object_data) {
  const unsigned char* buf = ConvertStringToByteBuffer(object_data.data());
  ScopedX509 certificate(d2i_X509(NULL, &buf, object_data.length()));
  if (certificate == nullptr)
    return false;
  CreateCertificate(session, object_data, object_id, certificate.get());
  return true;
}

void ReadInObject(CK_SESSION_HANDLE session,
                  const string& input_path,
                  const vector<uint8_t>& object_id,
                  CryptoObjectType type,
                  bool force_software) {
  const base::FilePath path(input_path);
  string object_data;
  if (!base::ReadFileToString(path, &object_data)) {
    LOG(ERROR) << "Failed to read object from file.";
    exit(-1);
  }

  string type_str;
  bool result = false;
  switch (type) {
    case kCertificate:
      result = ParseAndCreateCertificate(session, object_id, object_data);
      type_str = "Certificate";
      break;
    case kPublicKey:
      result = ParseAndCreatePublicKey(session, object_id, object_data);
      type_str = "Public key";
      break;
    case kPrivateKey:
      result = ParseAndCreatePrivateKey(session, object_id, object_data,
                                        force_software);
      type_str = "Private key";
      break;
  }

  if (!result) {
    LOG(ERROR) << __func__ << ": " << type_str << " parsing fail.";
    exit(-1);
  }
}

// Generates a test key pair locally and injects it.
void InjectRSAKeyPair(CK_SESSION_HANDLE session,
                      int key_size_bits,
                      const string& label) {
  crypto::ScopedRSA rsa(RSA_new());
  crypto::ScopedBIGNUM e(BN_new());
  if (!rsa || !e) {
    LOG(ERROR) << "Failed to allocate RSA or exponent for key pair.";
    exit(-1);
  }
  if (!BN_set_word(e.get(), 0x10001) ||
      !RSA_generate_key_ex(rsa.get(), key_size_bits, e.get(), nullptr)) {
    LOG(ERROR) << "Failed to locally generate key pair.";
    exit(-1);
  }
  vector<uint8_t> id(kKeyID, kKeyID + strlen(kKeyID));
  CreateRSAPublicKey(session, id, label, key_size_bits, rsa.get());
  CreateRSAPrivateKey(session, id, label, rsa.get(), false);
}

// Deletes all test keys previously created.
void DeleteAllTestKeys(CK_SESSION_HANDLE session) {
  CK_OBJECT_CLASS class_value = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE attributes[] = {
      {CKA_CLASS, &class_value, sizeof(class_value)},
      {CKA_ID, const_cast<char*>(kKeyID), strlen(kKeyID)}};
  vector<CK_OBJECT_HANDLE> objects;
  Find(session, attributes, std::size(attributes), &objects);
  class_value = CKO_PUBLIC_KEY;
  Find(session, attributes, std::size(attributes), &objects);
  for (size_t i = 0; i < objects.size(); ++i) {
    CK_RV result = C_DestroyObject(session, objects[i]);
    LOG(INFO) << "C_DestroyObject: " << chaps::CK_RVToString(result);
    if (result != CKR_OK)
      exit(-1);
  }
}

// Retrieve the object handle for the object with the specified |object_id| and
// CKA_CLASS of |obj_type|, and return the object iff exactly one object is
// found. Exit with a non-zero status code otherwise.
CK_OBJECT_HANDLE GetObjectOrDie(CK_SESSION_HANDLE session,
                                const vector<uint8_t>& object_id,
                                string obj_type) {
  CK_OBJECT_CLASS class_value;
  if (base::EqualsCaseInsensitiveASCII(obj_type, "privkey")) {
    class_value = CKO_PRIVATE_KEY;
  } else if (base::EqualsCaseInsensitiveASCII(obj_type, "pubkey")) {
    class_value = CKO_PUBLIC_KEY;
  } else if (base::EqualsCaseInsensitiveASCII(obj_type, "cert")) {
    class_value = CKO_CERTIFICATE;
  } else {
    LOG(INFO) << "Invalid object class: " << obj_type;
    exit(-1);
  }

  CK_ATTRIBUTE attributes[] = {
      {CKA_CLASS, &class_value, sizeof(class_value)},
      {CKA_ID,
       const_cast<char*>(reinterpret_cast<const char*>(object_id.data())),
       object_id.size()},
  };
  vector<CK_OBJECT_HANDLE> objects;
  Find(session, attributes, std::size(attributes), &objects);
  if (objects.size() == 0) {
    LOG(INFO) << "No object found.";
    exit(-1);
  }
  if (objects.size() > 1) {
    LOG(INFO) << "More than 1 object.";
    exit(-1);
  }
  return objects[0];
}

// Get the specified attribute for the specified object and print it out in
// specified format.
void GetAttribute(CK_SESSION_HANDLE session,
                  const vector<uint8_t>& object_id,
                  CK_ATTRIBUTE_TYPE attribute,
                  string output_format,
                  string obj_type) {
  CK_OBJECT_HANDLE object = GetObjectOrDie(session, object_id, obj_type);

  // Get the length of the attribute.
  CK_ATTRIBUTE attribute_template[] = {
      {attribute, nullptr, 0},
  };
  CK_RV ret = C_GetAttributeValue(session, object, attribute_template,
                                  std::size(attribute_template));
  if (ret != CKR_OK) {
    printf("Unable to access the attribute, error: %s\n",
           chaps::CK_RVToString(ret));
    exit(-1);
  }
  if (attribute_template[0].ulValueLen == -1) {
    printf("Unable to access the attribute, got -1 for attribute length.\n");
    exit(-1);
  }

  size_t attribute_size = attribute_template[0].ulValueLen;
  printf("Size: %d\n", static_cast<int>(attribute_size));

  if (attribute_size <= 0) {
    // No data, we are done here.
    return;
  }

  // Get the object value.
  std::vector<uint8_t> buffer(attribute_template[0].ulValueLen, 0);
  attribute_template[0].pValue = std::data(buffer);
  ret = C_GetAttributeValue(session, object, attribute_template,
                            std::size(attribute_template));
  if (ret != CKR_OK) {
    printf("Unable to read the attribute, error: %s\n",
           chaps::CK_RVToString(ret));
    exit(-1);
  }

  // Print out the attribute value.
  if (output_format == "hex" || output_format == "") {
    printf("Attribute Data in hex: %s\n",
           base::HexEncode(std::data(buffer), buffer.size()).c_str());
  } else {
    printf("Invalid output format: %s\n", output_format.c_str());
    exit(-1);
  }
}

// Set the specified attribute for the specified object.
void SetAttribute(CK_SESSION_HANDLE session,
                  const vector<uint8_t>& object_id,
                  CK_ATTRIBUTE_TYPE attribute,
                  string obj_type,
                  const vector<uint8_t>& data_to_write) {
  CK_OBJECT_HANDLE object = GetObjectOrDie(session, object_id, obj_type);

  // Set the attribute
  // Cryptoki wants a non-const buffer in template.
  vector<uint8_t> buffer = data_to_write;
  CK_ATTRIBUTE attribute_template[] = {
      {attribute, std::data(buffer), buffer.size()},
  };
  CK_RV ret = C_SetAttributeValue(session, object, attribute_template,
                                  std::size(attribute_template));
  if (ret != CKR_OK) {
    printf("Failed to set attribute, error: %s\n", chaps::CK_RVToString(ret));
    exit(-1);
  }
  printf("Set attribute OK.\n");
}

void CopyObject(
    CK_SESSION_HANDLE session,
    string obj_type,
    const vector<uint8_t>& object_id,
    const unordered_map<CK_ATTRIBUTE_TYPE, vector<uint8_t>>& attr_map) {
  CK_OBJECT_HANDLE object = GetObjectOrDie(session, object_id, obj_type);

  vector<CK_ATTRIBUTE> copy_template{attr_map.size()};
  // This will hold the buffer that is pointed to by copy_template's pValue.
  vector<vector<uint8_t>> value_holder;
  int i = 0;
  for (const auto& itr : attr_map) {
    CHECK(i < copy_template.size());
    copy_template[i].type = itr.first;

    // Copy the value buffer into value_holder.
    value_holder.push_back(itr.second);
    auto& buffer = value_holder[value_holder.size() - 1];

    copy_template[i].pValue = reinterpret_cast<CK_VOID_PTR>(std::data(buffer));
    copy_template[i].ulValueLen = buffer.size();
    i++;
  }

  CK_OBJECT_HANDLE new_object;
  CK_RV result =
      C_CopyObject(session, object,
                   reinterpret_cast<CK_ATTRIBUTE_PTR>(std::data(copy_template)),
                   copy_template.size(), &new_object);
  if (result != CKR_OK) {
    printf("Failed to copy the attribute, error: %s\n",
           chaps::CK_RVToString(result));
    exit(-1);
  }
  printf("Operation completed successfully.\n");
}

// This checks if a session is still functional/open.
bool TestSession(CK_SESSION_HANDLE session) {
  CK_OBJECT_CLASS class_value = CKO_PUBLIC_KEY;
  CK_ATTRIBUTE attributes[] = {
      {CKA_CLASS, &class_value, sizeof(class_value)},
  };

  CK_RV result = C_FindObjectsInit(session, attributes, std::size(attributes));
  LOG(INFO) << "C_FindObjectsInit: " << chaps::CK_RVToString(result);
  if (result != CKR_OK) {
    return false;
  }

  CK_OBJECT_HANDLE object = 0;
  CK_ULONG object_count = 1;
  result = C_FindObjects(session, &object, 1, &object_count);
  LOG(INFO) << "C_FindObjects: " << chaps::CK_RVToString(result);
  if (result != CKR_OK) {
    return false;
  }

  result = C_FindObjectsFinal(session);
  LOG(INFO) << "C_FindObjectsFinal: " << chaps::CK_RVToString(result);
  if (result != CKR_OK) {
    return false;
  }

  return true;
}

int ReplayCloseAllSessionsLoop(CK_SESSION_HANDLE session,
                               const std::string& ipc_file_path) {
  // Check session is operation at the start.
  bool success = TestSession(session);
  if (!success) {
    LOG(ERROR)
        << "Session destroyed at the start of ReplayCloseAllSessionsLoop()";
    return 1;
  }

  // Since we have an operation session, touch the file to let
  // ReplayCloseAllSessionsCheck() know.
  base::FilePath path(ipc_file_path);
  CHECK(brillo::WriteStringToFile(path, "")) << "Failed to write ipc_file";
  CHECK(brillo::SyncFileOrDirectory(
      path.DirName(), true /* is directory? */,
      false /* data_sync? false because we want to sync metadata */))
      << "Failed to sync after writing ipc_file";

  // We'll test that the session works during the test run time.
  for (int i = 0; i < 30; i++) {
    bool success = TestSession(session);
    bool done = !base::PathExists(path);
    if (!success) {
      LOG(ERROR)
          << "Session destroyed halfway during ReplayCloseAllSessionsLoop()";
      return 1;
    }
    if (done) {
      LOG(INFO)
          << "Signaled by ReplayCloseAllSessionsCheck() that they are done.";
      return 0;
    }
    base::PlatformThread::Sleep(base::Milliseconds(300));
  }
  LOG(ERROR)
      << "Timed out waiting for signal from ReplayCloseAllSessionsCheck().";
  return 1;
}

int ReplayCloseAllSessionsCheck(CK_SESSION_HANDLE session,
                                CK_SLOT_ID slotID,
                                const std::string& ipc_file_path) {
  base::FilePath path(ipc_file_path);

  // Wait for ipc_file_path to exist (i.e. ReplayCloseAllSessionsLoop() is
  // ready).
  constexpr int kWaitLoopCount = 30;
  for (int i = 0; i < kWaitLoopCount; i++) {
    if (i == kWaitLoopCount - 1) {
      LOG(ERROR)
          << "Timed out waiting for signal from ReplayCloseAllSessionsLoop().";
      return 1;
    }
    if (base::PathExists(path))
      break;
    base::PlatformThread::Sleep(base::Milliseconds(300));
  }

  base::ScopedClosureRunner ipc_file_cleanup(base::BindOnce(
      [](const std::string& ipc_file_path) {
        base::FilePath path(ipc_file_path);

        CHECK(base::DeleteFile(path))
            << "Failed to delete ipc_file after ReplayCloseAllSessionsCheck()";
        CHECK(brillo::SyncFileOrDirectory(
            path.DirName(), true /* is directory? */,
            false /* data_sync? false because we want to sync metadata */))
            << "Failed to sync after writing ipc_file";
      },
      ipc_file_path));

  // Check session works at first, then call C_CloseAllSessions(), then check it
  // doesn't work.
  bool success = TestSession(session);
  if (!success) {
    LOG(ERROR)
        << "Session doesn't work at the start of ReplayCloseAllSessionsCheck()";
    return 1;
  }

  CK_RV rv = C_CloseAllSessions(slotID);
  if (rv != CKR_OK) {
    LOG(ERROR)
        << "Failed to C_CloseAllSessions() in ReplayCloseAllSessionsCheck()";
    return 1;
  }

  success = TestSession(session);
  if (success) {
    LOG(ERROR) << "Session still works after C_CloseAllSessions() in "
                  "ReplayCloseAllSessionsCheck()";
    return 1;
  }

  return 0;
}

// Cleans up the session and library.
void TearDown(CK_SESSION_HANDLE session, bool logout) {
  CK_RV result = CKR_OK;
  if (logout) {
    result = C_Logout(session);
    LOG(INFO) << "C_Logout: " << chaps::CK_RVToString(result);
  }
  result = C_CloseSession(session);
  LOG(INFO) << "C_CloseSession: " << chaps::CK_RVToString(result);
  result = C_Finalize(NULL);
  LOG(INFO) << "C_Finalize: " << chaps::CK_RVToString(result);
}

void PrintHelp() {
  printf("Usage: p11_replay [--slot=<slot>] [COMMAND]\n");
  printf("Commands:\n");
  printf("  --cleanup : Deletes all test keys.\n");
  printf(
      "  --generate [--label=<key_label> --key_size=<size_in_bits>]"
      " : Generates a key pair suitable for replay tests.\n");
  printf(
      "  --generate_delete : Generates a key pair and deletes it. This is "
      "useful for comparing key generation on different HWSec backend.\n");
  printf(
      "  --import --path=<path to file> --type=<cert, privkey, pubkey>"
      " --id=<token id str>"
      " : Reads an object into the token.  Accepts DER formatted X.509"
      " certificates and DER formatted PKCS#1 or PKCS#8 private keys.\n");
  printf(
      "  --inject [--label=<key_label> --key_size=<size_in_bits>]"
      " : Locally generates a key pair suitable for replay tests and injects"
      " it into the token.\n");
  printf("  --list_objects : Lists all token objects.\n");
  printf("  --list_tokens: Lists token info for each loaded token.\n");
  printf("  --logout : Logs out once all other commands have finished.\n");
  printf(
      "  --replay_vpn [--label=<key_label>]"
      " : Replays a L2TP/IPSEC VPN negotiation.\n");
  printf(
      "  --replay_wifi [--label=<key_label> --skip_generate]"
      " : Replays a EAP-TLS Wifi negotiation. This is the default command if"
      " no command is specified. Do not generate key pair if --skip_generate"
      " is set\n");
  printf(
      "  --get_attribute --id=<token id str> --type=<cert, privkey, pubkey> "
      "--attribute=<attribute>: Get the attribute for an object.\n");
  printf(
      "  --set_attribute --id=<token id str> --type=<cert, privkey, pubkey> "
      "--attribute=<attribute> --data=<raw hex string>: Set the attribute for "
      "an object.\n");
  printf(
      "  --copy_object --id=<token id str> --attr_list=CKA_XXX:<hex "
      "value>,CKA_YYY:<hex value>,... --type=<cert, privkey, pubkey>: Copy the "
      "object specified by --id into a new object.\n");
  printf(
      "  --replay_close_all_sessions --check_close_all_sessions "
      "--ipc_file=<path>: This is a helper for hwsec.ChapsCloseAllSessions "
      "test. --check_close_all_sessions will open a session, check it works, "
      "then close it with C_CloseAllSessions(), then check the session is "
      "indeed closed. ipc_file should point to a file that does not yet exist, "
      "and is the same that is passed to --use_sessions_loop.\n");
  printf(
      "  --replay_close_all_sessions --use_sessions_loop --ipc_file=<path>: "
      "Same as above, but it repeately uses a session that it opened for "
      "around 5 seconds to make sure it doesn't get invalidated for no reason. "
      "See above for --ipc_file.\n");
}

void PrintTicks(base::TimeTicks* start_ticks) {
  base::TimeTicks now = base::TimeTicks::Now();
  base::TimeDelta delta = now - *start_ticks;
  *start_ticks = now;
  intmax_t value = delta.InMillisecondsRoundedUp();
  printf("Elapsed: %jdms\n", value);
}

void PrintObjects(const vector<CK_OBJECT_HANDLE>& objects) {
  for (size_t i = 0; i < objects.size(); ++i) {
    if (i > 0)
      printf(", ");
    printf("%d", static_cast<int>(objects[i]));
  }
  printf("\n");
}

class DigestTestThread : public base::PlatformThread::Delegate {
 public:
  explicit DigestTestThread(CK_SLOT_ID slot) : slot_(slot) {}
  void ThreadMain() {
    const int kNumIterations = 100;
    CK_BYTE data[1024] = {0};
    CK_ULONG data_length = std::size(data);
    CK_BYTE digest[32];
    CK_ULONG digest_length = std::size(digest);
    CK_MECHANISM mechanism = {CKM_SHA256, NULL, 0};
    CK_SESSION_HANDLE session = OpenSession(slot_);
    for (int i = 0; i < kNumIterations; ++i) {
      TimeTicks start = TimeTicks::Now();
      C_DigestInit(session, &mechanism);
      C_DigestUpdate(session, data, data_length);
      C_DigestFinal(session, digest, &digest_length);
      TimeDelta delta = TimeTicks::Now() - start;
      if (delta > base::Milliseconds(500)) {
        LOG(WARNING) << "Hash took long: " << delta.InMilliseconds();
      }
    }
    C_CloseSession(session);
  }

 private:
  CK_SLOT_ID slot_;
};

void PrintTokens() {
  CK_RV result = CKR_OK;
  CK_SLOT_ID slot_list[10];
  CK_ULONG slot_count = std::size(slot_list);
  result = C_GetSlotList(CK_TRUE, slot_list, &slot_count);
  if (result != CKR_OK)
    exit(-1);
  for (CK_ULONG i = 0; i < slot_count; ++i) {
    CK_SLOT_INFO slot_info;
    result = C_GetSlotInfo(slot_list[i], &slot_info);
    if (result != CKR_OK)
      exit(-1);
    printf("Slot %d: ", static_cast<int>(slot_list[i]));
    if (slot_info.flags & CKF_TOKEN_PRESENT) {
      CK_TOKEN_INFO token_info;
      result = C_GetTokenInfo(slot_list[i], &token_info);
      if (result != CKR_OK)
        exit(-1);
      string label(reinterpret_cast<char*>(token_info.label),
                   std::size(token_info.label));
      printf("%s\n", label.c_str());
    } else {
      printf("No token present.\n");
    }
  }
}

}  // namespace

int main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  if (cl->HasSwitch("h") || cl->HasSwitch("help")) {
    PrintHelp();
    return 0;
  }
  bool generate = cl->HasSwitch("generate");
  bool inject = cl->HasSwitch("inject");
  bool generate_delete = cl->HasSwitch("generate_delete");
  bool vpn = cl->HasSwitch("replay_vpn");
  bool wifi = cl->HasSwitch("replay_wifi") || (cl->GetSwitches().size() == 0);
  bool logout = cl->HasSwitch("logout");
  bool cleanup = cl->HasSwitch("cleanup");
  bool list_objects = cl->HasSwitch("list_objects");
  bool import = cl->HasSwitch("import") && cl->HasSwitch("path") &&
                cl->HasSwitch("type") && cl->HasSwitch("id");
  bool digest_test = cl->HasSwitch("digest_test");
  bool list_tokens = cl->HasSwitch("list_tokens");
  bool get_attribute = cl->HasSwitch("get_attribute");
  bool set_attribute = cl->HasSwitch("set_attribute");
  bool copy = cl->HasSwitch("copy_object");
  bool close_all_sessions = cl->HasSwitch("replay_close_all_sessions");
  if (!generate && !generate_delete && !vpn && !wifi && !logout && !cleanup &&
      !inject && !list_objects && !import && !digest_test && !list_tokens &&
      !get_attribute && !set_attribute && !copy && !close_all_sessions) {
    PrintHelp();
    return 0;
  }

  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);
  base::TimeTicks start_ticks = base::TimeTicks::Now();
  CK_SLOT_ID slot = Initialize();
  int tmp_slot = 0;
  if (cl->HasSwitch("slot") &&
      base::StringToInt(cl->GetSwitchValueASCII("slot"), &tmp_slot))
    slot = tmp_slot;
  LOG(INFO) << "Using slot " << slot;
  CK_SESSION_HANDLE session = OpenSession(slot);
  PrintTicks(&start_ticks);
  string label = "_default";
  if (cl->HasSwitch("label"))
    label = cl->GetSwitchValueASCII("label");
  int key_size_bits = 2048;
  if (cl->HasSwitch("key_size") &&
      !base::StringToInt(cl->GetSwitchValueASCII("key_size"), &key_size_bits))
    key_size_bits = 2048;
  if (generate || generate_delete) {
    session = Login(slot, false, session);
    PrintTicks(&start_ticks);
    GenerateKeyPair(session, key_size_bits, label, generate_delete);
    PrintTicks(&start_ticks);
  } else if (inject) {
    session = Login(slot, false, session);
    PrintTicks(&start_ticks);
    InjectRSAKeyPair(session, key_size_bits, label);
    PrintTicks(&start_ticks);
  } else if (import) {
    vector<uint8_t> object_id;
    if (!base::HexStringToBytes(cl->GetSwitchValueASCII("id"), &object_id)) {
      LOG(ERROR) << "Invalid arg, expecting hex string for id (like b18aa8).";
      exit(-1);
    }
    std::string type = cl->GetSwitchValueASCII("type");
    std::string path = cl->GetSwitchValueASCII("path");
    if (base::EqualsCaseInsensitiveASCII("cert", type)) {
      ReadInObject(session, path, object_id, kCertificate, false);
    } else if (base::EqualsCaseInsensitiveASCII("privkey", type)) {
      ReadInObject(session, path, object_id, kPrivateKey,
                   cl->HasSwitch("force_software"));
    } else if (base::EqualsCaseInsensitiveASCII("pubkey", type)) {
      ReadInObject(session, path, object_id, kPublicKey, false);
    } else {
      LOG(ERROR) << "Invalid token type.";
      exit(-1);
    }
    PrintTicks(&start_ticks);
  }
  if (list_objects) {
    vector<CK_OBJECT_HANDLE> objects;
    CK_BBOOL priv_value = CK_FALSE;
    CK_ATTRIBUTE priv = {CKA_PRIVATE, &priv_value, sizeof(priv_value)};
    Find(session, &priv, 1, &objects);
    printf("Public Objects:\n");
    PrintObjects(objects);
    PrintTicks(&start_ticks);
    objects.clear();
    Login(slot, false, session);
    priv_value = CK_TRUE;
    Find(session, &priv, 1, &objects);
    printf("Private Objects:\n");
    PrintObjects(objects);
    PrintTicks(&start_ticks);
  }
  if (vpn || wifi) {
    bool skip_generate = cl->HasSwitch("skip_generate");
    printf("Replay 1 of 2\n");
    // No need to login again if --generate or --inject flag is passed
    // as it's already logged in for this session
    if (!generate && !inject && !skip_generate) {
      session = Login(slot, vpn, session);
      GenerateKeyPair(session, key_size_bits, label, false);
    }
    Sign(session, label);
    PrintTicks(&start_ticks);
    printf("Replay 2 of 2\n");
    CK_SESSION_HANDLE session2 = OpenSession(slot);
    session2 = Login(slot, vpn, session2);
    Sign(session2, label);
    PrintTicks(&start_ticks);
    C_CloseSession(session2);
    // Delete the temporary key pair to avoid piling up.
    if (!generate && !inject && !skip_generate) {
      DestroyKeyPair(session, label);
    }
  }
  if (digest_test) {
    const int kNumThreads = 100;
    std::unique_ptr<DigestTestThread> threads[kNumThreads];
    base::PlatformThreadHandle handles[kNumThreads];
    for (int i = 0; i < kNumThreads; ++i) {
      LOG(INFO) << "Creating thread " << i;
      threads[i].reset(new DigestTestThread(slot));
      if (!base::PlatformThread::Create(0, threads[i].get(), &handles[i]))
        LOG(FATAL) << "Failed to create thread.";
    }
    for (int i = 0; i < kNumThreads; ++i) {
      base::PlatformThread::Join(handles[i]);
      LOG(INFO) << "Joined thread " << i;
    }
  }
  if (list_tokens) {
    PrintTokens();
  }
  if (get_attribute) {
    vector<uint8_t> object_id;
    if (!base::HexStringToBytes(cl->GetSwitchValueASCII("id"), &object_id)) {
      LOG(ERROR) << "Invalid arg, expecting hex string for id (like b18aa8).";
      exit(-1);
    }
    string attribute_string = cl->GetSwitchValueASCII("attribute");
    CK_ATTRIBUTE_TYPE attribute;
    if (!chaps::StringToAttribute(attribute_string, &attribute)) {
      LOG(ERROR) << "Unable to parse attribute: " << attribute_string;
      exit(-1);
    }
    GetAttribute(session, object_id, attribute,
                 cl->GetSwitchValueASCII("output_format"),
                 cl->GetSwitchValueASCII("type"));
  }
  if (set_attribute) {
    vector<uint8_t> object_id;
    if (!base::HexStringToBytes(cl->GetSwitchValueASCII("id"), &object_id)) {
      LOG(ERROR) << "Invalid arg, expecting hex string for id (like b18aa8).";
      exit(-1);
    }
    string attribute_string = cl->GetSwitchValueASCII("attribute");
    CK_ATTRIBUTE_TYPE attribute;
    if (!chaps::StringToAttribute(attribute_string, &attribute)) {
      LOG(ERROR) << "Unable to parse attribute: " << attribute_string;
      exit(-1);
    }
    string data_string = cl->GetSwitchValueASCII("data");
    vector<uint8_t> data_to_write;
    if (!base::HexStringToBytes(data_string, &data_to_write)) {
      LOG(ERROR) << "Invalid hex input data: " << data_string;
    }
    SetAttribute(session, object_id, attribute, cl->GetSwitchValueASCII("type"),
                 data_to_write);
  }
  if (copy) {
    // Parse from and to object ID.
    vector<uint8_t> object_id;
    if (!base::HexStringToBytes(cl->GetSwitchValueASCII("id"), &object_id)) {
      LOG(ERROR) << "Invalid arg, expecting hex string for --id (like b18aa8).";
      exit(-1);
    }

    // Parse the --attr_list switch
    vector<string> raw_attr_list =
        base::SplitString(cl->GetSwitchValueASCII("attr_list"), ",",
                          base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
    unordered_map<CK_ATTRIBUTE_TYPE, vector<uint8_t>> attr_map;
    for (const string& attr_pair : raw_attr_list) {
      vector<string> splitted_attr = base::SplitString(
          attr_pair, ":", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
      if (splitted_attr.size() != 2) {
        LOG(ERROR)
            << "Invalid attribute pair, expected <attr>:<hex value>, got: "
            << attr_pair;
        exit(-1);
      }

      // Parse the attribute.
      CK_ATTRIBUTE_TYPE current_attr;
      if (!chaps::StringToAttribute(splitted_attr[0], &current_attr)) {
        LOG(ERROR) << "Unable to parse attribute: " << splitted_attr[0];
        exit(-1);
      }

      // Parse the value.
      vector<uint8_t> attr_value;
      if (!base::HexStringToBytes(splitted_attr[1], &attr_value)) {
        LOG(ERROR) << "Invalid attribute value, must be in hex: "
                   << splitted_attr[1];
        exit(-1);
      }

      // Insert it into the attribute map.
      if (attr_map.count(current_attr) != 0) {
        LOG(ERROR) << "Duplicate attribute: " << splitted_attr[0];
        exit(-1);
      }
      attr_map[current_attr] = attr_value;
    }
    CopyObject(session, cl->GetSwitchValueASCII("type"), object_id, attr_map);
  }
  if (close_all_sessions) {
    // This section is used to test that C_CloseAllSessions() behaves correctly.
    // --use_sessions_loop will create a process that continuously use a
    // session, to check that it's session is not closed by C_CloseAllSessions()
    // from another process. This will continue for approximately 10 seconds.
    // --check_close_all_sessions will check that the current session works,
    // then call C_CloseAllSessions(), then check that it no longer works.
    string ipc_file_path = cl->GetSwitchValueASCII("ipc_file");
    CHECK(!ipc_file_path.empty()) << "--ipc_file should be specified";
    if (cl->HasSwitch("use_sessions_loop")) {
      return ReplayCloseAllSessionsLoop(session, ipc_file_path);
    } else if (cl->HasSwitch("check_close_all_sessions")) {
      return ReplayCloseAllSessionsCheck(session, slot, ipc_file_path);
    } else {
      LOG(FATAL) << "--replay_close_all_sessions needs --use_sessions_loop or "
                    "--check_close_all_sessions";
    }
  }
  if (cleanup)
    DeleteAllTestKeys(session);
  TearDown(session, logout);
  PrintTicks(&start_ticks);
}
