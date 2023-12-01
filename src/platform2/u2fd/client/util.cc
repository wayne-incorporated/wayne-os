// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "u2fd/client/util.h"

#include <array>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/logging.h>
#include <brillo/secure_blob.h>
#include <crypto/scoped_openssl_types.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

namespace u2f {
namespace util {

template <>
void AppendToVector(const std::vector<uint8_t>& from,
                    std::vector<uint8_t>* to) {
  to->insert(to->end(), from.begin(), from.end());
}

template <>
void AppendToVector(const std::string& from, std::vector<uint8_t>* to) {
  to->insert(to->end(), from.begin(), from.end());
}

void AppendSubstringToVector(const std::string& from,
                             int start,
                             int length,
                             std::vector<uint8_t>* to) {
  to->insert(to->end(), from.begin() + start, from.begin() + start + length);
}

std::vector<uint8_t> ToVector(const std::string& str) {
  std::vector<uint8_t> vect;
  util::AppendToVector(str, &vect);
  return vect;
}

std::optional<std::vector<uint8_t>> SignatureToDerBytes(
    const std::vector<uint8_t>& r, const std::vector<uint8_t>& s) {
  if (r.size() != 32 || s.size() != 32) {
    LOG(ERROR) << "Incorrect input signature size.";
    return std::nullopt;
  }
  crypto::ScopedBIGNUM sig_r(BN_new()), sig_s(BN_new());
  crypto::ScopedECDSA_SIG sig(ECDSA_SIG_new());
  if (!sig_r || !sig_s || !sig) {
    LOG(ERROR) << "Failed to allocate ECDSA_SIG or BIGNUM.";
    return std::nullopt;
  }
  if (!BN_bin2bn(r.data(), 32, sig_r.get()) ||
      !BN_bin2bn(s.data(), 32, sig_s.get())) {
    LOG(ERROR) << "Failed to convert ECDSA_SIG parameters to BIGNUM";
    return std::nullopt;
  }

  if (!ECDSA_SIG_set0(sig.get(), sig_r.release(), sig_s.release())) {
    LOG(ERROR) << "Failed to initialize ECDSA_SIG";
    return std::nullopt;
  }

  int sig_len = i2d_ECDSA_SIG(sig.get(), nullptr);

  std::vector<uint8_t> signature(sig_len);
  uint8_t* sig_ptr = &signature[0];

  if (i2d_ECDSA_SIG(sig.get(), &sig_ptr) != sig_len) {
    LOG(ERROR) << "DER encoding returned unexpected length";
    return std::nullopt;
  }

  return signature;
}

std::vector<uint8_t> HmacSha256(const brillo::SecureBlob& key,
                                const std::vector<uint8_t>& data) {
  brillo::Blob mac(SHA256_DIGEST_LENGTH);
  HMAC(EVP_sha256(), key.data(), key.size(), data.data(), data.size(),
       mac.data(), nullptr);
  return mac;
}

bool DoSoftwareAttest(const std::vector<uint8_t>& data_to_sign,
                      std::vector<uint8_t>* attestation_cert,
                      std::vector<uint8_t>* signature) {
  crypto::ScopedEC_KEY attestation_key = util::CreateAttestationKey();
  if (!attestation_key) {
    return false;
  }

  std::optional<std::vector<uint8_t>> cert_result =
      util::CreateAttestationCertificate(attestation_key.get());
  std::optional<std::vector<uint8_t>> attest_result =
      util::AttestToData(data_to_sign, attestation_key.get());

  if (!cert_result.has_value() || !attest_result.has_value()) {
    // These functions are never expected to fail.
    LOG(ERROR) << "U2F software attestation failed.";
    return false;
  }

  *attestation_cert = std::move(*cert_result);
  *signature = std::move(*attest_result);
  return true;
}

crypto::ScopedEC_KEY CreateAttestationKey() {
  crypto::ScopedEC_KEY key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  EC_KEY_set_asn1_flag(key.get(), OPENSSL_EC_NAMED_CURVE);

  if (!key || !EC_KEY_generate_key(key.get())) {
    LOG(ERROR) << "Failed to generate U2F attestation key.";
    return nullptr;
  } else {
    return key;
  }
}

std::optional<std::vector<uint8_t>> AttestToData(
    const std::vector<uint8_t>& data, EC_KEY* attestation_key) {
  std::vector<uint8_t> digest = Sha256(data);

  std::vector<uint8_t> signature(ECDSA_size(attestation_key));
  unsigned int signature_length;

  if (!ECDSA_sign(0 /* type: ignored by OpenSSL */, &digest[0], digest.size(),
                  signature.data(), &signature_length, attestation_key)) {
    LOG(ERROR) << "Failed to sign data using U2F attestation key";
    return std::nullopt;
  }

  signature.resize(signature_length);
  return signature;
}

namespace {

template <typename C>
crypto::ScopedOpenSSL<X509, X509_free> ParseX509(const C& container) {
  const unsigned char* parse_ptr =
      static_cast<const unsigned char*>(&container[0]);

  crypto::ScopedOpenSSL<X509, X509_free> cert(
      d2i_X509(nullptr /* create and return new X509 struct */, &parse_ptr,
               container.size()));

  if (!cert) {
    LOG(ERROR) << "Failed to parse X509 certificate.";
  }

  return cert;
}

std::optional<std::vector<uint8_t>> DerEncodeCertificate(X509* cert) {
  int cert_size = i2d_X509(cert, nullptr);
  if (cert_size <= 0) {
    LOG(ERROR) << "Failed to DER-encode X509 certficate, error: " << cert_size;
    return std::nullopt;
  }

  unsigned char* output_ptr = nullptr;
  if (i2d_X509(cert, &output_ptr) != cert_size) {
    LOG(ERROR) << "X509 DER-encoding returned unexpected size, expected "
               << cert_size;
    return std::nullopt;
  }
  std::vector<uint8_t> cert_der(output_ptr, output_ptr + cert_size);
  OPENSSL_free(output_ptr);
  return cert_der;
}

}  // namespace

std::optional<std::vector<uint8_t>> CreateAttestationCertificate(
    EC_KEY* attestation_key) {
  // We use a fixed template for the X509 certificate rather than generating one
  // using OpenSSL, so that we can ensure that u2fd and cr50 both return
  // certificates with the same structure.
  // The array below is generated by the openssl tool from the template in
  // x509_tmpl.txt.
  constexpr std::array<unsigned char, 164> cert_template = {
      0x30, 0x81, 0xA1, 0x30, 0x81, 0x8E, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02,
      0x01, 0x00, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04,
      0x03, 0x02, 0x30, 0x0F, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04,
      0x03, 0x13, 0x04, 0x63, 0x72, 0x35, 0x30, 0x30, 0x22, 0x18, 0x0F, 0x32,
      0x30, 0x30, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30,
      0x30, 0x5A, 0x18, 0x0F, 0x32, 0x30, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31,
      0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5A, 0x30, 0x0F, 0x31, 0x0D, 0x30,
      0x0B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04, 0x63, 0x72, 0x35, 0x30,
      0x30, 0x19, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
      0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,
      0x02, 0x00, 0x00, 0xA3, 0x17, 0x30, 0x15, 0x30, 0x13, 0x06, 0x0B, 0x2B,
      0x06, 0x01, 0x04, 0x01, 0x82, 0xE5, 0x1C, 0x02, 0x01, 0x01, 0x04, 0x04,
      0x03, 0x02, 0x03, 0x08, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE,
      0x3D, 0x04, 0x03, 0x02, 0x03, 0x02, 0x00, 0x00,
  };

  crypto::ScopedOpenSSL<X509, X509_free> cert = ParseX509(cert_template);
  if (!cert) {
    return std::nullopt;
  }

  crypto::ScopedEVP_PKEY pkey(EVP_PKEY_new());
  if (!pkey || !EVP_PKEY_set1_EC_KEY(pkey.get(), attestation_key)) {
    LOG(ERROR) << "Failed to create EVP_PKEY";
    return std::nullopt;
  }

  if (!X509_set_pubkey(cert.get(), pkey.get()) ||
      X509_sign(cert.get(), pkey.get(), EVP_sha256()) <=
          0 /* returns length on success */) {
    LOG(ERROR) << "Failed to update X509 pubkey and signature fields";
    return std::nullopt;
  }

  return DerEncodeCertificate(cert.get());
}

bool RemoveCertificatePadding(std::vector<uint8_t>* cert_in) {
  const unsigned char* cert_start = &cert_in->front();
  const unsigned char* parse_ptr = cert_start;

  crypto::ScopedOpenSSL<X509, X509_free> cert(
      d2i_X509(nullptr /* create and return new X509 struct */, &parse_ptr,
               cert_in->size()));

  if (!cert) {
    LOG(ERROR) << "Failed to parse X509 certificate.";
    return false;
  }

  size_t cert_size = parse_ptr - cert_start;

  if (cert_size > cert_in->size()) {
    LOG(ERROR) << "Unexpectedly parsed X509 cert larger than input buffer.";
    return false;
  }

  cert_in->resize(cert_size);
  return true;
}

std::vector<uint8_t> BuildU2fRegisterResponseSignedData(
    const std::vector<uint8_t>& app_id,
    const std::vector<uint8_t>& challenge,
    const std::vector<uint8_t>& pub_key,
    const std::vector<uint8_t>& key_handle) {
  std::vector<uint8_t> signed_data;
  signed_data.push_back('\0');  // reserved byte
  util::AppendToVector(app_id, &signed_data);
  util::AppendToVector(challenge, &signed_data);
  util::AppendToVector(key_handle, &signed_data);
  util::AppendToVector(pub_key, &signed_data);
  return signed_data;
}

std::optional<brillo::Blob> ParseSerialNumberFromCert(
    const brillo::Blob& cert_template) {
  crypto::ScopedOpenSSL<X509, X509_free> cert = ParseX509(cert_template);
  if (!cert) {
    LOG(ERROR) << "Failed to parse X509 cert.";
    return std::nullopt;
  }

  unsigned char* serial_number_buffer = nullptr;
  size_t length = i2d_ASN1_INTEGER(X509_get_serialNumber(cert.get()),
                                   &serial_number_buffer);
  crypto::ScopedOpenSSLBytes scoped_serial_number_buffer(serial_number_buffer);
  if (length <= 0) {
    LOG(ERROR) << "Failed to encode certificate serial number.";
    return std::nullopt;
  }

  brillo::Blob serial_number;
  serial_number.assign(serial_number_buffer, serial_number_buffer + length);

  return serial_number;
}

}  // namespace util
}  // namespace u2f
