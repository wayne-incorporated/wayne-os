// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-test-utils/fake_pca_agent/issue_certificate.h"

#include <openssl/x509.h>

#include <optional>

#include <base/logging.h>

#include "hwsec-test-utils/common/openssl_utility.h"
#include "hwsec-test-utils/well_known_key_pairs/well_known_key_pairs.h"

namespace hwsec_test_utils {

namespace {

constexpr int kDummySerialNumber = 9487;
constexpr int kDummyDeadlineInSeconds = 60 * 60 * 24;
constexpr unsigned char kDummyCountry[] = "CR";
constexpr unsigned char kDummyOrganization[] = "Attestation Local Test Infra";
constexpr unsigned char kDummyCommonName[] = "localhost";

constexpr char kSigningKeyPem[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEAuVJlvwxcP+Be6k9WjJRotgsf4SvNVo/O+kXKISI+JklXIW1A\n"
    "3+m6US2l9t4lFjd30RFNPWaCUN6y7a7jQJ4g/1bP7c+2Aykm9A00YuOUbVSrYSM1\n"
    "mnOIHR7m8utFrRzlho3+GACs6nVc5b+oxwqrkjHEo3piLv5wqubNJ4pdGEsMSLxO\n"
    "gO8icttZe/DSSHeOm7P8pnv86mBnKUf628mSN5VPn0d9zkyeK74WEmNVVr6JVrnz\n"
    "UBX0zeg12Zraio1f7A75WKSD+BaOfKoyxEGRiTbxFoQZfK/Pn7pjmXCfW7YlU5xv\n"
    "Z9uYh2KSfkSg3zMr1j9gqNyRn6CoV+1fLu2oswIDAQABAoIBAQCO05dBB7itLjJY\n"
    "qS7OB68v5iD6vHRz6z+cmV7v7GEzxsBVLcubBpqm5+SJ/6lblwJL6ea6lJ+Izine\n"
    "jzPr4DMUN4bnBHeFthikbOzb7gO9w0yV/7nXQIU91EwwGe1IPwYSjqqvOw4JYMxo\n"
    "8S6VwH58nMitKaw0Bbs1q82fVL7s8dGr+B1QRrkW/kq4AL+1ZyntHICqLdhOY81M\n"
    "pP+o02I7sdx9Gereh6vtxiTBvcNCWMySBv4q4LX7sRYAgR2kDZtQEi294oJAISFb\n"
    "oSB+A+GzKD88NBNZdfF5wkLUrFS95p4gmV4BN/IAYshcZMXmI9cY5O5Y8t941laJ\n"
    "XtYV6mQ5AoGBAOgE7gcL6KaFwQRCdhflRPtE6YOEPu/8cIlWbzRueiOFWKfqA+8r\n"
    "lymSrIIc+lxvYMtyX7BesTlU39LolW9c/JSBaxLgWzBzbeqqRqA+KjBya6sWRd5h\n"
    "8UV/nUCL9b6DiDYaosAYy4J5rtkFepIxlY+dEl6dfxCdjnsS39lCi4s3AoGBAMx5\n"
    "4wCdM88YVZv+P2dkQJ+dAaOJoZ7RMtY+fO8gjd1dS4pCxYvycn/gwC/VORnonibF\n"
    "+te95izLkPisofIIOwFD0Z+QBT8rnsOjLew1XrqGoO4VBuvxhDPaQy1oYYi/1YVl\n"
    "9HTKiNMVQUvjEWYRaz6LnkpoFzAWYY0cEqkCFCRlAoGASgYQnwTopAA2dZJytOr7\n"
    "2CLDUadmoRBsIxUFg7ffleecQm5B9RN2NdhK23Q9WDJcsmv6JX4AkucGRfbYfmAv\n"
    "YX3s2GfmEA4zulO7FrLeqPhIa5w+jFW5MVAmroo4zCCQ25oh5KHEhAsogqrh0TSq\n"
    "n9ggHTmoaXerFo8OBfXaKX8CgYA0fOlHhBMDizSWmXo/GR35mv0LtM23De5lzp6V\n"
    "Z57i/wrgD+nT1cWMi+3pmWtR+kN2ooWUkdufDhZFr1LW5UP4PCd4NSkToSfdAmtM\n"
    "YhrR+LMgymb/c/zCrrll05CN4Oh3mMdan47l2GPtjfkuYTRNVtuoL/Yb0vLxnQ4x\n"
    "MiZnfQKBgQC90+lhI3hGv71rKl2i44Zr5suft/VDx+1w7bTqVIbQDE7YfwfPghwh\n"
    "BapLiMbo9ggUdLabM72fOSpB1fqwiYZM98vUOYnKRmUlMll5NgXxeNsk8sctRdhZ\n"
    "yor1Akd3Nm2GLfTPPBKnXsT9d5LhD0a0b7dLZk/2PkB8vhuze4cdlg==\n"
    "-----END RSA PRIVATE KEY-----";

}  // namespace

crypto::ScopedX509 IssueTestCertificate(const crypto::ScopedEVP_PKEY& subject) {
  crypto::ScopedX509 x509(X509_new());
  if (ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), kDummySerialNumber) !=
      1) {
    LOG(ERROR) << __func__
               << ": Failed to call ASN1_INTEGER_set: " << GetOpenSSLError();
    return nullptr;
  }
  X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
  X509_gmtime_adj(X509_get_notAfter(x509.get()), kDummyDeadlineInSeconds);
  if (X509_set_pubkey(x509.get(), subject.get()) != 1) {
    LOG(ERROR) << __func__
               << ": Failed to call X509_set_pubkey: " << GetOpenSSLError();
    return nullptr;
  }
  X509_NAME* name = X509_get_subject_name(x509.get());
  if (X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, kDummyCountry, -1, -1,
                                 0) != 1) {
    LOG(ERROR) << __func__ << ": Failed to call X509_NAME_add_entry_by_txt: "
               << GetOpenSSLError();
    return nullptr;
  }
  if (X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, kDummyOrganization,
                                 -1, -1, 0) != 1) {
    LOG(ERROR) << __func__ << ": Failed to call X509_NAME_add_entry_by_txt: "
               << GetOpenSSLError();
    return nullptr;
  }
  if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, kDummyCommonName, -1,
                                 -1, 0) != 1) {
    LOG(ERROR) << __func__ << ": Failed to call X509_NAME_add_entry_by_txt: "
               << GetOpenSSLError();
    return nullptr;
  }
  if (X509_set_issuer_name(x509.get(), name) != 1) {
    LOG(ERROR) << __func__ << ": Failed to call X509_set_issuer_name: "
               << GetOpenSSLError();
    return nullptr;
  }

  crypto::ScopedEVP_PKEY signing_key = PemToEVP(kSigningKeyPem);
  if (!signing_key) {
    LOG(ERROR) << __func__ << " : Failed to create signing key.";
    return nullptr;
  }
  if (X509_sign(x509.get(), signing_key.get(), EVP_sha1()) == 0) {
    LOG(ERROR) << __func__
               << ": Failed to call X509_sign: " << GetOpenSSLError();
    return nullptr;
  }
  return x509;
}

std::optional<std::string> IssueTestCertificateDer(
    const crypto::ScopedEVP_PKEY& subject) {
  crypto::ScopedX509 x509 = IssueTestCertificate(subject);
  if (!x509) {
    LOG(ERROR) << __func__ << ": Failed to issue test certificate.";
    return {};
  }
  int length = i2d_X509(x509.get(), nullptr);
  if (length <= 0) {
    LOG(ERROR) << __func__ << ": Failed to call i2d_X509 to get output size: "
               << GetOpenSSLError();
    return {};
  }
  unsigned char* output = nullptr;
  if (i2d_X509(x509.get(), &output) <= 0) {
    LOG(ERROR) << __func__
               << ": Failed to call i2d_X509: " << GetOpenSSLError();
    return {};
  }
  // Let it free after the return value construction.
  crypto::ScopedOpenSSLBytes scoped_output(output);
  return std::string(output, output + length);
}

}  // namespace hwsec_test_utils
