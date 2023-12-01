// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_COMMON_MOCK_CRYPTO_UTILITY_H_
#define ATTESTATION_COMMON_MOCK_CRYPTO_UTILITY_H_

#include "attestation/common/crypto_utility.h"

#include <string>

#include <gmock/gmock.h>

namespace attestation {

class MockCryptoUtility : public CryptoUtility {
 public:
  MockCryptoUtility();
  ~MockCryptoUtility() override;

  MOCK_METHOD(bool, GetRandom, (size_t, std::string*), (const, override));

  MOCK_METHOD(bool, CreateSealedKey, (std::string*, std::string*), (override));

  MOCK_METHOD(bool,
              EncryptData,
              (const std::string&,
               const std::string&,
               const std::string&,
               std::string*),
              (override));

  MOCK_METHOD(bool,
              UnsealKey,
              (const std::string&, std::string*, std::string*),
              (override));

  MOCK_METHOD(bool,
              DecryptData,
              (const std::string&, const std::string&, std::string*),
              (override));
  MOCK_METHOD(bool,
              GetRSASubjectPublicKeyInfo,
              (const std::string&, std::string*),
              (override));
  MOCK_METHOD(bool,
              GetRSAPublicKey,
              (const std::string&, std::string*),
              (override));
  MOCK_METHOD(bool,
              EncryptIdentityCredential,
              (TpmVersion,
               const std::string&,
               const std::string&,
               const std::string&,
               EncryptedIdentityCredential*),
              (override));
  MOCK_METHOD(bool,
              DecryptIdentityCertificateForTpm2,
              (const std::string&, const EncryptedData&, std::string*),
              (override));
  MOCK_METHOD(bool,
              EncryptForUnbind,
              (const std::string&, const std::string&, std::string*),
              (override));
  MOCK_METHOD(bool,
              VerifySignature,
              (int, const std::string&, const std::string&, const std::string&),
              (override));
  MOCK_METHOD(bool,
              VerifySignatureUsingHexKey,
              (int, const std::string&, const std::string&, const std::string&),
              (override));
  MOCK_METHOD(bool,
              EncryptDataForGoogle,
              (const std::string&,
               const std::string&,
               const std::string&,
               EncryptedData*),
              (override));
  MOCK_METHOD(bool,
              CreateSPKAC,
              (const std::string&, const std::string&, KeyType, std::string*),
              (override));
  MOCK_METHOD(bool,
              VerifyCertificate,
              (const std::string&, const std::string&),
              (override));
  MOCK_METHOD(bool,
              VerifyCertificateWithSubjectPublicKey,
              (const std::string&, const std::string&),
              (override));
  MOCK_METHOD(bool,
              GetCertificateIssuerName,
              (const std::string&, std::string*),
              (override));
  MOCK_METHOD(bool,
              GetCertificateSubjectPublicKeyInfo,
              (const std::string&, std::string*),
              (override));
  MOCK_METHOD(bool,
              GetCertificatePublicKey,
              (const std::string&, std::string*),
              (override));
  MOCK_METHOD(bool,
              GetKeyDigest,
              (const std::string&, std::string*),
              (override));
  MOCK_METHOD(std::string,
              HmacSha256,
              (const std::string&, const std::string&),
              (override));
  MOCK_METHOD(std::string,
              HmacSha512,
              (const std::string&, const std::string&),
              (override));
  MOCK_METHOD(int, DefaultDigestAlgoForSignature, (), (override));
};

}  // namespace attestation

#endif  // ATTESTATION_COMMON_MOCK_CRYPTO_UTILITY_H_
