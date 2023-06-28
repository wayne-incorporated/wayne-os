// Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_MOCK_NSS_UTIL_H_
#define LOGIN_MANAGER_MOCK_NSS_UTIL_H_

#include "login_manager/nss_util.h"

#include <stdint.h>
#include <unistd.h>

#include <memory>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <crypto/nss_util.h>
#include <crypto/rsa_private_key.h>
#include <crypto/scoped_nss_types.h>
#include <crypto/scoped_test_nss_db.h>
#include <gmock/gmock.h>

namespace crypto {
class RSAPrivateKey;
}

namespace login_manager {
// Forward declaration.
typedef struct PK11SlotInfoStr PK11SlotInfo;

class MockNssUtil : public NssUtil {
 public:
  MockNssUtil();
  MockNssUtil(const MockNssUtil&) = delete;
  MockNssUtil& operator=(const MockNssUtil&) = delete;

  ~MockNssUtil() override;

  std::unique_ptr<crypto::RSAPrivateKey> CreateShortKey();

  ScopedPK11SlotDescriptor OpenUserDB(
      const base::FilePath& user_homedir,
      const OptionalFilePath& ns_mnt_path) override;
  MOCK_METHOD(std::unique_ptr<crypto::RSAPrivateKey>,
              GetPrivateKeyForUser,
              (const std::vector<uint8_t>&, PK11SlotDescriptor*),
              (override));
  MOCK_METHOD(std::unique_ptr<crypto::RSAPrivateKey>,
              GenerateKeyPairForUser,
              (PK11SlotDescriptor*),
              (override));
  MOCK_METHOD(base::FilePath, GetNssdbSubpath, (), (override));
  MOCK_METHOD(bool,
              CheckPublicKeyBlob,
              (const std::vector<uint8_t>&),
              (override));
  MOCK_METHOD(bool,
              Verify,
              (const std::vector<uint8_t>&,
               const std::vector<uint8_t>&,
               const std::vector<uint8_t>&),
              (override));
  MOCK_METHOD(bool,
              Sign,
              (const std::vector<uint8_t>&,
               crypto::RSAPrivateKey*,
               std::vector<uint8_t>*),
              (override));
  base::FilePath GetOwnerKeyFilePath() override;

  PK11SlotDescriptor* GetDescriptor();
  PK11SlotInfo* GetSlot();

  // After this is called, OpenUserDB() will return empty ScopedPK11Slots.
  void MakeBadDB() { return_bad_db_ = true; }

  // Ensures that temp_dir_ is created and accessible.
  bool EnsureTempDir();

 protected:
  bool return_bad_db_ = false;
  crypto::ScopedTestNSSDB test_nssdb_;
  base::ScopedTempDir temp_dir_;
  ScopedPK11SlotDescriptor desc_;
};

class CheckPublicKeyUtil : public MockNssUtil {
 public:
  explicit CheckPublicKeyUtil(bool expected);
  CheckPublicKeyUtil(const CheckPublicKeyUtil&) = delete;
  CheckPublicKeyUtil& operator=(const CheckPublicKeyUtil&) = delete;

  ~CheckPublicKeyUtil() override;
};

class KeyCheckUtil : public MockNssUtil {
 public:
  KeyCheckUtil();
  KeyCheckUtil(const KeyCheckUtil&) = delete;
  KeyCheckUtil& operator=(const KeyCheckUtil&) = delete;

  ~KeyCheckUtil() override;
};

class KeyFailUtil : public MockNssUtil {
 public:
  KeyFailUtil();
  KeyFailUtil(const KeyFailUtil&) = delete;
  KeyFailUtil& operator=(const KeyFailUtil&) = delete;

  ~KeyFailUtil() override;
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_MOCK_NSS_UTIL_H_
