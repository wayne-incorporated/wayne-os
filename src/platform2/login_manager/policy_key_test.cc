// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/policy_key.h"

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <crypto/nss_key_util.h>
#include <crypto/nss_util.h>
#include <crypto/nss_util_internal.h>
#include <crypto/rsa_private_key.h>
#include <gtest/gtest.h>

#include "login_manager/blob_util.h"
#include "login_manager/mock_nss_util.h"
#include "login_manager/nss_util.h"

namespace login_manager {

class PolicyKeyTest : public ::testing::Test {
 public:
  PolicyKeyTest() {}
  PolicyKeyTest(const PolicyKeyTest&) = delete;
  PolicyKeyTest& operator=(const PolicyKeyTest&) = delete;

  ~PolicyKeyTest() override {}

  void SetUp() override {
    ASSERT_TRUE(tmpdir_.CreateUniqueTempDir());
    ASSERT_TRUE(base::CreateTemporaryFileInDir(tmpdir_.GetPath(), &tmpfile_));
    ASSERT_EQ(2, base::WriteFile(tmpfile_, "a", 2));
  }

  void TearDown() override {}

  void StartUnowned() { base::DeleteFile(tmpfile_); }

  static std::unique_ptr<crypto::RSAPrivateKey> CreateRSAPrivateKey(
      PK11SlotInfo* slot, uint16_t num_bits) {
    std::unique_ptr<crypto::RSAPrivateKey> key;
    crypto::ScopedSECKEYPublicKey public_key_obj;
    crypto::ScopedSECKEYPrivateKey private_key_obj;
    if (crypto::GenerateRSAKeyPairNSS(slot, num_bits, true /* permanent */,
                                      &public_key_obj, &private_key_obj)) {
      key.reset(crypto::RSAPrivateKey::CreateFromKey(private_key_obj.get()));
    }
    return key;
  }

  base::FilePath tmpfile_;

 private:
  base::ScopedTempDir tmpdir_;
};

TEST_F(PolicyKeyTest, Equals) {
  // Set up an empty key
  StartUnowned();
  MockNssUtil noop_util;
  PolicyKey key(tmpfile_, &noop_util);
  ASSERT_TRUE(key.PopulateFromDiskIfPossible());
  ASSERT_TRUE(key.HaveCheckedDisk());
  ASSERT_FALSE(key.IsPopulated());

  // Trivial case.
  EXPECT_TRUE(key.VEquals(std::vector<uint8_t>()));

  // Ensure that 0-length keys don't cause us to return true for everything.
  const std::vector<uint8_t> fake = {1};
  EXPECT_FALSE(key.VEquals(fake));

  // Populate the key.
  ASSERT_TRUE(key.PopulateFromBuffer(fake));
  ASSERT_TRUE(key.HaveCheckedDisk());
  ASSERT_TRUE(key.IsPopulated());

  // Real comparison.
  EXPECT_TRUE(key.VEquals(fake));
}

TEST_F(PolicyKeyTest, LoadKey) {
  CheckPublicKeyUtil good_key_util(true);
  PolicyKey key(tmpfile_, &good_key_util);
  ASSERT_FALSE(key.HaveCheckedDisk());
  ASSERT_FALSE(key.IsPopulated());
  ASSERT_TRUE(key.PopulateFromDiskIfPossible());
  ASSERT_TRUE(key.HaveCheckedDisk());
  ASSERT_TRUE(key.IsPopulated());
}

TEST_F(PolicyKeyTest, NoKeyToLoad) {
  StartUnowned();
  MockNssUtil noop_util;
  PolicyKey key(tmpfile_, &noop_util);
  ASSERT_FALSE(key.HaveCheckedDisk());
  ASSERT_FALSE(key.IsPopulated());
  ASSERT_TRUE(key.PopulateFromDiskIfPossible());
  ASSERT_TRUE(key.HaveCheckedDisk());
  ASSERT_FALSE(key.IsPopulated());
}

TEST_F(PolicyKeyTest, EmptyKeyToLoad) {
  ASSERT_EQ(0, base::WriteFile(tmpfile_, "", 0));
  ASSERT_TRUE(base::PathExists(tmpfile_));
  CheckPublicKeyUtil bad_key_util(false);

  PolicyKey key(tmpfile_, &bad_key_util);
  ASSERT_FALSE(key.HaveCheckedDisk());
  ASSERT_FALSE(key.IsPopulated());
  ASSERT_FALSE(key.PopulateFromDiskIfPossible());
  ASSERT_TRUE(key.HaveCheckedDisk());
  ASSERT_FALSE(key.IsPopulated());
}

TEST_F(PolicyKeyTest, NoKeyOnDiskAllowSetting) {
  StartUnowned();
  MockNssUtil noop_util;
  PolicyKey key(tmpfile_, &noop_util);
  ASSERT_FALSE(key.HaveCheckedDisk());
  ASSERT_FALSE(key.IsPopulated());
  ASSERT_TRUE(key.PopulateFromDiskIfPossible());
  ASSERT_TRUE(key.HaveCheckedDisk());
  ASSERT_FALSE(key.IsPopulated());

  const std::vector<uint8_t> fake = {1};
  ASSERT_TRUE(key.PopulateFromBuffer(fake));
  ASSERT_TRUE(key.HaveCheckedDisk());
  ASSERT_TRUE(key.IsPopulated());
}

TEST_F(PolicyKeyTest, EnforceDiskCheckFirst) {
  const std::vector<uint8_t> fake = {1};

  MockNssUtil noop_util;
  PolicyKey key(tmpfile_, &noop_util);
  ASSERT_FALSE(key.HaveCheckedDisk());
  ASSERT_FALSE(key.IsPopulated());
  ASSERT_FALSE(key.PopulateFromBuffer(fake));
  ASSERT_FALSE(key.IsPopulated());
  ASSERT_FALSE(key.HaveCheckedDisk());
}

TEST_F(PolicyKeyTest, RefuseToClobberInMemory) {
  const std::vector<uint8_t> fake = {1};

  CheckPublicKeyUtil good_key_util(true);
  PolicyKey key(tmpfile_, &good_key_util);
  ASSERT_FALSE(key.HaveCheckedDisk());
  ASSERT_FALSE(key.IsPopulated());

  ASSERT_TRUE(key.PopulateFromDiskIfPossible());
  ASSERT_TRUE(key.HaveCheckedDisk());
  ASSERT_TRUE(key.IsPopulated());

  ASSERT_FALSE(key.PopulateFromBuffer(fake));
  ASSERT_TRUE(key.HaveCheckedDisk());
  ASSERT_TRUE(key.IsPopulated());
}

TEST_F(PolicyKeyTest, RefuseToClobberOnDisk) {
  CheckPublicKeyUtil good_key_util(true);
  PolicyKey key(tmpfile_, &good_key_util);
  ASSERT_FALSE(key.HaveCheckedDisk());
  ASSERT_FALSE(key.IsPopulated());

  ASSERT_TRUE(key.PopulateFromDiskIfPossible());
  ASSERT_TRUE(key.HaveCheckedDisk());
  ASSERT_TRUE(key.IsPopulated());

  ASSERT_FALSE(key.Persist());
  ASSERT_TRUE(key.HaveCheckedDisk());
  ASSERT_TRUE(key.IsPopulated());
}

TEST_F(PolicyKeyTest, SignVerify) {
  std::unique_ptr<NssUtil> nss(NssUtil::Create());
  StartUnowned();
  PolicyKey key(tmpfile_, nss.get());
  crypto::ScopedTestNSSDB test_db;

  std::unique_ptr<crypto::RSAPrivateKey> pair(
      CreateRSAPrivateKey(test_db.slot(), 512));
  ASSERT_NE(pair, nullptr);

  ASSERT_TRUE(key.PopulateFromDiskIfPossible());
  ASSERT_TRUE(key.HaveCheckedDisk());
  ASSERT_FALSE(key.IsPopulated());

  {
    std::vector<uint8_t> to_export;
    ASSERT_TRUE(pair->ExportPublicKey(&to_export));
    ASSERT_TRUE(key.PopulateFromBuffer(to_export));
  }
  ASSERT_TRUE(key.HaveCheckedDisk());
  ASSERT_TRUE(key.IsPopulated());

  const std::vector<uint8_t> data = StringToBlob("whatever");
  std::vector<uint8_t> signature;
  EXPECT_TRUE(nss->Sign(data, pair.get(), &signature));
  EXPECT_TRUE(key.Verify(data, signature));
}

TEST_F(PolicyKeyTest, RotateKey) {
  std::unique_ptr<NssUtil> nss(NssUtil::Create());
  StartUnowned();
  PolicyKey key(tmpfile_, nss.get());
  crypto::ScopedTestNSSDB test_db;

  std::unique_ptr<crypto::RSAPrivateKey> pair(
      CreateRSAPrivateKey(test_db.slot(), 512));
  ASSERT_NE(pair, nullptr);

  ASSERT_TRUE(key.PopulateFromDiskIfPossible());
  ASSERT_TRUE(key.HaveCheckedDisk());
  ASSERT_FALSE(key.IsPopulated());

  {
    std::vector<uint8_t> to_export;
    ASSERT_TRUE(pair->ExportPublicKey(&to_export));
    ASSERT_TRUE(key.PopulateFromBuffer(to_export));
  }
  ASSERT_TRUE(key.HaveCheckedDisk());
  ASSERT_TRUE(key.IsPopulated());
  ASSERT_TRUE(key.Persist());

  PolicyKey key2(tmpfile_, nss.get());
  ASSERT_TRUE(key2.PopulateFromDiskIfPossible());
  ASSERT_TRUE(key2.HaveCheckedDisk());
  ASSERT_TRUE(key2.IsPopulated());

  std::unique_ptr<crypto::RSAPrivateKey> new_pair(
      CreateRSAPrivateKey(test_db.slot(), 512));
  ASSERT_NE(new_pair, nullptr);
  std::vector<uint8_t> new_export;
  ASSERT_TRUE(new_pair->ExportPublicKey(&new_export));

  std::vector<uint8_t> signature;
  ASSERT_TRUE(nss->Sign(new_export, pair.get(), &signature));
  ASSERT_TRUE(key2.Rotate(new_export, signature));
  ASSERT_TRUE(key2.Persist());
}

TEST_F(PolicyKeyTest, ClobberKey) {
  CheckPublicKeyUtil good_key_util(true);
  PolicyKey key(tmpfile_, &good_key_util);

  ASSERT_TRUE(key.PopulateFromDiskIfPossible());
  ASSERT_TRUE(key.HaveCheckedDisk());
  ASSERT_TRUE(key.IsPopulated());

  const std::vector<uint8_t> fake = {1};
  key.ClobberCompromisedKey(fake);
  ASSERT_TRUE(key.VEquals(fake));
  ASSERT_TRUE(key.Persist());
}

TEST_F(PolicyKeyTest, ResetKey) {
  CheckPublicKeyUtil good_key_util(true);
  PolicyKey key(tmpfile_, &good_key_util);

  ASSERT_TRUE(key.PopulateFromDiskIfPossible());
  ASSERT_TRUE(key.HaveCheckedDisk());
  ASSERT_TRUE(key.IsPopulated());

  key.ClobberCompromisedKey(std::vector<uint8_t>());
  ASSERT_TRUE(!key.IsPopulated());
  ASSERT_TRUE(key.Persist());
  ASSERT_FALSE(base::PathExists(tmpfile_));
}

}  // namespace login_manager
