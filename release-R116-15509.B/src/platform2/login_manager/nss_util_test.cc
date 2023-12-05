// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/nss_util.h"

#include <stdint.h>

#include <memory>
#include <optional>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <crypto/nss_util.h>
#include <crypto/rsa_private_key.h>
#include <crypto/scoped_nss_types.h>
#include <gtest/gtest.h>

using crypto::ScopedPK11Slot;

namespace login_manager {
class NssUtilTest : public ::testing::Test {
 public:
  NssUtilTest() : util_(NssUtil::Create()) {}
  NssUtilTest(const NssUtilTest&) = delete;
  NssUtilTest& operator=(const NssUtilTest&) = delete;

  ~NssUtilTest() override {}

  void SetUp() override {
    ASSERT_TRUE(tmpdir_.CreateUniqueTempDir());
    ASSERT_TRUE(base::CreateDirectory(
        tmpdir_.GetPath().Append(util_->GetNssdbSubpath())));
    desc_ = util_->OpenUserDB(tmpdir_.GetPath(), std::nullopt);
  }

 protected:
  static const char kUsername[];
  base::ScopedTempDir tmpdir_;
  std::unique_ptr<NssUtil> util_;
  ScopedPK11SlotDescriptor desc_;
};

const char NssUtilTest::kUsername[] = "someone@nowhere.com";

TEST_F(NssUtilTest, FindFromPublicKey) {
  // Create a keypair, which will put the keys in the user's NSSDB.
  std::unique_ptr<crypto::RSAPrivateKey> pair(
      util_->GenerateKeyPairForUser(desc_.get()));
  ASSERT_NE(pair, nullptr);

  std::vector<uint8_t> public_key;
  ASSERT_TRUE(pair->ExportPublicKey(&public_key));

  EXPECT_TRUE(util_->CheckPublicKeyBlob(public_key));

  std::unique_ptr<crypto::RSAPrivateKey> private_key(
      util_->GetPrivateKeyForUser(public_key, desc_.get()));
  EXPECT_NE(private_key, nullptr);
}

TEST_F(NssUtilTest, RejectBadPublicKey) {
  std::vector<uint8_t> public_key(10, 'a');
  EXPECT_FALSE(util_->CheckPublicKeyBlob(public_key));
}

}  // namespace login_manager
