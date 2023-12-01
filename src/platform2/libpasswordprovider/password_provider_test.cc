// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <unistd.h>

#include <keyutils.h>

#include <memory>
#include <string>

#include <gtest/gtest.h>

#include "base/logging.h"
#include "libpasswordprovider/password.h"
#include "libpasswordprovider/password_provider.h"
#include "libpasswordprovider/password_provider_test_utils.h"

namespace password_provider {

// Tests for the PasswordProvider class.
class PasswordProviderTest : public testing::Test {
 protected:
  void SetUp() override {
    // Before running a test, check if keyrings are supported in the kernel.
    keyrings_supported_ =
        !(keyctl_clear(KEY_SPEC_PROCESS_KEYRING) == -1 && errno == ENOSYS);
  }

  PasswordProvider password_provider_;
  bool keyrings_supported_ = true;
};

// Saving and retrieving password should succeed.
TEST_F(PasswordProviderTest, SaveAndGetPassword) {
  if (!keyrings_supported_) {
    LOG(WARNING)
        << "Skipping test because keyrings are not supported by the kernel.";
    return;
  }

  const std::string kPasswordStr("thepassword");
  auto password = test::CreatePassword(kPasswordStr);

  EXPECT_TRUE(password_provider_.SavePassword(*password.get()));
  std::unique_ptr<Password> retrieved_password =
      password_provider_.GetPassword();
  ASSERT_TRUE(retrieved_password);
  EXPECT_EQ(std::string(retrieved_password->GetRaw()), kPasswordStr);
  EXPECT_EQ(retrieved_password->size(), kPasswordStr.size());
}

// Reading password should fail if password was already discarded.
TEST_F(PasswordProviderTest, DiscardAndGetPassword) {
  if (!keyrings_supported_) {
    LOG(WARNING)
        << "Skipping test because keyrings are not supported by the kernel.";
    return;
  }

  const std::string kPasswordStr("thepassword");
  auto password = test::CreatePassword(kPasswordStr);

  EXPECT_TRUE(password_provider_.SavePassword(*password.get()));
  EXPECT_TRUE(password_provider_.DiscardPassword());
  std::unique_ptr<Password> retrieved_password =
      password_provider_.GetPassword();
  EXPECT_FALSE(retrieved_password);
}

// Retrieving a very long password should succeed.
TEST_F(PasswordProviderTest, GetLongPassword) {
  if (!keyrings_supported_) {
    LOG(WARNING)
        << "Skipping test because keyrings are not supported by the kernel.";
    return;
  }

  // Create a very long password.
  // (page size - 1) is the max size of the Password buffer.
  size_t max_size = sysconf(_SC_PAGESIZE) - 1;
  auto long_password = std::make_unique<char[]>(max_size);
  memset(long_password.get(), 'a', max_size);
  std::string password_str(long_password.get(), max_size);
  auto password = test::CreatePassword(password_str);

  EXPECT_TRUE(password_provider_.SavePassword(*password.get()));
  std::unique_ptr<Password> retrieved_password =
      password_provider_.GetPassword();
  ASSERT_TRUE(retrieved_password);
  EXPECT_EQ(std::string(retrieved_password->GetRaw()), password_str);
}

}  // namespace password_provider
