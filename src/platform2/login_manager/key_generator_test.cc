// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/key_generator.h"

#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <memory>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/memory/ref_counted.h>
#include <base/optional.h>
#include <base/time/time.h>
#include <brillo/cryptohome.h>
#include <gtest/gtest.h>

#include "login_manager/fake_child_process.h"
#include "login_manager/fake_generated_key_handler.h"
#include "login_manager/fake_generator_job.h"
#include "login_manager/keygen_worker.h"
#include "login_manager/matchers.h"
#include "login_manager/mock_nss_util.h"
#include "login_manager/nss_util.h"
#include "login_manager/system_utils_impl.h"

namespace login_manager {

using ::testing::_;
using ::testing::InvokeWithoutArgs;
using ::testing::Return;
using ::testing::StrEq;

using brillo::cryptohome::home::GetUserPathPrefix;
using brillo::cryptohome::home::SetSystemSalt;
using brillo::cryptohome::home::SetUserHomePrefix;

class KeyGeneratorTest : public ::testing::Test {
 public:
  KeyGeneratorTest()
      : original_user_prefix_(GetUserPathPrefix()), fake_salt_("fake salt") {}
  KeyGeneratorTest(const KeyGeneratorTest&) = delete;
  KeyGeneratorTest& operator=(const KeyGeneratorTest&) = delete;

  ~KeyGeneratorTest() override {}

  void SetUp() override {
    ASSERT_TRUE(tmpdir_.CreateUniqueTempDir());
    SetUserHomePrefix(tmpdir_.GetPath().value() + "/");
    SetSystemSalt(&fake_salt_);
  }

  void TearDown() override {
    SetUserHomePrefix(original_user_prefix_.value());
    SetSystemSalt(nullptr);
  }

 protected:
  SystemUtilsImpl utils_;
  base::ScopedTempDir tmpdir_;
  const base::FilePath original_user_prefix_;
  std::string fake_salt_;
};

TEST_F(KeyGeneratorTest, KeygenEndToEndTest) {
  FakeGeneratedKeyHandler handler;

  pid_t kFakePid = 4;
  std::string fake_ownername("user");
  std::string fake_key_contents("stuff");
  siginfo_t fake_info;
  memset(&fake_info, 0, sizeof(siginfo_t));
  fake_info.si_pid = kFakePid;

  KeyGenerator keygen(getuid(), &utils_);
  keygen.set_delegate(&handler);
  keygen.InjectJobFactory(std::unique_ptr<GeneratorJobFactoryInterface>(
      new FakeGeneratorJob::Factory(kFakePid, "gen", fake_key_contents)));

  ASSERT_TRUE(keygen.Start(fake_ownername, base::nullopt));
  keygen.HandleExit(fake_info);

  EXPECT_EQ(fake_ownername, handler.key_username());
  EXPECT_GT(handler.key_contents().size(), 0);
}

TEST_F(KeyGeneratorTest, GenerateKey) {
  MockNssUtil nss;
  EXPECT_CALL(nss, GetNssdbSubpath()).Times(1);
  ON_CALL(nss, GenerateKeyPairForUser(_))
      .WillByDefault(InvokeWithoutArgs(&nss, &MockNssUtil::CreateShortKey));
  EXPECT_CALL(nss, GenerateKeyPairForUser(_)).Times(1);

  const base::FilePath key_file_path(tmpdir_.GetPath().AppendASCII("foo.pub"));
  ASSERT_EQ(keygen::GenerateKey(key_file_path, tmpdir_.GetPath(), &nss), 0);
  ASSERT_TRUE(base::PathExists(key_file_path));

  int32_t file_size = 0;
  ASSERT_TRUE(utils_.EnsureAndReturnSafeFileSize(key_file_path, &file_size));
  ASSERT_GT(file_size, 0);
}

}  // namespace login_manager
