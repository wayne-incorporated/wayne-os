// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/da_reset/da_resetter.h"

#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <tpm_manager-client-test/tpm_manager/dbus-proxy-mocks.h>

namespace hwsec_foundation {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StrictMock;

class DAResetterTest : public ::testing::Test {
 public:
  DAResetterTest() {
    auto mock_proxy = std::make_unique<org::chromium::TpmManagerProxyMock>();
    mock_proxy_ = mock_proxy.get();
    resetter_ = std::make_unique<DAResetter>(
        std::unique_ptr<org::chromium::TpmManagerProxyInterface>(
            mock_proxy.release()));
  }
  ~DAResetterTest() override = default;

 protected:
  org::chromium::TpmManagerProxyMock* mock_proxy_ = nullptr;
  std::unique_ptr<DAResetter> resetter_;
};

TEST_F(DAResetterTest, Success) {
  tpm_manager::ResetDictionaryAttackLockReply reply;
  reply.set_status(tpm_manager::STATUS_SUCCESS);
  EXPECT_CALL(*mock_proxy_, ResetDictionaryAttackLock(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(reply), Return(true)));
  EXPECT_TRUE(resetter_->ResetDictionaryAttackLock());
}

TEST_F(DAResetterTest, Failure) {
  tpm_manager::ResetDictionaryAttackLockReply reply;
  reply.set_status(tpm_manager::STATUS_DEVICE_ERROR);
  EXPECT_CALL(*mock_proxy_, ResetDictionaryAttackLock(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(reply), Return(true)));
  EXPECT_FALSE(resetter_->ResetDictionaryAttackLock());
}

TEST_F(DAResetterTest, DBusError) {
  tpm_manager::ResetDictionaryAttackLockReply reply;
  reply.set_status(tpm_manager::STATUS_DEVICE_ERROR);
  auto fake_function =
      [](const tpm_manager::ResetDictionaryAttackLockRequest& /*request*/,
         tpm_manager::ResetDictionaryAttackLockReply* reply,
         brillo::ErrorPtr* error, int /*timeout_ms*/) -> bool {
    // We don't care about what are carried in the error.
    *error = brillo::Error::Create({}, {}, {}, {});
    return false;
  };
  EXPECT_CALL(*mock_proxy_, ResetDictionaryAttackLock(_, _, _, _))
      .WillOnce(fake_function);
  EXPECT_FALSE(resetter_->ResetDictionaryAttackLock());
}

}  // namespace hwsec_foundation
