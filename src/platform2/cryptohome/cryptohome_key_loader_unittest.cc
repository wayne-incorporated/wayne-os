// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/cryptohome_key_loader.h"

#include <map>
#include <string>

#include <base/files/file_path.h>
#include <brillo/secure_blob.h>
#include <libhwsec/frontend/cryptohome/mock_frontend.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "cryptohome/mock_platform.h"

using ::hwsec::TPMError;
using ::hwsec::TPMRetryAction;
using ::hwsec_foundation::error::testing::ReturnError;
using ::hwsec_foundation::error::testing::ReturnValue;
using ::testing::_;
using ::testing::ByMove;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;

namespace cryptohome {

constexpr char kDefaultCryptohomeKeyFile[] = "/home/.shadow/cryptohome.key";
constexpr hwsec::KeyToken kTestKeyToken = 17;
constexpr hwsec::KeyAlgoType kTestKeyAlgo = hwsec::KeyAlgoType::kRsa;

// Tests that need to do more setup work before calling Service::Initialize can
// use this instead of ServiceTest.
class CryptohomeKeyLoaderTest : public ::testing::Test {
 public:
  CryptohomeKeyLoaderTest()
      : cryptohome_key_loader_(&hwsec_,
                               &platform_,
                               kTestKeyAlgo,
                               base::FilePath(kDefaultCryptohomeKeyFile)) {}
  CryptohomeKeyLoaderTest(const CryptohomeKeyLoaderTest&) = delete;
  CryptohomeKeyLoaderTest& operator=(const CryptohomeKeyLoaderTest&) = delete;

  virtual ~CryptohomeKeyLoaderTest() = default;

  // Default mock implementations for |tpm_| methods.
  // For TPM-related flags: enabled is always true, other flags are settable.
  bool IsReady() const { return is_hwsec_ready_; }
  void SetIsReady(bool is_hwsec_ready) { is_hwsec_ready_ = is_hwsec_ready; }
  void SetUp() override {
    ON_CALL(hwsec_, IsEnabled()).WillByDefault(ReturnValue(true));
    ON_CALL(hwsec_, IsReady()).WillByDefault([this]() { return IsReady(); });
  }

  void TearDown() override {}

  Platform* GetPlatform() { return &platform_; }

 protected:
  brillo::Blob kTestKeyBlob = brillo::BlobFromString("test_key_blob");
  brillo::Blob kTestKeyBlob2 = brillo::BlobFromString("test_key_blob2");

  hwsec::ScopedKey GetTestScopedKey() {
    return hwsec::ScopedKey(hwsec::Key{.token = 17},
                            hwsec_.GetFakeMiddlewareDerivative());
  }

  bool HasStoredCryptohomeKey(brillo::Blob blob) {
    brillo::Blob stored_blob;
    if (!platform_.ReadFile(base::FilePath(kDefaultCryptohomeKeyFile),
                            &stored_blob)) {
      return false;
    }
    if (stored_blob != blob) {
      return false;
    }
    return true;
  }

  bool HasLoadedCryptohomeKey(hwsec::KeyToken token) {
    if (!cryptohome_key_loader_.HasCryptohomeKey()) {
      return false;
    }
    hwsec::Key key = cryptohome_key_loader_.GetCryptohomeKey();
    if (key.token != token) {
      return false;
    }
    return true;
  }

  bool is_hwsec_ready_ = false;
  std::map<base::FilePath, brillo::Blob> files_;
  NiceMock<hwsec::MockCryptohomeFrontend> hwsec_;
  NiceMock<MockPlatform> platform_;

  // Declare cryptohome_key_loader_ last, so it gets destroyed before all the
  // mocks.
  CryptohomeKeyLoader cryptohome_key_loader_;
};

ACTION_P(GenerateWrappedKey, wrapped_key) {
  *arg0 = brillo::SecureBlob(wrapped_key);
  return true;
}

ACTION_P2(LoadWrappedKeyToHandle, tpm, handle) {
  arg1->reset(tpm, handle);
  return nullptr;
}

TEST_F(CryptohomeKeyLoaderTest, LoadCryptohomeKeySuccess) {
  SetIsReady(true);
  platform_.WriteFile(base::FilePath(kDefaultCryptohomeKeyFile), kTestKeyBlob);
  EXPECT_CALL(hwsec_, LoadKey(kTestKeyBlob))
      .WillOnce(Return(ByMove(GetTestScopedKey())));
  cryptohome_key_loader_.Init();
  EXPECT_TRUE(HasLoadedCryptohomeKey(kTestKeyToken));
}

TEST_F(CryptohomeKeyLoaderTest, LoadCryptohomeKeyNotOwned) {
  SetIsReady(false);
  platform_.WriteFile(base::FilePath(kDefaultCryptohomeKeyFile), kTestKeyBlob);
  EXPECT_CALL(hwsec_, LoadKey(_)).Times(0);
  EXPECT_CALL(hwsec_, CreateCryptohomeKey(_)).Times(0);
  cryptohome_key_loader_.Init();
  EXPECT_FALSE(cryptohome_key_loader_.HasCryptohomeKey());
}

TEST_F(CryptohomeKeyLoaderTest, ReCreateCryptohomeKeyAfterLoadFailure) {
  // Permanent failure while loading the key leads to re-creating, storing
  // and loading the new key.
  SetIsReady(true);
  platform_.WriteFile(base::FilePath(kDefaultCryptohomeKeyFile), kTestKeyBlob);
  EXPECT_CALL(hwsec_, LoadKey(kTestKeyBlob))
      .WillOnce(ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));
  EXPECT_CALL(hwsec_, CreateCryptohomeKey(kTestKeyAlgo))
      .WillOnce(Return(ByMove(hwsec::CryptohomeFrontend::CreateKeyResult{
          .key = GetTestScopedKey(),
          .key_blob = kTestKeyBlob2,
      })));
  cryptohome_key_loader_.Init();
  EXPECT_TRUE(HasLoadedCryptohomeKey(kTestKeyToken));
  EXPECT_TRUE(HasStoredCryptohomeKey(kTestKeyBlob2));
}

TEST_F(CryptohomeKeyLoaderTest, ReCreateCryptohomeKeyFailureDuringKeyCreation) {
  // Permanent failure while loading the key leads to an attempt to re-create
  // the key. Which fails. So, nothing new is stored or loaded.
  SetIsReady(true);
  platform_.WriteFile(base::FilePath(kDefaultCryptohomeKeyFile), kTestKeyBlob);
  EXPECT_CALL(hwsec_, LoadKey(kTestKeyBlob))
      .WillOnce(ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));
  EXPECT_CALL(hwsec_, CreateCryptohomeKey(kTestKeyAlgo))
      .WillOnce(ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));
  cryptohome_key_loader_.Init();
  EXPECT_TRUE(HasStoredCryptohomeKey(kTestKeyBlob));
}

}  // namespace cryptohome
