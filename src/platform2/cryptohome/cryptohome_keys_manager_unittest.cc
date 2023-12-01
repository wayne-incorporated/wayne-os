// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/cryptohome_keys_manager.h"

#include <map>
#include <string>
#include <utility>
#include <vector>

#include <libhwsec/frontend/cryptohome/mock_frontend.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "cryptohome/mock_cryptohome_key_loader.h"
#include "cryptohome/mock_platform.h"

using ::hwsec_foundation::error::testing::ReturnValue;
using ::testing::_;
using ::testing::AtMost;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;

namespace cryptohome {

class CryptohomeKeysManagerTest : public ::testing::Test {
 public:
  CryptohomeKeysManagerTest() {}
  CryptohomeKeysManagerTest(const CryptohomeKeysManagerTest&) = delete;
  CryptohomeKeysManagerTest& operator=(const CryptohomeKeysManagerTest&) =
      delete;
  ~CryptohomeKeysManagerTest() override = default;

 protected:
  MockCryptohomeKeyLoader* AddMockLoader(CryptohomeKeyType type) {
    auto mock_loader = std::make_unique<MockCryptohomeKeyLoader>();
    MockCryptohomeKeyLoader* mock_loader_ptr = mock_loader.get();
    mock_loaders_.push_back(std::make_pair(type, std::move(mock_loader)));
    return mock_loader_ptr;
  }

  void InitKeysManager() {
    cryptohome_keys_manager_ = std::make_unique<CryptohomeKeysManager>(
        &hwsec_, std::move(mock_loaders_));
  }

 protected:
  hwsec::MockCryptohomeFrontend hwsec_;
  MockPlatform platform_;
  std::unique_ptr<CryptohomeKeysManager> cryptohome_keys_manager_;

 private:
  std::vector<
      std::pair<CryptohomeKeyType, std::unique_ptr<CryptohomeKeyLoader>>>
      mock_loaders_;
};

TEST_F(CryptohomeKeysManagerTest, Constructor) {
  EXPECT_CALL(hwsec_, GetSupportedAlgo())
      .WillOnce(ReturnValue(absl::flat_hash_set<hwsec::KeyAlgoType>(
          {hwsec::KeyAlgoType::kRsa, hwsec::KeyAlgoType::kEcc})));

  cryptohome_keys_manager_ =
      std::make_unique<CryptohomeKeysManager>(&hwsec_, &platform_);
}

TEST_F(CryptohomeKeysManagerTest, GetKeyLoaderSuccess) {
  MockCryptohomeKeyLoader* mock_rsa_loader =
      AddMockLoader(CryptohomeKeyType::kRSA);
  InitKeysManager();
  EXPECT_EQ(mock_rsa_loader,
            cryptohome_keys_manager_->GetKeyLoader(CryptohomeKeyType::kRSA));
}

TEST_F(CryptohomeKeysManagerTest, GetNoneExistKeyLoader) {
  InitKeysManager();
  EXPECT_EQ(nullptr,
            cryptohome_keys_manager_->GetKeyLoader(CryptohomeKeyType::kRSA));
  EXPECT_EQ(nullptr,
            cryptohome_keys_manager_->GetKeyLoader(CryptohomeKeyType::kECC));
}

TEST_F(CryptohomeKeysManagerTest, GetEccKeyLoaderSuccess) {
  MockCryptohomeKeyLoader* mock_rsa_loader =
      AddMockLoader(CryptohomeKeyType::kRSA);
  MockCryptohomeKeyLoader* mock_ecc_loader =
      AddMockLoader(CryptohomeKeyType::kECC);
  InitKeysManager();
  EXPECT_EQ(mock_rsa_loader,
            cryptohome_keys_manager_->GetKeyLoader(CryptohomeKeyType::kRSA));
  EXPECT_EQ(mock_ecc_loader,
            cryptohome_keys_manager_->GetKeyLoader(CryptohomeKeyType::kECC));
}

TEST_F(CryptohomeKeysManagerTest, GetEccKeyLoaderFail) {
  MockCryptohomeKeyLoader* mock_rsa_loader =
      AddMockLoader(CryptohomeKeyType::kRSA);
  InitKeysManager();
  EXPECT_EQ(mock_rsa_loader,
            cryptohome_keys_manager_->GetKeyLoader(CryptohomeKeyType::kRSA));
  EXPECT_EQ(nullptr,
            cryptohome_keys_manager_->GetKeyLoader(CryptohomeKeyType::kECC));
}

TEST_F(CryptohomeKeysManagerTest, Init) {
  MockCryptohomeKeyLoader* mock_rsa_loader =
      AddMockLoader(CryptohomeKeyType::kRSA);
  MockCryptohomeKeyLoader* mock_ecc_loader =
      AddMockLoader(CryptohomeKeyType::kECC);
  InitKeysManager();
  EXPECT_CALL(*mock_rsa_loader, Init()).Times(1);
  EXPECT_CALL(*mock_ecc_loader, Init()).Times(1);
  cryptohome_keys_manager_->Init();
}

TEST_F(CryptohomeKeysManagerTest, HasAnyCryptohomeKey) {
  MockCryptohomeKeyLoader* mock_rsa_loader =
      AddMockLoader(CryptohomeKeyType::kRSA);
  MockCryptohomeKeyLoader* mock_ecc_loader =
      AddMockLoader(CryptohomeKeyType::kECC);
  InitKeysManager();
  EXPECT_CALL(*mock_rsa_loader, HasCryptohomeKey())
      .Times(AtMost(1))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*mock_ecc_loader, HasCryptohomeKey())
      .Times(AtMost(1))
      .WillRepeatedly(Return(true));
  EXPECT_TRUE(cryptohome_keys_manager_->HasAnyCryptohomeKey());
}

TEST_F(CryptohomeKeysManagerTest, HasAnyCryptohomeKeyRsa) {
  MockCryptohomeKeyLoader* mock_rsa_loader =
      AddMockLoader(CryptohomeKeyType::kRSA);
  MockCryptohomeKeyLoader* mock_ecc_loader =
      AddMockLoader(CryptohomeKeyType::kECC);
  InitKeysManager();
  EXPECT_CALL(*mock_rsa_loader, HasCryptohomeKey())
      .Times(AtMost(1))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*mock_ecc_loader, HasCryptohomeKey())
      .Times(AtMost(1))
      .WillRepeatedly(Return(false));
  EXPECT_TRUE(cryptohome_keys_manager_->HasAnyCryptohomeKey());
}

TEST_F(CryptohomeKeysManagerTest, HasAnyCryptohomeKeyEcc) {
  MockCryptohomeKeyLoader* mock_rsa_loader =
      AddMockLoader(CryptohomeKeyType::kRSA);
  MockCryptohomeKeyLoader* mock_ecc_loader =
      AddMockLoader(CryptohomeKeyType::kECC);
  InitKeysManager();
  EXPECT_CALL(*mock_rsa_loader, HasCryptohomeKey())
      .Times(AtMost(1))
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*mock_ecc_loader, HasCryptohomeKey())
      .Times(AtMost(1))
      .WillRepeatedly(Return(true));
  EXPECT_TRUE(cryptohome_keys_manager_->HasAnyCryptohomeKey());
}

TEST_F(CryptohomeKeysManagerTest, HasAnyCryptohomeKeyNoKey) {
  MockCryptohomeKeyLoader* mock_rsa_loader =
      AddMockLoader(CryptohomeKeyType::kRSA);
  MockCryptohomeKeyLoader* mock_ecc_loader =
      AddMockLoader(CryptohomeKeyType::kECC);
  InitKeysManager();
  EXPECT_CALL(*mock_rsa_loader, HasCryptohomeKey())
      .Times(AtMost(1))
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*mock_ecc_loader, HasCryptohomeKey())
      .Times(AtMost(1))
      .WillRepeatedly(Return(false));
  EXPECT_FALSE(cryptohome_keys_manager_->HasAnyCryptohomeKey());
}

TEST_F(CryptohomeKeysManagerTest, HasCryptohomeKey) {
  MockCryptohomeKeyLoader* mock_rsa_loader =
      AddMockLoader(CryptohomeKeyType::kRSA);
  MockCryptohomeKeyLoader* mock_ecc_loader =
      AddMockLoader(CryptohomeKeyType::kECC);
  InitKeysManager();
  EXPECT_CALL(*mock_rsa_loader, HasCryptohomeKey()).Times(0);
  EXPECT_CALL(*mock_ecc_loader, HasCryptohomeKey())
      .Times(AtMost(1))
      .WillRepeatedly(Return(true));
  EXPECT_TRUE(
      cryptohome_keys_manager_->HasCryptohomeKey(CryptohomeKeyType::kECC));
}

TEST_F(CryptohomeKeysManagerTest, HasCryptohomeKeyNoKey) {
  MockCryptohomeKeyLoader* mock_rsa_loader =
      AddMockLoader(CryptohomeKeyType::kRSA);
  InitKeysManager();
  EXPECT_CALL(*mock_rsa_loader, HasCryptohomeKey()).Times(0);
  EXPECT_FALSE(
      cryptohome_keys_manager_->HasCryptohomeKey(CryptohomeKeyType::kECC));
}
}  // namespace cryptohome
