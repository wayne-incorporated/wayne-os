// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "biod/crypto_init/bio_crypto_init.h"

#include <memory>

#include "biod/crypto_init/mock_bio_crypto_init.h"
#include <libec/mock_ec_command_factory.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace biod {

using ec::FpSeedCommand;
using ::testing::Return;

TEST(BioCryptoInit, CheckTemplateVersionCompatible) {
  BioCryptoInit bio_crypto_init(std::make_unique<ec::EcCommandFactory>());
  EXPECT_TRUE(bio_crypto_init.CrosFpTemplateVersionCompatible(3, 3));
  EXPECT_TRUE(bio_crypto_init.CrosFpTemplateVersionCompatible(4, 4));
  // Format version 2 should not be in the field.
  EXPECT_FALSE(bio_crypto_init.CrosFpTemplateVersionCompatible(2, 2));

  // This should change when we deprecate firmware with template format v3
  EXPECT_TRUE(bio_crypto_init.CrosFpTemplateVersionCompatible(3, 4));

  // These are false because of the current rule and should change when we
  // launch format version 5.
  EXPECT_FALSE(bio_crypto_init.CrosFpTemplateVersionCompatible(4, 5));
  EXPECT_FALSE(bio_crypto_init.CrosFpTemplateVersionCompatible(5, 5));

  // This should break and be fixed when we uprev format version to 5 so that
  // we are guarding against unplanned uprev.
  EXPECT_TRUE(bio_crypto_init.CrosFpTemplateVersionCompatible(
      4, FP_TEMPLATE_FORMAT_VERSION));
}

class BioCryptoInitTest : public testing::Test {
 public:
  class MockFpSeedCommand : public FpSeedCommand {
   public:
    MOCK_METHOD(bool, Run, (int fd), (override));
  };

  BioCryptoInitTest() {
    auto mock_command_factory = std::make_unique<ec::MockEcCommandFactory>();
    mock_ec_command_factory_ = mock_command_factory.get();
    mock_bio_crypto_init_ =
        std::make_unique<MockBioCryptoInit>(std::move(mock_command_factory));
  }

 protected:
  ec::MockEcCommandFactory* mock_ec_command_factory_ = nullptr;
  std::unique_ptr<MockBioCryptoInit> mock_bio_crypto_init_;
};

TEST_F(BioCryptoInitTest, WriteSeedToCrosFp) {
  EXPECT_CALL(*mock_bio_crypto_init_, InitCrosFp).WillOnce(Return(true));
  EXPECT_CALL(*mock_bio_crypto_init_, GetFirmwareTemplateVersion)
      .WillOnce(Return(3));

  const brillo::SecureVector kSeed(FpSeedCommand::kTpmSeedSize, 0xFF);

  // Verify that the seed passed to WriteSeedToCrosFp matches and that the
  // command to set the seed is run.
  EXPECT_CALL(*mock_ec_command_factory_, FpSeedCommand)
      .WillOnce(
          [&kSeed](const brillo::SecureVector& seed, uint16_t seed_version) {
            EXPECT_EQ(seed, kSeed);
            auto mock_cmd =
                FpSeedCommand::Create<MockFpSeedCommand>(seed, seed_version);
            EXPECT_CALL(*mock_cmd, Run).WillOnce(Return(true));
            return mock_cmd;
          });

  mock_bio_crypto_init_->WriteSeedToCrosFpDelegate(kSeed);
}
}  // namespace biod
