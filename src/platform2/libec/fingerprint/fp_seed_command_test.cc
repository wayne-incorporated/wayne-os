// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/fingerprint/fp_seed_command.h"

namespace ec {
namespace {

/**
 * The file descriptor isn't used by anything, so we set it to an invalid so
 * we set it to an invalid value.
 */
constexpr int kTestFd = -1;

TEST(FpSeedCommand, Create_Success) {
  const brillo::SecureVector kSeed = {
      1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
      17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
  constexpr uint16_t kSeedVersion = 1;
  auto cmd = FpSeedCommand::Create(kSeed, kSeedVersion);
  EXPECT_TRUE(cmd);
  EXPECT_EQ(cmd->Version(), 0);
  EXPECT_EQ(cmd->Command(), EC_CMD_FP_SEED);

  EXPECT_EQ(cmd->seed(), kSeed);
  EXPECT_EQ(cmd->seed_version(), kSeedVersion);
}

TEST(FpSeedCommand, Create_InvalidSeedSize_TooSmall) {
  const brillo::SecureVector kSeed = {1, 2, 3};
  constexpr uint16_t kSeedVersion = 1;
  auto cmd = FpSeedCommand::Create(kSeed, kSeedVersion);
  EXPECT_FALSE(cmd);
}

TEST(FpSeedCommand, Create_InvalidSeedSize_TooLarge) {
  const brillo::SecureVector kSeed(256);
  constexpr uint16_t kSeedVersion = 1;
  auto cmd = FpSeedCommand::Create(kSeed, kSeedVersion);
  EXPECT_FALSE(cmd);
}

TEST(FpSeedCommand, DestructorClearsBuffer) {
  const brillo::SecureVector kSeed(FpSeedCommand::kTpmSeedSize, 0xFF);
  constexpr uint16_t kSeedVersion = 1;
  std::unique_ptr<FpSeedCommand> cmd =
      FpSeedCommand::Create(kSeed, kSeedVersion);
  EXPECT_TRUE(cmd);

  // Seed set in FpSeedCommand should be non-zero.
  EXPECT_EQ(cmd->seed(), kSeed);

  // Call destructor without deleting (freeing memory for) object.
  // Note that the destructor will still be called when the std::unique_ptr
  // is destructed, so it will be called twice in this test.
  cmd->~FpSeedCommand();

  // After FpSeedCommand destructor is called we expect the seed to have been
  // cleared.
  EXPECT_EQ(cmd->seed(), brillo::SecureVector(FpSeedCommand::kTpmSeedSize, 0));
}

// Mock the underlying EcCommand to test
class FpSeedCommandTest : public testing::Test {
 public:
  class MockFpSeedCommand : public FpSeedCommand {
   public:
    MOCK_METHOD(bool, EcCommandRun, (int fd), (override));
  };
};

TEST_F(FpSeedCommandTest, CheckClearsIntermediateBuffers) {
  const brillo::SecureVector kSeed(FpSeedCommand::kTpmSeedSize, 1);
  constexpr uint16_t kSeedVersion = 1;

  auto cmd = FpSeedCommand::Create<MockFpSeedCommand>(kSeed, kSeedVersion);

  EXPECT_CALL(*cmd, EcCommandRun)
      // First call should be setting the seed we requested.
      .WillOnce([&cmd, &kSeed](int fd) {
        EXPECT_EQ(cmd->seed(), kSeed);
        return true;
      })
      // Second call should be setting a seed full of zeroes.
      .WillOnce([&cmd](int fd) {
        const brillo::SecureVector kZeroSeed(FpSeedCommand::kTpmSeedSize, 0);
        EXPECT_EQ(cmd->seed(), kZeroSeed);
        // The FPMCU will reject this command since seed is already set, so
        // we emulate the same behavior here.
        return false;
      });

  bool ret = cmd->Run(kTestFd);
  EXPECT_TRUE(ret);
}

}  // namespace
}  // namespace ec
