// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libcrossystem/crossystem.h"
#include "libcrossystem/crossystem_fake.h"

namespace crossystem {
namespace {

using ::testing::Return;

constexpr char kCheckFailedRegex[] = "Check failed.*";

class CrossystemTest : public ::testing::Test {
 protected:
  void SetUp() override {
    auto fake = std::make_unique<fake::CrossystemFake>();
    fake_ = fake.get();
    crossystem_ = std::make_unique<Crossystem>(std::move(fake));
  }

  std::unique_ptr<Crossystem> crossystem_;
  fake::CrossystemFake* fake_;
};

TEST_F(CrossystemTest, GetBooleanPropertyTrue) {
  fake_->VbSetSystemPropertyInt("fake", 1);
  EXPECT_EQ(crossystem_->GetSystemPropertyBool("fake"),
            std::make_optional(true));
}

TEST_F(CrossystemTest, GetBooleanPropertyFalse) {
  fake_->VbSetSystemPropertyInt("fake", 0);
  EXPECT_EQ(crossystem_->GetSystemPropertyBool("fake"),
            std::make_optional(false));
}

TEST_F(CrossystemTest, GetBooleanPropertyDoesNotExist) {
  EXPECT_EQ(crossystem_->GetSystemPropertyBool("fake"), std::nullopt);
}

TEST_F(CrossystemTest, GetBooleanPropertyNegative) {
  fake_->VbSetSystemPropertyInt("fake", -1);
  EXPECT_DEATH(crossystem_->GetSystemPropertyBool("fake"), kCheckFailedRegex);
}

TEST_F(CrossystemTest, SetBooleanPropertyTrueSucceeds) {
  EXPECT_TRUE(crossystem_->SetSystemPropertyBool("fake", true));
  EXPECT_EQ(fake_->VbGetSystemPropertyInt("fake"), 1);
}

TEST_F(CrossystemTest, SetBooleanPropertyTrueFails) {
  fake_->SetSystemPropertyReadOnlyStatus("fake", true);
  EXPECT_FALSE(crossystem_->SetSystemPropertyBool("fake", true));
}

TEST_F(CrossystemTest, SetBooleanPropertyFalseSucceeds) {
  EXPECT_TRUE(crossystem_->SetSystemPropertyBool("fake", false));
  EXPECT_EQ(fake_->VbGetSystemPropertyInt("fake"), 0);
}

TEST_F(CrossystemTest, SetBooleanPropertyFalseFails) {
  fake_->SetSystemPropertyReadOnlyStatus("fake", true);
  EXPECT_FALSE(crossystem_->SetSystemPropertyBool("fake", false));
}

TEST_F(CrossystemTest, IsHardwareWriteProtectEnabledTrue) {
  fake_->VbSetSystemPropertyInt(Crossystem::kHardwareWriteProtect, 1);
  EXPECT_TRUE(crossystem_->HardwareWriteProtectIsEnabled());
}

TEST_F(CrossystemTest, IsHardwareWriteProtectEnabledFalse) {
  fake_->VbSetSystemPropertyInt(Crossystem::kHardwareWriteProtect, 0);
  EXPECT_FALSE(crossystem_->HardwareWriteProtectIsEnabled());
}

TEST_F(CrossystemTest, IsHardwareWriteProtectEnabledNotBoolean) {
  fake_->VbSetSystemPropertyInt(Crossystem::kHardwareWriteProtect, -1);
  EXPECT_DEATH(crossystem_->HardwareWriteProtectIsEnabled(), kCheckFailedRegex);
}

TEST_F(CrossystemTest, IsHardwareWriteProtectEnabledPropertyDoesNotExist) {
  EXPECT_DEATH(crossystem_->HardwareWriteProtectIsEnabled(), kCheckFailedRegex);
}

TEST_F(CrossystemTest, GetHardwareID) {
  fake_->VbSetSystemPropertyString(Crossystem::kHardwareId, "abc123");
  EXPECT_EQ(crossystem_->GetHardwareID(), "abc123");
}

TEST_F(CrossystemTest, GetHardwareIDNotSet) {
  EXPECT_DEATH(crossystem_->GetHardwareID(), kCheckFailedRegex);
}

TEST_F(CrossystemTest, OnlyBootSignedKernelTrue) {
  fake_->VbSetSystemPropertyInt(Crossystem::kDevBootSignedOnly, 1);
  EXPECT_TRUE(crossystem_->OnlyBootSignedKernel());
}

TEST_F(CrossystemTest, OnlyBootSignedKernelFalse) {
  fake_->VbSetSystemPropertyInt(Crossystem::kDevBootSignedOnly, 0);
  EXPECT_FALSE(crossystem_->OnlyBootSignedKernel());
}

TEST_F(CrossystemTest, OnlyBootSignedKernelNotBoolean) {
  fake_->VbSetSystemPropertyInt(Crossystem::kDevBootSignedOnly, -1);
  EXPECT_DEATH(crossystem_->OnlyBootSignedKernel(), kCheckFailedRegex);
}

TEST_F(CrossystemTest, OnlyBootSignedKernelPropertyDoesNotExist) {
  EXPECT_DEATH(crossystem_->OnlyBootSignedKernel(), kCheckFailedRegex);
}

}  // namespace
}  // namespace crossystem
