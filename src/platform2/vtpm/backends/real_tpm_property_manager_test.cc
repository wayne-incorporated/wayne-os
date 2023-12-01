// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/backends/real_tpm_property_manager.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace vtpm {

namespace {

using ::testing::ElementsAre;

constexpr trunks::TPM_CC kFakeCC1 = 1;
constexpr trunks::TPM_CC kFakeCC2 = 2;
constexpr trunks::TPM_CC kFakeCC3 = 3;

}  // namespace

class RealTpmPropertyManagerTest : public testing::Test {
 protected:
  RealTpmPropertyManager tpm_property_manager_;
};

namespace {

TEST_F(RealTpmPropertyManagerTest, CommandList) {
  EXPECT_TRUE(tpm_property_manager_.GetCommandList().empty());
  // Add the commands in decreasing order.
  tpm_property_manager_.AddCommand(kFakeCC3);
  tpm_property_manager_.AddCommand(kFakeCC2);
  tpm_property_manager_.AddCommand(kFakeCC1);

  // Add duplicates.
  tpm_property_manager_.AddCommand(kFakeCC1);
  tpm_property_manager_.AddCommand(kFakeCC2);
  tpm_property_manager_.AddCommand(kFakeCC2);
  tpm_property_manager_.AddCommand(kFakeCC3);

  EXPECT_THAT(tpm_property_manager_.GetCommandList(),
              ElementsAre(kFakeCC1, kFakeCC2, kFakeCC3));
}

TEST_F(RealTpmPropertyManagerTest, CapabilityPropertyListUpdateTotalCommands) {
  const std::vector<trunks::TPMS_TAGGED_PROPERTY>& props =
      tpm_property_manager_.GetCapabilityPropertyList();

  auto total_commands_iter = std::lower_bound(
      props.begin(), props.end(),
      trunks::TPMS_TAGGED_PROPERTY{trunks::TPM_PT_TOTAL_COMMANDS, 0},
      [](const trunks::TPMS_TAGGED_PROPERTY& a,
         const trunks::TPMS_TAGGED_PROPERTY& b) -> bool {
        return a.property < b.property;
      });
  EXPECT_EQ(total_commands_iter->value, 0);
  tpm_property_manager_.AddCommand(kFakeCC1);
  tpm_property_manager_.GetCapabilityPropertyList();
  total_commands_iter = std::lower_bound(
      props.begin(), props.end(),
      trunks::TPMS_TAGGED_PROPERTY{trunks::TPM_PT_TOTAL_COMMANDS, 0},
      [](const trunks::TPMS_TAGGED_PROPERTY& a,
         const trunks::TPMS_TAGGED_PROPERTY& b) -> bool {
        return a.property < b.property;
      });
  EXPECT_EQ(total_commands_iter->value, 1);
  tpm_property_manager_.AddCommand(kFakeCC2);
  tpm_property_manager_.AddCommand(kFakeCC3);
  tpm_property_manager_.GetCapabilityPropertyList();
  total_commands_iter = std::lower_bound(
      props.begin(), props.end(),
      trunks::TPMS_TAGGED_PROPERTY{trunks::TPM_PT_TOTAL_COMMANDS, 0},
      [](const trunks::TPMS_TAGGED_PROPERTY& a,
         const trunks::TPMS_TAGGED_PROPERTY& b) -> bool {
        return a.property < b.property;
      });
  EXPECT_EQ(total_commands_iter->value, 3);
}

}  // namespace

}  // namespace vtpm
