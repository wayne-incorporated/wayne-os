// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/stl_util.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libec/ec_command.h"
#include "libec/flash_protect_command.h"

namespace ec {
namespace {

using ::testing::StrEq;

TEST(FlashProtectCommand_v1, FlashProtectCommand_v1) {
  flash_protect::Flags flags =
      flash_protect::Flags::kRollbackAtBoot | flash_protect::Flags::kRoAtBoot;
  flash_protect::Flags mask = flash_protect::Flags::kNone;
  FlashProtectCommand_v1 cmd(flags, mask);
  EXPECT_EQ(cmd.Version(), EC_VER_FLASH_PROTECT);
  EXPECT_EQ(cmd.Command(), EC_CMD_FLASH_PROTECT);
  EXPECT_EQ(cmd.Req()->flags, base::to_underlying(flags));
  EXPECT_EQ(cmd.Req()->mask, base::to_underlying(mask));
}

TEST(FlashProtectCommand, ParseFlags) {
  std::string result;

  // test each flag string individually
  flash_protect::Flags flags = flash_protect::Flags::kNone;
  result = FlashProtectCommand::ParseFlags(flags);
  EXPECT_THAT(result, StrEq(""));

  flags = flash_protect::Flags::kRoAtBoot;
  result = FlashProtectCommand::ParseFlags(flags);
  EXPECT_THAT(result, StrEq(" ro_at_boot"));

  flags = flash_protect::Flags::kRoNow;
  result = FlashProtectCommand::ParseFlags(flags);
  EXPECT_THAT(result, StrEq(" ro_now"));

  flags = flash_protect::Flags::kAllNow;
  result = FlashProtectCommand::ParseFlags(flags);
  EXPECT_THAT(result, StrEq(" all_now"));

  flags = flash_protect::Flags::kGpioAsserted;
  result = FlashProtectCommand::ParseFlags(flags);
  EXPECT_THAT(result, StrEq(" wp_gpio_asserted"));

  flags = flash_protect::Flags::kErrorStuck;
  result = FlashProtectCommand::ParseFlags(flags);
  EXPECT_THAT(result, StrEq(" STUCK"));

  flags = flash_protect::Flags::kErrorInconsistent;
  result = FlashProtectCommand::ParseFlags(flags);
  EXPECT_THAT(result, StrEq(" INCONSISTENT"));

  flags = flash_protect::Flags::kAllAtBoot;
  result = FlashProtectCommand::ParseFlags(flags);
  EXPECT_THAT(result, StrEq(" all_at_boot"));

  flags = flash_protect::Flags::kRwAtBoot;
  result = FlashProtectCommand::ParseFlags(flags);
  EXPECT_THAT(result, StrEq(" rw_at_boot"));

  flags = flash_protect::Flags::kRwNow;
  result = FlashProtectCommand::ParseFlags(flags);
  EXPECT_THAT(result, StrEq(" rw_now"));

  flags = flash_protect::Flags::kRollbackAtBoot;
  result = FlashProtectCommand::ParseFlags(flags);
  EXPECT_THAT(result, StrEq(" rollback_at_boot"));

  flags = flash_protect::Flags::kRollbackNow;
  result = FlashProtectCommand::ParseFlags(flags);
  EXPECT_THAT(result, StrEq(" rollback_now"));

  flags = flash_protect::Flags::kErrorUnknown;
  result = FlashProtectCommand::ParseFlags(flags);
  EXPECT_THAT(result, StrEq(" UNKNOWN_ERROR"));

  // test a combination of flags
  flags = flash_protect::Flags::kRoAtBoot | flash_protect::Flags::kRoNow |
          flash_protect::Flags::kGpioAsserted;
  result = FlashProtectCommand::ParseFlags(flags);
  EXPECT_THAT(result, StrEq(" wp_gpio_asserted ro_at_boot ro_now"));
}

TEST(FlashProtectCommand_v1, Enum) {
  EXPECT_EQ(base::to_underlying(flash_protect::Flags::kNone), 0);
  EXPECT_EQ(base::to_underlying(flash_protect::Flags::kRoAtBoot), 1);
  EXPECT_EQ(base::to_underlying(flash_protect::Flags::kRoNow), 2);
  EXPECT_EQ(base::to_underlying(flash_protect::Flags::kAllNow), 4);
  EXPECT_EQ(base::to_underlying(flash_protect::Flags::kGpioAsserted), 8);
  EXPECT_EQ(base::to_underlying(flash_protect::Flags::kErrorStuck), 16);
  EXPECT_EQ(base::to_underlying(flash_protect::Flags::kErrorInconsistent), 32);
  EXPECT_EQ(base::to_underlying(flash_protect::Flags::kAllAtBoot), 64);
  EXPECT_EQ(base::to_underlying(flash_protect::Flags::kRwAtBoot), 128);
  EXPECT_EQ(base::to_underlying(flash_protect::Flags::kRwNow), 256);
  EXPECT_EQ(base::to_underlying(flash_protect::Flags::kRollbackAtBoot), 512);
  EXPECT_EQ(base::to_underlying(flash_protect::Flags::kRollbackNow), 1024);
}

TEST(FlashProtect, OverloadedStreamOperator) {
  std::stringstream stream;
  stream << flash_protect::Flags::kRoAtBoot;
  EXPECT_EQ(stream.str(), "1");
}

TEST(FlashProtectCommand_v2, FlashProtectCommand_v2) {
  flash_protect::Flags flags =
      flash_protect::Flags::kRollbackAtBoot | flash_protect::Flags::kRoAtBoot;
  flash_protect::Flags mask = flash_protect::Flags::kNone;
  FlashProtectCommand_v2 cmd(flags, mask);
  EXPECT_EQ(cmd.Version(), 2);
  EXPECT_EQ(cmd.Command(), EC_CMD_FLASH_PROTECT);
  EXPECT_EQ(cmd.Req()->action, FLASH_PROTECT_ASYNC);
  EXPECT_EQ(cmd.options().poll_for_result_num_attempts, 20);
  EXPECT_EQ(cmd.options().poll_interval, base::Milliseconds(100));
  EXPECT_EQ(cmd.options().validate_poll_result, false);
}

TEST(FlashProtectCommand, FlashProtectCommand_v1) {
  flash_protect::Flags flags =
      flash_protect::Flags::kRollbackAtBoot | flash_protect::Flags::kRoAtBoot;
  flash_protect::Flags mask = flash_protect::Flags::kNone;
  uint32_t version = 1;
  FlashProtectCommand cmd(flags, mask, version);
  EXPECT_EQ(cmd.Version(), 1);
  EXPECT_EQ(cmd.Command(), EC_CMD_FLASH_PROTECT);
}

TEST(FlashProtectCommand, FlashProtectCommand_v2) {
  flash_protect::Flags flags =
      flash_protect::Flags::kRollbackAtBoot | flash_protect::Flags::kRoAtBoot;
  flash_protect::Flags mask = flash_protect::Flags::kNone;
  uint32_t version = 2;
  FlashProtectCommand cmd(flags, mask, version);
  EXPECT_EQ(cmd.Version(), 2);
  EXPECT_EQ(cmd.Command(), EC_CMD_FLASH_PROTECT);
}

}  // namespace
}  // namespace ec
