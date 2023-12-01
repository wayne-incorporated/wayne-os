// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "libec/ec_command.h"
#include "libec/flash_info_params.h"

namespace ec {
namespace {

TEST(FlashInfoParams, ValidateSize) {
  EXPECT_EQ(flash_info::Params_v2().banks.size(), 66);
}

TEST(FlashInfoParams, FlashBankEqual) {
  struct ec_flash_bank expected_bank0 = {.count = 1,
                                         .size_exp = 2,
                                         .write_size_exp = 3,
                                         .erase_size_exp = 4,
                                         .protect_size_exp = 5};
  struct ec_flash_bank expected_bank1 = {.count = 1,
                                         .size_exp = 2,
                                         .write_size_exp = 3,
                                         .erase_size_exp = 4,
                                         .protect_size_exp = 5};
  EXPECT_EQ(expected_bank0, expected_bank1);
}

TEST(FlashInfoParams, FlashBankNotEqual) {
  struct ec_flash_bank expected_bank0 = {.count = 1,
                                         .size_exp = 2,
                                         .write_size_exp = 3,
                                         .erase_size_exp = 4,
                                         .protect_size_exp = 5};
  struct ec_flash_bank expected_bank1 = {.count = 0,
                                         .size_exp = 2,
                                         .write_size_exp = 3,
                                         .erase_size_exp = 4,
                                         .protect_size_exp = 5};
  EXPECT_FALSE(expected_bank0 == expected_bank1);
}

}  // namespace
}  // namespace ec
