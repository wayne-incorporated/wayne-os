// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <tuple>

#include "libec/ec_command.h"
#include "libec/flash_info_params.h"

bool operator==(const struct ec_flash_bank& lhs,
                const struct ec_flash_bank& rhs) {
  return std::tie(lhs.count, lhs.size_exp, lhs.write_size_exp,
                  lhs.erase_size_exp, lhs.protect_size_exp) ==
         std::tie(rhs.count, rhs.size_exp, rhs.write_size_exp,
                  rhs.erase_size_exp, rhs.protect_size_exp);
}
