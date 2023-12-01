// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_FLASH_INFO_PARAMS_H_
#define LIBEC_FLASH_INFO_PARAMS_H_

#include <array>

#include "libec/ec_command.h"

namespace ec::flash_info {

// Allocates space for the flash bank response.
struct Params_v2 {
  struct ec_response_flash_info_2 info {};
  ArrayData<struct ec_flash_bank, struct ec_response_flash_info_2> banks{};
};

}  // namespace ec::flash_info

bool operator==(const struct ec_flash_bank& lhs,
                const struct ec_flash_bank& rhs);

#endif  // LIBEC_FLASH_INFO_PARAMS_H_
