// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_RAND_NUM_PARAMS_H_
#define LIBEC_RAND_NUM_PARAMS_H_

#include <array>

#include "libec/ec_command.h"

namespace ec::rand {

// We cannot use "ec_response_rand_num" directly in the RandCommand class
// because the "rand" member is a variable length array.
using RandNumData = ArrayData<uint8_t>;

struct RandNumResp {
  RandNumData rand_num_data{};
};

}  // namespace ec::rand

#endif  // LIBEC_RAND_NUM_PARAMS_H_
