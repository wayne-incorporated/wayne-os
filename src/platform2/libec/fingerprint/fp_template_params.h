// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_FINGERPRINT_FP_TEMPLATE_PARAMS_H_
#define LIBEC_FINGERPRINT_FP_TEMPLATE_PARAMS_H_

#include <array>

#include "libec/ec_command.h"

namespace ec {
namespace fp_template {

// We cannot use "struct ec_params_fp_template" directly in the
// FpTemplateCommand class because the "data" member is a variable length array.
// "Header" includes everything from that struct except "data". A test validates
// that the size of the two structs is the same to avoid any divergence.
struct Header {
  uint32_t offset = 0;
  uint32_t size = 0;
};

struct Params {
  struct Header req;
  ArrayData<uint8_t, struct Header> data{};
};

}  // namespace fp_template
}  // namespace ec

#endif  // LIBEC_FINGERPRINT_FP_TEMPLATE_PARAMS_H_
