// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_TPM_ERROR_TPM_ERROR_CONSTANTS_H_
#define LIBHWSEC_FOUNDATION_TPM_ERROR_TPM_ERROR_CONSTANTS_H_

#include <stdint.h>

namespace hwsec_foundation {

// The value of `TPM_E_AUTHFAIL`, per TPM1.2 spec.
constexpr uint32_t kTpm1AuthFailResponse = 1;
// The value of `TPM_E_AUTHF2AIL`, per TPM1.2 spec.
constexpr uint32_t kTpm1Auth2FailResponse = 29;

}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_TPM_ERROR_TPM_ERROR_CONSTANTS_H_
