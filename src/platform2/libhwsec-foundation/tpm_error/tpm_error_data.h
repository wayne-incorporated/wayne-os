// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_TPM_ERROR_TPM_ERROR_DATA_H_
#define LIBHWSEC_FOUNDATION_TPM_ERROR_TPM_ERROR_DATA_H_

#include <stdint.h>

#if defined(__cplusplus)
#include <type_traits>
#include <vector>

#include "libhwsec-foundation/hwsec-foundation_export.h"
#endif

#if defined(__cplusplus)
extern "C" {
#endif

// The data that describes a TPM command and the response.
struct TpmErrorData {
  uint32_t command;
  uint32_t response;
};

// It has to be POD so it's C-compatible.
#if defined(__cplusplus)
static_assert(std::is_trivial<TpmErrorData>::value);
static_assert(std::is_standard_layout<TpmErrorData>::value);
#endif

#if defined(__cplusplus)
}
#endif

#if defined(__cplusplus)
HWSEC_FOUNDATION_EXPORT bool operator==(const struct TpmErrorData& a,
                                        const struct TpmErrorData& b);
HWSEC_FOUNDATION_EXPORT bool operator<(const struct TpmErrorData& a,
                                       const struct TpmErrorData& b);

// Get SHA256 value from vector of TpmErrorData.
uint32_t GetHashFromTpmDataSet(
    const std::vector<struct TpmErrorData>& data_set);
#endif

#endif  // LIBHWSEC_FOUNDATION_TPM_ERROR_TPM_ERROR_DATA_H_
