// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_FUZZED_TROUSERS_UTILS_H_
#define LIBHWSEC_FOUNDATION_FUZZED_TROUSERS_UTILS_H_

#include <stddef.h>

#include "libhwsec-foundation/hwsec-foundation_export.h"

#if defined(__cplusplus)

#include <fuzzer/FuzzedDataProvider.h>

namespace hwsec_foundation {

HWSEC_FOUNDATION_EXPORT void FuzzedTrousersSetup(
    FuzzedDataProvider* data_provider);

}  // namespace hwsec_foundation

#endif

#if defined(__cplusplus)
extern "C" {
#endif

#define DEFINE_CONSUME_INTEGRAL(TYPE, NAME) \
  HWSEC_FOUNDATION_EXPORT TYPE FuzzedTrousersConsume##NAME();
DEFINE_CONSUME_INTEGRAL(uint8_t, Byte)
DEFINE_CONSUME_INTEGRAL(int8_t, Bool)
DEFINE_CONSUME_INTEGRAL(uint16_t, Uint16)
DEFINE_CONSUME_INTEGRAL(uint32_t, Uint32)
DEFINE_CONSUME_INTEGRAL(uint64_t, Uint64)
#undef DEFINE_CONSUME_INTEGRAL

HWSEC_FOUNDATION_EXPORT void FuzzedTrousersConsumeBytes(size_t size,
                                                        uint8_t* result);

#if defined(__cplusplus)
}
#endif

#endif  // LIBHWSEC_FOUNDATION_FUZZED_TROUSERS_UTILS_H_
