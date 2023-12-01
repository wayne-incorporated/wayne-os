// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/fuzzed_trousers_utils.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <memory>
#include <string>

#include <fuzzer/FuzzedDataProvider.h>

namespace hwsec_foundation {

namespace {

struct FuzzedTrousersData {
  FuzzedDataProvider* data_provider;
};
std::unique_ptr<FuzzedTrousersData> data;

}  // namespace

void FuzzedTrousersSetup(FuzzedDataProvider* data_provider) {
  data = std::make_unique<FuzzedTrousersData>();
  data->data_provider = data_provider;
}

#define DECLARE_CONSUME_INTEGRAL(TYPE, NAME)             \
  extern "C" TYPE FuzzedTrousersConsume##NAME() {        \
    return data->data_provider->ConsumeIntegral<TYPE>(); \
  }
DECLARE_CONSUME_INTEGRAL(uint8_t, Byte)
DECLARE_CONSUME_INTEGRAL(int8_t, Bool)
DECLARE_CONSUME_INTEGRAL(uint16_t, Uint16)
DECLARE_CONSUME_INTEGRAL(uint32_t, Uint32)
DECLARE_CONSUME_INTEGRAL(uint64_t, Uint64)
#undef DECLARE_CONSUME_INTEGRAL

extern "C" void FuzzedTrousersConsumeBytes(size_t size, uint8_t* result) {
  std::string bytes = data->data_provider->ConsumeBytesAsString(size);
  // Use |bytes.size()| instead of |size| because the data from
  // FuzzedDataProvider may be shorter.
  memcpy(result, bytes.data(), bytes.size());
}

}  // namespace hwsec_foundation
