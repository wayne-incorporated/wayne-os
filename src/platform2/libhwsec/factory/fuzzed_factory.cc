// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/factory/fuzzed_factory.h"

#include <memory>
#include <utility>

#include "libhwsec/middleware/middleware.h"

#if !USE_FUZZER
#error "Don't build this file without using fuzzer!"
#endif

namespace hwsec {

FuzzedFactory::FuzzedFactory(FuzzedDataProvider& data_provider,
                             ThreadingMode mode)
    : FactoryImpl(std::make_unique<MiddlewareOwner>(
          /*custom_backend=*/nullptr, mode)) {
  middleware_.set_data_provider(&data_provider);
}

FuzzedFactory::~FuzzedFactory() {}

}  // namespace hwsec
