// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FACTORY_FUZZED_FACTORY_H_
#define LIBHWSEC_FACTORY_FUZZED_FACTORY_H_

#include <fuzzer/FuzzedDataProvider.h>

#include "libhwsec/factory/factory_impl.h"
#include "libhwsec/hwsec_export.h"
#include "libhwsec/structures/threading_mode.h"

// A fuzzed factory implementation for fuzzing.
//
// The default mode will run the middleware on current task runner, but that
// need to be used carefully in multi-thread environment.
//
// Example usage:
//   FuzzedFactory factory(data_provider);
//   StatusOr<bool> ready = factory.GetCryptohomeFrontend()->IsReady();
//
//   The result of "ready" might be an TPMError or true or false.

namespace hwsec {

class HWSEC_EXPORT FuzzedFactory : public FactoryImpl {
 public:
  explicit FuzzedFactory(FuzzedDataProvider& data_provider,
                         ThreadingMode mode = ThreadingMode::kCurrentThread);

  ~FuzzedFactory() override;
};

}  // namespace hwsec

#endif  // LIBHWSEC_FACTORY_FUZZED_FACTORY_H_
