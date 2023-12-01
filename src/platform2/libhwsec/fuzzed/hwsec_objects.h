// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FUZZED_HWSEC_OBJECTS_H_
#define LIBHWSEC_FUZZED_HWSEC_OBJECTS_H_

#include <type_traits>

#include <base/task/single_thread_task_runner.h>
#include <base/task/task_runner.h>
#include <base/threading/thread.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "libhwsec/fuzzed/basic_objects.h"
#include "libhwsec/status.h"

namespace hwsec {

template <>
struct FuzzedObject<Status> {
  [[clang::return_typestate(unconsumed)]] Status GenerateError(
      FuzzedDataProvider& provider) const {
    using hwsec_foundation::status::MakeStatus;
    return MakeStatus<TPMError>("Error",
                                FuzzedObject<TPMRetryAction>()(provider));
  }

  Status operator()(FuzzedDataProvider& provider) const {
    if (provider.ConsumeBool()) {
      return OkStatus();
    }
    return GenerateError(provider);
  }
};

template <typename T>
struct FuzzedObject<StatusOr<T>> {
  StatusOr<T> operator()(FuzzedDataProvider& provider) const {
    if (!provider.ConsumeBool()) {
      return FuzzedObject<Status>().GenerateError(provider);
    }
    return FuzzedObject<T>()(provider);
  }
};

}  // namespace hwsec

#endif  // LIBHWSEC_FUZZED_HWSEC_OBJECTS_H_
