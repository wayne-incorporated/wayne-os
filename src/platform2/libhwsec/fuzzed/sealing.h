// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FUZZED_SEALING_H_
#define LIBHWSEC_FUZZED_SEALING_H_

#include <fuzzer/FuzzedDataProvider.h>

#include "libhwsec/backend/sealing.h"
#include "libhwsec/fuzzed/basic_objects.h"
#include "libhwsec/fuzzed/key_management.h"

namespace hwsec {

template <>
struct FuzzedObject<Sealing::UnsealOptions> {
  Sealing::UnsealOptions operator()(FuzzedDataProvider& provider) const {
    return Sealing::UnsealOptions{
        .preload_data = FuzzedObject<std::optional<Key>>()(provider),
    };
  }
};

}  // namespace hwsec

#endif  // LIBHWSEC_FUZZED_SEALING_H_
