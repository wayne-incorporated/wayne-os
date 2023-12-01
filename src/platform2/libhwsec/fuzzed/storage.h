// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FUZZED_STORAGE_H_
#define LIBHWSEC_FUZZED_STORAGE_H_

#include <type_traits>

#include <fuzzer/FuzzedDataProvider.h>

#include "libhwsec/backend/storage.h"
#include "libhwsec/fuzzed/basic_objects.h"

namespace hwsec {

template <>
struct FuzzedObject<Storage::ReadyState> {
  Storage::ReadyState operator()(FuzzedDataProvider& provider) const {
    return Storage::ReadyState{
        .preparable = provider.ConsumeBool(),
        .readable = provider.ConsumeBool(),
        .writable = provider.ConsumeBool(),
        .destroyable = provider.ConsumeBool(),
    };
  }
};

template <>
struct FuzzedObject<Storage::LockOptions> {
  Storage::LockOptions operator()(FuzzedDataProvider& provider) const {
    return Storage::LockOptions{
        .read_lock = provider.ConsumeBool(),
        .write_lock = provider.ConsumeBool(),
    };
  }
};

}  // namespace hwsec

#endif  // LIBHWSEC_FUZZED_STORAGE_H_
