// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FUZZED_DA_MITIGATION_H_
#define LIBHWSEC_FUZZED_DA_MITIGATION_H_

#include <fuzzer/FuzzedDataProvider.h>

#include "libhwsec/backend/da_mitigation.h"
#include "libhwsec/fuzzed/basic_objects.h"

namespace hwsec {

template <>
struct FuzzedObject<DAMitigation::DAMitigationStatus> {
  DAMitigation::DAMitigationStatus operator()(
      FuzzedDataProvider& provider) const {
    return DAMitigation::DAMitigationStatus{
        .lockout = FuzzedObject<bool>()(provider),
        .remaining = FuzzedObject<base::TimeDelta>()(provider),
    };
  }
};

}  // namespace hwsec

#endif  // LIBHWSEC_FUZZED_DA_MITIGATION_H_
