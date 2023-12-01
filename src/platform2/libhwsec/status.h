// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_STATUS_H_
#define LIBHWSEC_STATUS_H_

#include "libhwsec/error/tpm_error.h"
#include "libhwsec-foundation/status/status_chain_or.h"

namespace hwsec {

using Status = hwsec_foundation::status::StatusChain<hwsec::TPMErrorBase>;

template <typename Type>
using StatusOr =
    hwsec_foundation::status::StatusChainOr<Type, hwsec::TPMErrorBase>;

inline auto OkStatus() {
  return hwsec_foundation::status::OkStatus<TPMErrorBase>();
}

}  // namespace hwsec

#endif  // LIBHWSEC_STATUS_H_
