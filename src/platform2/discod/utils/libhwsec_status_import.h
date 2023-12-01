// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DISCOD_UTILS_LIBHWSEC_STATUS_IMPORT_H_
#define DISCOD_UTILS_LIBHWSEC_STATUS_IMPORT_H_

#include <utility>

#include <libhwsec-foundation/error/testing_helper.h>
#include <libhwsec-foundation/status/status_chain.h>
#include <libhwsec-foundation/status/status_chain_macros.h>
#include <libhwsec-foundation/status/status_chain_or.h>

namespace discod {

using Status =
    ::hwsec_foundation::status::StatusChain<::hwsec_foundation::status::Error>;

template <typename _Vt>
using StatusOr = ::hwsec_foundation::status::
    StatusChainOr<_Vt, ::hwsec_foundation::status::Error>;

inline Status OkStatus() {
  return ::hwsec_foundation::status::OkStatus<
      ::hwsec_foundation::status::Error>();
}

template <typename... Args>
inline Status MakeStatus(Args&&... args) {
  return ::hwsec_foundation::status::MakeStatus<
      ::hwsec_foundation::status::Error, Args...>(std::forward<Args>(args)...);
}

using ::hwsec_foundation::error::testing::IsOk;
using ::hwsec_foundation::error::testing::NotOk;

}  // namespace discod

#endif  // DISCOD_UTILS_LIBHWSEC_STATUS_IMPORT_H_
