// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_ERROR_ERROR_H_
#define LIBHWSEC_FOUNDATION_ERROR_ERROR_H_

#include <utility>

#include "libhwsec-foundation/status/status_chain.h"

namespace hwsec_foundation {
namespace error {

template <typename _Et, typename... Args>
inline auto CreateError(Args&&... args) {
  return hwsec_foundation::status::MakeStatus<_Et>(std::forward<Args>(args)...);
}

template <typename _Et, typename _Ot, typename... Args>
inline auto WrapError(hwsec_foundation::status::StatusChain<_Ot> error,
                      Args&&... args) {
  return hwsec_foundation::status::MakeStatus<_Et>(std::forward<Args>(args)...)
      .Wrap(std::move(error));
}

}  // namespace error
}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_ERROR_ERROR_H_
