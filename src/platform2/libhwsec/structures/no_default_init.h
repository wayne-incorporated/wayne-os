// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_STRUCTURES_NO_DEFAULT_INIT_H_
#define LIBHWSEC_STRUCTURES_NO_DEFAULT_INIT_H_

#include "libhwsec-foundation/utility/no_default_init.h"

namespace hwsec {

template <typename T>
using NoDefault = hwsec_foundation::NoDefault<T>;

}  // namespace hwsec

#endif  // LIBHWSEC_STRUCTURES_NO_DEFAULT_INIT_H_
