// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_STRUCTURES_EXPLICIT_INIT_H_
#define LIBHWSEC_STRUCTURES_EXPLICIT_INIT_H_

#include "libhwsec-foundation/utility/explicit_init.h"

namespace hwsec {

template <typename T>
using ExplicitInit = hwsec_foundation::ExplicitInit<T>;

}  // namespace hwsec

#endif  // LIBHWSEC_STRUCTURES_EXPLICIT_INIT_H_
