// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_OVERALLS_OVERALLS_API_H_
#define LIBHWSEC_OVERALLS_OVERALLS_API_H_

#include "libhwsec/hwsec_export.h"
#include "libhwsec/overalls/overalls.h"

namespace hwsec {
namespace overalls {

// Returns the singleton of |Overalls| instance.
HWSEC_EXPORT Overalls* GetOveralls();

}  // namespace overalls
}  // namespace hwsec

#endif  // LIBHWSEC_OVERALLS_OVERALLS_API_H_
