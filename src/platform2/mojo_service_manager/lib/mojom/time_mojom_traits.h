// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MOJO_SERVICE_MANAGER_LIB_MOJOM_TIME_MOJOM_TRAITS_H_
#define MOJO_SERVICE_MANAGER_LIB_MOJOM_TIME_MOJOM_TRAITS_H_

#include <base/time/time.h>
#include <mojo/public/cpp/bindings/struct_traits.h>

#include "mojo_service_manager/lib/mojom/time.mojom.h"

namespace mojo {

template <>
struct StructTraits<chromeos::mojo_service_manager::mojom::TimeDeltaDataView,
                    base::TimeDelta> {
  static int64_t microseconds(const base::TimeDelta& delta) {
    return delta.InMicroseconds();
  }

  static bool Read(
      chromeos::mojo_service_manager::mojom::TimeDeltaDataView data,
      base::TimeDelta* delta) {
    *delta = base::Microseconds(data.microseconds());
    return true;
  }
};

}  // namespace mojo

#endif  // MOJO_SERVICE_MANAGER_LIB_MOJOM_TIME_MOJOM_TRAITS_H_
