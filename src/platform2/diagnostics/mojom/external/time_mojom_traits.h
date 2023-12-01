// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file is copied and modified from,
// https://chrome-internal.googlesource.com/chromeos/platform/drivefs/+/HEAD/mojom/time_mojom_traits.h

#ifndef DIAGNOSTICS_MOJOM_EXTERNAL_TIME_MOJOM_TRAITS_H_
#define DIAGNOSTICS_MOJOM_EXTERNAL_TIME_MOJOM_TRAITS_H_

#include <limits>

#include <base/time/time.h>
#include <mojo/public/cpp/bindings/struct_traits.h>

#include "diagnostics/mojom/external/time.mojom.h"

namespace mojo {

template <>
struct StructTraits<ash::cros_healthd::external::mojo_base::mojom::TimeDataView,
                    base::Time> {
  static int64_t internal_value(const base::Time& time) {
    return (time - base::Time()).InMicroseconds();
  }

  static bool Read(
      ash::cros_healthd::external::mojo_base::mojom::TimeDataView data,
      base::Time* time) {
    *time = base::Time() + base::Microseconds(data.internal_value());
    return true;
  }
};

template <>
struct StructTraits<
    ash::cros_healthd::external::mojo_base::mojom::TimeDeltaDataView,
    base::TimeDelta> {
  static int64_t microseconds(const base::TimeDelta& delta) {
    return delta.InMicroseconds();
  }

  static bool Read(
      ash::cros_healthd::external::mojo_base::mojom::TimeDeltaDataView data,
      base::TimeDelta* delta) {
    *delta = base::Microseconds(data.microseconds());
    return true;
  }
};

}  // namespace mojo

#endif  // DIAGNOSTICS_MOJOM_EXTERNAL_TIME_MOJOM_TRAITS_H_
