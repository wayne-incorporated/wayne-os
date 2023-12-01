// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_FINGERPRINT_FP_SENSOR_ERRORS_H_
#define LIBEC_FINGERPRINT_FP_SENSOR_ERRORS_H_

#include <brillo/brillo_export.h>
#include <brillo/enum_flags.h>
#include <chromeos/ec/ec_commands.h>

namespace ec {

inline constexpr int kMaxDeadPixels = FP_ERROR_DEAD_PIXELS_UNKNOWN - 1;
static_assert(kMaxDeadPixels > 0,
              "Max number of dead pixels must be greater than zero");

enum class BRILLO_EXPORT FpSensorErrors {
  kNone = 0,
  kNoIrq = 1u << 0u,
  kSpiCommunication = 1u << 1u,
  kBadHardwareID = 1u << 2u,
  kInitializationFailure = 1u << 3u,
  kDeadPixels = 1u << 4u,
};
DECLARE_FLAGS_ENUM(FpSensorErrors);

}  // namespace ec

#endif  // LIBEC_FINGERPRINT_FP_SENSOR_ERRORS_H_
