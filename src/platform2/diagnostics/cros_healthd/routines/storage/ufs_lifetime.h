// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_STORAGE_UFS_LIFETIME_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_STORAGE_UFS_LIFETIME_H_

#include "diagnostics/cros_healthd/routines/base_routine_control.h"
#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/mojom/public/cros_healthd_routines.mojom.h"

namespace diagnostics {

inline constexpr char kUfsHealthDescPreEolInfo[] = "eol_info";
inline constexpr char kUfsHealthDescDeviceLifeTimeEstA[] =
    "life_time_estimation_a";
inline constexpr char kUfsHealthDescDeviceLifeTimeEstB[] =
    "life_time_estimation_b";

// The UFS lifetime routine checks the UFS drive's lifetime.
class UfsLifetimeRoutine final : public BaseRoutineControl {
 public:
  explicit UfsLifetimeRoutine(
      Context* context,
      const ash::cros_healthd::mojom::UfsLifetimeRoutineArgumentPtr& arg);
  UfsLifetimeRoutine(const UfsLifetimeRoutine&) = delete;
  UfsLifetimeRoutine& operator=(const UfsLifetimeRoutine&) = delete;
  ~UfsLifetimeRoutine() override;

  // BaseRoutineControl overrides:
  void OnStart() override;

 private:
  // Unowned. Should outlive this instance.
  Context* const context_ = nullptr;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_STORAGE_UFS_LIFETIME_H_
