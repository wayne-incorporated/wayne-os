// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_EMMC_LIFETIME_EMMC_LIFETIME_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_EMMC_LIFETIME_EMMC_LIFETIME_H_

#include <string>

#include <base/memory/weak_ptr.h>
#include <base/values.h>
#include <brillo/errors/error.h>

#include "diagnostics/cros_healthd/routines/diag_routine_with_status.h"

namespace org {
namespace chromium {
class debugdProxyInterface;
}  // namespace chromium
}  // namespace org

namespace diagnostics {

inline constexpr char kEmmcLifetimeRoutineSuccess[] = "Pre-EOL info is normal.";
inline constexpr char kEmmcLifetimeRoutineDebugdError[] =
    "Debugd returns error.";
inline constexpr char kEmmcLifetimeRoutineParseError[] =
    "Failed to parse mmc output.";
inline constexpr char kEmmcLifetimeRoutinePreEolInfoAbnormalError[] =
    "Pre-EOL info is not normal.";

// Examine the lifetime of the eMMC drive. The routine will pass if PRE_EOL_INFO
// (an indication about device life time reflected by average reserved blocks)
// is 0x01 (normal). In addition, the value of DEVICE_LIFE_TIME_EST_TYP_A and
// DEVICE_LIFE_TIME_EST_TYP_B (an estimated indication about the device life
// time that is reflected by the averaged wear out of memory of Type A/B
// relative to its maximum estimated device life time) will be included in the
// output.
class EmmcLifetimeRoutine final : public DiagnosticRoutineWithStatus {
 public:
  explicit EmmcLifetimeRoutine(
      org::chromium::debugdProxyInterface* debugd_proxy);
  EmmcLifetimeRoutine(const EmmcLifetimeRoutine&) = delete;
  EmmcLifetimeRoutine& operator=(const EmmcLifetimeRoutine&) = delete;

  // DiagnosticRoutine overrides:
  ~EmmcLifetimeRoutine() override;
  void Start() override;
  void Resume() override;
  void Cancel() override;
  void PopulateStatusUpdate(ash::cros_healthd::mojom::RoutineUpdate* response,
                            bool include_output) override;

 private:
  void OnDebugdResultCallback(const std::string& result);
  void OnDebugdErrorCallback(brillo::Error* error);
  // Updates status, percent_, status_message at the same moment to ensure
  // each of them corresponds with the others.
  void UpdateStatusWithProgressPercent(
      ash::cros_healthd::mojom::DiagnosticRoutineStatusEnum status,
      uint32_t percent,
      std::string msg);

  org::chromium::debugdProxyInterface* const debugd_proxy_;

  uint32_t percent_ = 0;
  base::Value::Dict output_dict_;

  base::WeakPtrFactory<EmmcLifetimeRoutine> weak_ptr_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_EMMC_LIFETIME_EMMC_LIFETIME_H_
