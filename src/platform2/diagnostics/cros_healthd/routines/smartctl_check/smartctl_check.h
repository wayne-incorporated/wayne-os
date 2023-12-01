// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_SMARTCTL_CHECK_SMARTCTL_CHECK_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_SMARTCTL_CHECK_SMARTCTL_CHECK_H_

#include <cstdint>
#include <optional>
#include <string>

#include <base/values.h>
#include <brillo/errors/error.h>

#include "diagnostics/cros_healthd/routines/diag_routine_with_status.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace org {
namespace chromium {
class debugdProxyInterface;
}  // namespace chromium
}  // namespace org

namespace diagnostics {

inline constexpr char kSmartctlCheckRoutineSuccess[] =
    "smartctl-check status: PASS.";
inline constexpr char kSmartctlCheckRoutineFailedToParse[] =
    "smartctl-check status: FAILED, unable to parse smartctl output.";
inline constexpr char kSmartctlCheckRoutineCheckFailed[] =
    "smartctl-check status: FAILED, one or more checks have failed.";
inline constexpr char kSmartctlCheckRoutineDebugdError[] =
    "smartctl-check status: ERROR, debugd returns error.";
inline constexpr char kSmartctlCheckRoutineThresholdError[] =
    "smartctl-check status: ERROR, threshold in percentage should be non-empty "
    "and between 0 and 255, inclusive.";

// The SmartctlCheckRoutine routine to examine:
// available_spare check: available_spare against available_spare_threshold.
// percentage_used check: percentage_used against input threshold.
// critical_warning check: critical_warning is 0x00 (no warning).
class SmartctlCheckRoutine final : public DiagnosticRoutineWithStatus {
 public:
  static const uint32_t kPercentageUsedMax;
  static const uint32_t kPercentageUsedMin;
  static const uint32_t kCriticalWarningNone;

  SmartctlCheckRoutine(
      org::chromium::debugdProxyInterface* debugd_proxy,
      const std::optional<uint32_t>& percentage_used_threshold);
  SmartctlCheckRoutine(const SmartctlCheckRoutine&) = delete;
  SmartctlCheckRoutine& operator=(const SmartctlCheckRoutine&) = delete;
  ~SmartctlCheckRoutine() override;

  // DiagnosticRoutine overrides:
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
  uint32_t percentage_used_threshold_;

  uint32_t percent_ = 0;
  base::Value::Dict output_dict_;

  base::WeakPtrFactory<SmartctlCheckRoutine> weak_ptr_routine_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_SMARTCTL_CHECK_SMARTCTL_CHECK_H_
