// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NVME_WEAR_LEVEL_NVME_WEAR_LEVEL_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NVME_WEAR_LEVEL_NVME_WEAR_LEVEL_H_

#include <cstdint>
#include <memory>
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

// The NvmeWearLevelRoutine routine to examine wear level against input
// threshold.
class NvmeWearLevelRoutine final : public DiagnosticRoutineWithStatus {
 public:
  static const char kNvmeWearLevelRoutineThresholdError[];
  static const char kNvmeWearLevelRoutineGetInfoError[];
  static const char kNvmeWearLevelRoutineFailed[];
  static const char kNvmeWearLevelRoutineSuccess[];
  static const uint32_t kNvmeLogPageId;
  static const uint32_t kNvmeLogDataLength;
  static const bool kNvmeLogRawBinary;

  NvmeWearLevelRoutine(org::chromium::debugdProxyInterface* debugd_proxy,
                       const std::optional<uint32_t>& wear_level_threshold);
  NvmeWearLevelRoutine(const NvmeWearLevelRoutine&) = delete;
  NvmeWearLevelRoutine& operator=(const NvmeWearLevelRoutine&) = delete;
  ~NvmeWearLevelRoutine() override;

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

  org::chromium::debugdProxyInterface* const debugd_proxy_ = nullptr;
  const std::optional<uint32_t> wear_level_threshold_;

  uint32_t percent_ = 0;
  base::Value::Dict output_dict_;

  base::WeakPtrFactory<NvmeWearLevelRoutine> weak_ptr_routine_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NVME_WEAR_LEVEL_NVME_WEAR_LEVEL_H_
