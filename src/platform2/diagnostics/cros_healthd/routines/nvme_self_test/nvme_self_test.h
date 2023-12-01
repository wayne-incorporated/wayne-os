// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NVME_SELF_TEST_NVME_SELF_TEST_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NVME_SELF_TEST_NVME_SELF_TEST_H_

#include <cstdint>
#include <memory>
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

// Launches self-test of NVMe for a short time or long period. This routine
// fetches the progress status by parsing message from NVMe log page ID 6.
// Please refer to https://nvmexpress.org/wp-content/uploads/NVM_Express_
// Revision_1.3.pdf, Figure 98 "Device Self-test log" and Figure 99 "Self-test
// Result Data Structure" from 5.14.1.6.
class NvmeSelfTestRoutine final : public DiagnosticRoutineWithStatus {
 public:
  static const char kNvmeSelfTestRoutineStarted[];
  static const char kNvmeSelfTestRoutineStartError[];
  static const char kNvmeSelfTestRoutineAbortionError[];
  static const char kNvmeSelfTestRoutineRunning[];
  static const char kNvmeSelfTestRoutineGetProgressFailed[];
  static const char kNvmeSelfTestRoutineCancelled[];

  // The error message captured from NVMe controller.
  // Reference: "Figure 99; Get Log Page - self-test Result Data Structure"
  // from https://nvmexpress.org/wp-content/uploads/NVM-Express-1_3b-2018.05.04
  // -ratified.pdf.
  static const char* const kSelfTestRoutineCompleteLog[];
  static const char kSelfTestRoutineCompleteUnknownStatus[];
  static const size_t kSelfTestRoutineCompleteLogSize;

  static const uint32_t kNvmeLogPageId;
  static const uint32_t kNvmeLogDataLength;
  static const bool kNvmeLogRawBinary;

  enum SelfTestType {
    // In NVMe spec, the referred byte(Log Page 6, byte 4, Bit 7:4) indiecates
    // the self-test type. 0: reserved; 1: short self-test; 2: long self-test.
    kRunShortSelfTest = 1, /* Launch short-time self-test */
    kRunLongSelfTest = 2,  /* Launch long-time self-test */
  };

  NvmeSelfTestRoutine(org::chromium::debugdProxyInterface* debugd_proxy,
                      SelfTestType self_test_type);
  NvmeSelfTestRoutine(const NvmeSelfTestRoutine&) = delete;
  NvmeSelfTestRoutine& operator=(const NvmeSelfTestRoutine&) = delete;
  ~NvmeSelfTestRoutine() override;

  // DiagnosticRoutine overrides:
  void Start() override;
  void Resume() override;
  void Cancel() override;
  void PopulateStatusUpdate(ash::cros_healthd::mojom::RoutineUpdate* response,
                            bool include_output) override;

 private:
  bool CheckSelfTestCompleted(uint8_t progress, uint8_t status) const;

  void OnDebugdNvmeSelfTestCancelCallback(const std::string& result);
  void OnDebugdNvmeSelfTestStartCallback(const std::string& result);
  void OnDebugdResultCallback(const std::string& result);
  void OnDebugdErrorCallback(brillo::Error* error);

  // Resets |output_dict_| to clear any previous input, then adds a new
  // dictionary with the key "rawData" and value |value|.
  void ResetOutputDictToValue(const std::string& value);

  // Update percent_, status_message, status at the same moment in case
  // misinformation occurring.
  bool UpdateStatusWithProgressPercent(
      ash::cros_healthd::mojom::DiagnosticRoutineStatusEnum status,
      uint32_t percent,
      std::string msg);

  // debugd_proxy_ is an unowned pointer and it should outlive this instance.
  org::chromium::debugdProxyInterface* const debugd_proxy_ = nullptr;
  const SelfTestType self_test_type_;

  // On certain devices, routine will still be running even if percent_ reaches
  // 100. Hence, we cannot rely on percent_ to determine whether the routine is
  // completed. Use GetStatus() instead.
  uint32_t percent_ = 0;
  base::Value::Dict output_dict_;

  FRIEND_TEST(NvmeSelfTestRoutineTest, RoutineStatusTransition);

  base::WeakPtrFactory<NvmeSelfTestRoutine> weak_ptr_routine_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_NVME_SELF_TEST_NVME_SELF_TEST_H_
