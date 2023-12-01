// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/nvme_self_test/nvme_self_test.h"

#include <algorithm>
#include <iterator>
#include <utility>
#include <vector>

#include <base/base64.h>
#include <base/check.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/json/json_writer.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/time/time.h>
#include <debugd/dbus-proxies.h>

#include "diagnostics/base/mojo_utils.h"
#include "diagnostics/cros_healthd/system/debugd_constants.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

mojom::DiagnosticRoutineStatusEnum CheckSelfTestPassed(uint8_t status) {
  // Bits 3:0: 0x0 means pass without an error; otherwise the index of error.
  return (status & 0xf) == 0 ? mojom::DiagnosticRoutineStatusEnum::kPassed
                             : mojom::DiagnosticRoutineStatusEnum::kFailed;
}

// Check the result and return corresponding complete message.
std::string GetCompleteMessage(uint8_t status) {
  // Bits 3:0: indicates the result of the device self-test operation.
  status &= 0xf;
  // Check if result(complete value) is large than complete message array.
  if (status >= NvmeSelfTestRoutine::kSelfTestRoutineCompleteLogSize) {
    return NvmeSelfTestRoutine::kSelfTestRoutineCompleteUnknownStatus;
  } else {
    return NvmeSelfTestRoutine::kSelfTestRoutineCompleteLog[status];
  }
}

}  // namespace

constexpr char NvmeSelfTestRoutine::kNvmeSelfTestRoutineStarted[] =
    "SelfTest status: self-test started.";
constexpr char NvmeSelfTestRoutine::kNvmeSelfTestRoutineStartError[] =
    "SelfTest status: self-test failed to start.";
constexpr char NvmeSelfTestRoutine::kNvmeSelfTestRoutineAbortionError[] =
    "SelfTest status: ERROR, self-test abortion failed.";
constexpr char NvmeSelfTestRoutine::kNvmeSelfTestRoutineRunning[] =
    "SelfTest status: self-test is running.";
constexpr char NvmeSelfTestRoutine::kNvmeSelfTestRoutineGetProgressFailed[] =
    "SelfTest status: ERROR, cannot get percent info.";
constexpr char NvmeSelfTestRoutine::kNvmeSelfTestRoutineCancelled[] =
    "SelfTest status: self-test is cancelled.";

const char* const NvmeSelfTestRoutine::kSelfTestRoutineCompleteLog[] = {
    "SelfTest status: Test PASS.",
    "SelfTest status: Operation was aborted by Device Self-test command.",
    "SelfTest status: Operation was aborted by a Controller Level Reset.",
    "SelfTest status: Operation was aborted due to a removal of a namespace"
    " from the namespace inventory.",
    "SelfTest Status: Operation was aborted due to the processing of a Format"
    " NVM command.",
    "SelfTest status: A fatal error or unknown test error occurred while the"
    " controller was executing the device self-test operation and the operation"
    " did not complete.",
    "SelfTest status: Operation completed with a segment that failed and the"
    " segment that failed is not known.",
    "SelfTest status: Operation completed with one or more failed segments and"
    " the first segment that failed is indicated in the Segment Number field.",
    "SelfTest status: Operation was aborted for an unknown reason.",
};
constexpr char NvmeSelfTestRoutine::kSelfTestRoutineCompleteUnknownStatus[] =
    "SelfTest status: Unknown complete status.";
constexpr size_t NvmeSelfTestRoutine::kSelfTestRoutineCompleteLogSize =
    std::size(NvmeSelfTestRoutine::kSelfTestRoutineCompleteLog);

// Page ID 6 if for self-test progress info.
constexpr uint32_t NvmeSelfTestRoutine::kNvmeLogPageId = 6;
constexpr uint32_t NvmeSelfTestRoutine::kNvmeLogDataLength = 16;
constexpr bool NvmeSelfTestRoutine::kNvmeLogRawBinary = true;

NvmeSelfTestRoutine::NvmeSelfTestRoutine(
    org::chromium::debugdProxyInterface* debugd_proxy,
    SelfTestType self_test_type)
    : debugd_proxy_(debugd_proxy), self_test_type_(self_test_type) {
  DCHECK(debugd_proxy_);
}

NvmeSelfTestRoutine::~NvmeSelfTestRoutine() = default;

void NvmeSelfTestRoutine::Start() {
  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kRunning, "");

  auto result_callback =
      base::BindOnce(&NvmeSelfTestRoutine::OnDebugdNvmeSelfTestStartCallback,
                     weak_ptr_routine_.GetWeakPtr());
  auto error_callback =
      base::BindOnce(&NvmeSelfTestRoutine::OnDebugdErrorCallback,
                     weak_ptr_routine_.GetWeakPtr());

  switch (self_test_type_) {
    case kRunShortSelfTest:
      debugd_proxy_->NvmeAsync(kNvmeShortSelfTestOption,
                               std::move(result_callback),
                               std::move(error_callback));
      break;
    case kRunLongSelfTest:
      debugd_proxy_->NvmeAsync(kNvmeLongSelfTestOption,
                               std::move(result_callback),
                               std::move(error_callback));
      break;
  }
}

void NvmeSelfTestRoutine::Resume() {}
void NvmeSelfTestRoutine::Cancel() {
  if (!UpdateStatusWithProgressPercent(
          mojom::DiagnosticRoutineStatusEnum::kCancelling,
          /*percent=*/0, "")) {
    return;
  }
  auto result_callback =
      base::BindOnce(&NvmeSelfTestRoutine::OnDebugdNvmeSelfTestCancelCallback,
                     weak_ptr_routine_.GetWeakPtr());
  auto error_callback =
      base::BindOnce(&NvmeSelfTestRoutine::OnDebugdErrorCallback,
                     weak_ptr_routine_.GetWeakPtr());
  debugd_proxy_->NvmeAsync(kNvmeStopSelfTestOption, std::move(result_callback),
                           std::move(error_callback));
}

void NvmeSelfTestRoutine::PopulateStatusUpdate(mojom::RoutineUpdate* response,
                                               bool include_output) {
  if (GetStatus() == mojom::DiagnosticRoutineStatusEnum::kRunning) {
    auto result_callback =
        base::BindOnce(&NvmeSelfTestRoutine::OnDebugdResultCallback,
                       weak_ptr_routine_.GetWeakPtr());
    auto error_callback =
        base::BindOnce(&NvmeSelfTestRoutine::OnDebugdErrorCallback,
                       weak_ptr_routine_.GetWeakPtr());
    debugd_proxy_->NvmeLogAsync(/*page_id=*/kNvmeLogPageId,
                                /*length=*/kNvmeLogDataLength,
                                /*raw_binary=*/kNvmeLogRawBinary,
                                std::move(result_callback),
                                std::move(error_callback));
  }

  auto status = GetStatus();
  auto update = mojom::NonInteractiveRoutineUpdate::New();
  update->status = status;
  update->status_message = GetStatusMessage();

  response->routine_update_union =
      mojom::RoutineUpdateUnion::NewNoninteractiveUpdate(std::move(update));
  response->progress_percent = percent_;

  if (include_output && !output_dict_.empty()) {
    // If routine status is not at completed/cancelled then prints the debugd
    // raw data with output.
    if (status != mojom::DiagnosticRoutineStatusEnum::kPassed &&
        status != mojom::DiagnosticRoutineStatusEnum::kCancelled) {
      std::string json;
      base::JSONWriter::Write(output_dict_, &json);
      response->output =
          CreateReadOnlySharedMemoryRegionMojoHandle(base::StringPiece(json));
    }
  }
}

void NvmeSelfTestRoutine::OnDebugdErrorCallback(brillo::Error* error) {
  if (error) {
    LOG(ERROR) << "Debugd error: " << error->GetMessage();
    UpdateStatusWithProgressPercent(mojom::DiagnosticRoutineStatusEnum::kError,
                                    /*percent=*/100, error->GetMessage());
  }
}

void NvmeSelfTestRoutine::OnDebugdNvmeSelfTestStartCallback(
    const std::string& result) {
  ResetOutputDictToValue(result);

  // Checks whether self-test has already been launched.
  if (!base::StartsWith(result, "Device self-test started",
                        base::CompareCase::SENSITIVE)) {
    LOG(ERROR) << "self-test failed to start: " << result;
    UpdateStatusWithProgressPercent(mojom::DiagnosticRoutineStatusEnum::kError,
                                    /*percent=*/100,
                                    kNvmeSelfTestRoutineStartError);
    return;
  }
  if (!UpdateStatusWithProgressPercent(
          mojom::DiagnosticRoutineStatusEnum::kRunning,
          /*percent=*/0, kNvmeSelfTestRoutineStarted)) {
    return;
  }
}

void NvmeSelfTestRoutine::OnDebugdNvmeSelfTestCancelCallback(
    const std::string& result) {
  ResetOutputDictToValue(result);

  // Checks abortion if successful
  if (!base::StartsWith(result, "Aborting device self-test operation",
                        base::CompareCase::SENSITIVE)) {
    LOG(ERROR) << "self-test abortion failed:" << result;
    UpdateStatusWithProgressPercent(mojom::DiagnosticRoutineStatusEnum::kError,
                                    /*percent=*/100,
                                    kNvmeSelfTestRoutineAbortionError);
    return;
  }
  if (!UpdateStatusWithProgressPercent(
          mojom::DiagnosticRoutineStatusEnum::kCancelled,
          /*percent=*/100, kNvmeSelfTestRoutineCancelled)) {
    return;
  }
}

bool NvmeSelfTestRoutine::CheckSelfTestCompleted(uint8_t progress,
                                                 uint8_t status) const {
  // |progress|: Bits 7:4 are reserved; Bits 3:0 indicates the status of
  // the current device self-test operation. |progress| is equal to 0 while
  // self-test has been completed.
  // |status|: Bits 7:4 indicates the type of operation: 0x1 for short-time
  // self-test, 0x2 for long-time self-test; Bits 3:0 indicates the result of
  // self-test.
  return (progress & 0xf) == 0 && (status >> 4) == self_test_type_;
}

void NvmeSelfTestRoutine::OnDebugdResultCallback(const std::string& result) {
  ResetOutputDictToValue(result);
  std::string decoded_output;

  if (!base::Base64Decode(result, &decoded_output)) {
    LOG(ERROR) << "Base64 decoding failed. Base64 data: " << result;
    UpdateStatusWithProgressPercent(mojom::DiagnosticRoutineStatusEnum::kError,
                                    /*percent=*/100,
                                    kNvmeSelfTestRoutineGetProgressFailed);
    return;
  }

  if (decoded_output.length() != kNvmeLogDataLength) {
    LOG(ERROR) << "String size is not as expected(" << kNvmeLogDataLength
               << "). Size: " << decoded_output.length();
    UpdateStatusWithProgressPercent(mojom::DiagnosticRoutineStatusEnum::kError,
                                    /*percent=*/100,
                                    kNvmeSelfTestRoutineGetProgressFailed);
    return;
  }

  const uint8_t progress = static_cast<uint8_t>(decoded_output[0]);
  // Bits 6:0: percentage of self-test operation.
  const uint8_t percent = static_cast<uint8_t>(decoded_output[1]) & 0x7f;
  const uint8_t complete_status = static_cast<uint8_t>(decoded_output[4]);

  if (CheckSelfTestCompleted(progress, complete_status)) {
    if (!UpdateStatusWithProgressPercent(CheckSelfTestPassed(complete_status),
                                         /*percent=*/100,
                                         GetCompleteMessage(complete_status))) {
      return;
    }
  } else if ((progress & 0xf) == self_test_type_) {
    if (!UpdateStatusWithProgressPercent(
            mojom::DiagnosticRoutineStatusEnum::kRunning, percent,
            kNvmeSelfTestRoutineRunning)) {
      return;
    }
  } else {
    // It's not readable if uint8_t variables are not cast to uint32_t.
    LOG(ERROR) << "No valid data is retrieved. progress: "
               << static_cast<uint32_t>(progress)
               << ", percent: " << static_cast<uint32_t>(percent)
               << ", status:" << static_cast<uint32_t>(complete_status);
    if (!UpdateStatusWithProgressPercent(
            mojom::DiagnosticRoutineStatusEnum::kError,
            /*percent=*/100, kNvmeSelfTestRoutineGetProgressFailed)) {
      return;
    }
  }
}

void NvmeSelfTestRoutine::ResetOutputDictToValue(const std::string& value) {
  base::Value::Dict result_dict;
  result_dict.Set("rawData", value);
  output_dict_.Set("resultDetails", std::move(result_dict));
}

bool NvmeSelfTestRoutine::UpdateStatusWithProgressPercent(
    mojom::DiagnosticRoutineStatusEnum status,
    uint32_t percent,
    std::string msg) {
  auto old_status = GetStatus();
  // Final states (kPassed, kFailed, kError, kCancelled) cannot be updated.
  // Override kCancelling with kRunning is prohibited.
  if (old_status == mojom::DiagnosticRoutineStatusEnum::kPassed ||
      old_status == mojom::DiagnosticRoutineStatusEnum::kFailed ||
      old_status == mojom::DiagnosticRoutineStatusEnum::kError ||
      old_status == mojom::DiagnosticRoutineStatusEnum::kCancelled ||
      (old_status == mojom::DiagnosticRoutineStatusEnum::kCancelling &&
       status == mojom::DiagnosticRoutineStatusEnum::kRunning)) {
    return false;
  }

  UpdateStatus(status, std::move(msg));
  percent_ = percent;
  return true;
}

}  // namespace diagnostics
