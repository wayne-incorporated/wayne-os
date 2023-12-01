// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/nvme_wear_level/nvme_wear_level.h"

#include <utility>
#include <vector>

#include <base/base64.h>
#include <base/check.h>
#include <base/json/json_writer.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/string_split.h>
#include <debugd/dbus-proxies.h>

#include "diagnostics/base/mojo_utils.h"

namespace diagnostics {

namespace mojom = ::ash::cros_healthd::mojom;

constexpr char NvmeWearLevelRoutine::kNvmeWearLevelRoutineThresholdError[] =
    "Wear-level status: ERROR, threshold in percentage should be non-empty and "
    "under 100.";
constexpr char NvmeWearLevelRoutine::kNvmeWearLevelRoutineGetInfoError[] =
    "Wear-level status: ERROR, cannot get wear level info.";
constexpr char NvmeWearLevelRoutine::kNvmeWearLevelRoutineFailed[] =
    "Wear-level status: FAILED, exceed the limitation value.";
constexpr char NvmeWearLevelRoutine::kNvmeWearLevelRoutineSuccess[] =
    "Wear-level status: PASS.";

// Page ID 202 is Dell specific for NVMe wear level status.
constexpr uint32_t NvmeWearLevelRoutine::kNvmeLogPageId = 202;
constexpr uint32_t NvmeWearLevelRoutine::kNvmeLogDataLength = 16;
constexpr bool NvmeWearLevelRoutine::kNvmeLogRawBinary = true;

NvmeWearLevelRoutine::NvmeWearLevelRoutine(
    org::chromium::debugdProxyInterface* debugd_proxy,
    const std::optional<uint32_t>& wear_level_threshold)
    : debugd_proxy_(debugd_proxy), wear_level_threshold_(wear_level_threshold) {
  DCHECK(debugd_proxy_);
}

NvmeWearLevelRoutine::~NvmeWearLevelRoutine() = default;

void NvmeWearLevelRoutine::Start() {
  if (!wear_level_threshold_.has_value()) {
    LOG(ERROR) << "Threshold value is null. "
                  "Be sure to provide one if not set in cros-config.";
    UpdateStatusWithProgressPercent(mojom::DiagnosticRoutineStatusEnum::kError,
                                    /*percent=*/100,
                                    kNvmeWearLevelRoutineThresholdError);
    return;
  }

  if (wear_level_threshold_.value() >= 100) {
    LOG(ERROR) << "Invalid threshold value (valid: 0-99): "
               << wear_level_threshold_.value();
    UpdateStatusWithProgressPercent(mojom::DiagnosticRoutineStatusEnum::kError,
                                    /*percent=*/100,
                                    kNvmeWearLevelRoutineThresholdError);
    return;
  }

  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kRunning, "");

  auto result_callback =
      base::BindOnce(&NvmeWearLevelRoutine::OnDebugdResultCallback,
                     weak_ptr_routine_.GetWeakPtr());
  auto error_callback =
      base::BindOnce(&NvmeWearLevelRoutine::OnDebugdErrorCallback,
                     weak_ptr_routine_.GetWeakPtr());
  debugd_proxy_->NvmeLogAsync(/*page_id=*/kNvmeLogPageId,
                              /*length=*/kNvmeLogDataLength,
                              /*raw_binary=*/kNvmeLogRawBinary,
                              std::move(result_callback),
                              std::move(error_callback));
}

// The wear-level check can only be started.
void NvmeWearLevelRoutine::Resume() {}
void NvmeWearLevelRoutine::Cancel() {}

void NvmeWearLevelRoutine::UpdateStatusWithProgressPercent(
    mojom::DiagnosticRoutineStatusEnum status,
    uint32_t percent,
    std::string msg) {
  UpdateStatus(status, std::move(msg));
  percent_ = percent;
}

void NvmeWearLevelRoutine::PopulateStatusUpdate(mojom::RoutineUpdate* response,
                                                bool include_output) {
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

void NvmeWearLevelRoutine::OnDebugdResultCallback(const std::string& result) {
  base::Value::Dict result_dict;
  result_dict.Set("rawData", result);
  output_dict_.Set("resultDetails", std::move(result_dict));
  std::string decoded_output;

  if (!base::Base64Decode(result, &decoded_output)) {
    LOG(ERROR) << "Base64 decoding failed. Base64 data: " << result;
    UpdateStatusWithProgressPercent(mojom::DiagnosticRoutineStatusEnum::kError,
                                    /*percent=*/100,
                                    kNvmeWearLevelRoutineGetInfoError);
    return;
  }

  if (decoded_output.length() != kNvmeLogDataLength) {
    LOG(ERROR) << "String size is not as expected(" << kNvmeLogDataLength
               << "). Size: " << decoded_output.length();
    UpdateStatusWithProgressPercent(mojom::DiagnosticRoutineStatusEnum::kError,
                                    /*percent=*/100,
                                    kNvmeWearLevelRoutineGetInfoError);
    return;
  }

  const uint32_t level = static_cast<uint32_t>(decoded_output[5]);

  if (level >= wear_level_threshold_) {
    LOG(INFO) << "Wear level status is higher than threshold. Level: " << level
              << ", threshold: " << wear_level_threshold_.value();
    UpdateStatusWithProgressPercent(mojom::DiagnosticRoutineStatusEnum::kFailed,
                                    /*percent=*/100,
                                    kNvmeWearLevelRoutineFailed);
    return;
  }

  UpdateStatusWithProgressPercent(mojom::DiagnosticRoutineStatusEnum::kPassed,
                                  /*percent=*/100,
                                  kNvmeWearLevelRoutineSuccess);
}

void NvmeWearLevelRoutine::OnDebugdErrorCallback(brillo::Error* error) {
  if (error) {
    LOG(ERROR) << "Debugd error: " << error->GetMessage();
    UpdateStatusWithProgressPercent(mojom::DiagnosticRoutineStatusEnum::kError,
                                    /*percent=*/100, error->GetMessage());
  }
}

}  // namespace diagnostics
