// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/smartctl_check/smartctl_check.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <base/base64.h>
#include <base/check.h>
#include <base/json/json_writer.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_split.h>
#include <debugd/dbus-proxies.h>
#include <re2/re2.h>

#include "diagnostics/base/mojo_utils.h"

namespace diagnostics {

namespace {

constexpr char kPercentStringRegex[] = R"((\d+)%)";

// A scraper that is coupled to the format of smartctl -A.
// Sample output:
//   smartctl 7.1 2019-12-30 r5022 (...truncated)
//   Copyright (C) 2002-19, Bruce Allen, Christian Franke, www.smartmontools.org
//
//   === START OF SMART DATA SECTION ===
//   SMART/Health Information (NVMe Log 0x02)
//   Critical Warning:                   0x00
//   Temperature:                        47 Celsius
//   Available Spare:                    100%
//   Available Spare Threshold:          5%
//   Percentage Used:                    86%
//   Data Units Read:                    213,587,518 [109 TB]
//   Data Units Written:                 318,929,637 [163 TB]
//   (...truncated)
bool ScrapeSmartctlAttributes(const std::string& output,
                              int* available_spare,
                              int* available_spare_threshold,
                              int* percentage_used,
                              int* critical_warning) {
  bool found_available_spare = false;
  bool found_available_spare_threshold = false;
  bool found_percentage_used = false;
  bool found_critical_warning = false;
  base::StringPairs pairs;
  base::SplitStringIntoKeyValuePairs(output, ':', '\n', &pairs);
  for (const auto& pair : pairs) {
    const std::string& key = pair.first;
    const base::StringPiece& value_str =
        base::TrimWhitespaceASCII(pair.second, base::TRIM_ALL);
    if (key == "Available Spare") {
      found_available_spare |= RE2::FullMatch(
          std::string(value_str), kPercentStringRegex, available_spare);
    } else if (key == "Available Spare Threshold") {
      found_available_spare_threshold |=
          RE2::FullMatch(std::string(value_str), kPercentStringRegex,
                         available_spare_threshold);
    } else if (key == "Percentage Used") {
      found_percentage_used |= RE2::FullMatch(
          std::string(value_str), kPercentStringRegex, percentage_used);
    } else if (key == "Critical Warning") {
      found_critical_warning |=
          base::HexStringToInt(value_str, critical_warning);
    } else {
      continue;
    }

    if (found_available_spare && found_available_spare_threshold &&
        found_percentage_used && found_critical_warning) {
      return true;
    }
  }
  return false;
}

}  // namespace

namespace mojom = ::ash::cros_healthd::mojom;

// Max and min value of "Percentage Used", used to validate input threshold.
// According to NVMe spec, this value is allowed to exceed 100, and values
// greater than 254 shall be represented as 255.
constexpr uint32_t SmartctlCheckRoutine::kPercentageUsedMax = 255;
constexpr uint32_t SmartctlCheckRoutine::kPercentageUsedMin = 0;
// The value defined in spec when there is no critical warning.
constexpr uint32_t SmartctlCheckRoutine::kCriticalWarningNone = 0x00;

SmartctlCheckRoutine::SmartctlCheckRoutine(
    org::chromium::debugdProxyInterface* debugd_proxy,
    const std::optional<uint32_t>& percentage_used_threshold)
    : debugd_proxy_(debugd_proxy) {
  DCHECK(debugd_proxy_);
  if (percentage_used_threshold.has_value()) {
    percentage_used_threshold_ = percentage_used_threshold.value();
  } else {
    LOG(INFO)
        << "percentage_used_threshold is empty. Default to the maximum value ("
        << kPercentageUsedMax << ")";
    percentage_used_threshold_ = kPercentageUsedMax;
  }
}

SmartctlCheckRoutine::~SmartctlCheckRoutine() = default;

void SmartctlCheckRoutine::Start() {
  if (percentage_used_threshold_ > kPercentageUsedMax ||
      percentage_used_threshold_ < kPercentageUsedMin) {
    LOG(ERROR) << "Invalid threshold value (valid: 0-255): "
               << percentage_used_threshold_;
    UpdateStatusWithProgressPercent(mojom::DiagnosticRoutineStatusEnum::kError,
                                    /*percent=*/100,
                                    kSmartctlCheckRoutineThresholdError);
    return;
  }

  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kRunning, "");

  auto result_callback =
      base::BindOnce(&SmartctlCheckRoutine::OnDebugdResultCallback,
                     weak_ptr_routine_.GetWeakPtr());
  auto error_callback =
      base::BindOnce(&SmartctlCheckRoutine::OnDebugdErrorCallback,
                     weak_ptr_routine_.GetWeakPtr());
  debugd_proxy_->SmartctlAsync("attributes", std::move(result_callback),
                               std::move(error_callback));
}

// The routine can only be started.
void SmartctlCheckRoutine::Resume() {}
void SmartctlCheckRoutine::Cancel() {}

void SmartctlCheckRoutine::UpdateStatusWithProgressPercent(
    mojom::DiagnosticRoutineStatusEnum status,
    uint32_t percent,
    std::string msg) {
  UpdateStatus(status, std::move(msg));
  percent_ = percent;
}

void SmartctlCheckRoutine::PopulateStatusUpdate(mojom::RoutineUpdate* response,
                                                bool include_output) {
  auto status = GetStatus();

  auto update = mojom::NonInteractiveRoutineUpdate::New();
  update->status = status;
  update->status_message = GetStatusMessage();

  response->routine_update_union =
      mojom::RoutineUpdateUnion::NewNoninteractiveUpdate(std::move(update));
  response->progress_percent = percent_;

  if (include_output && !output_dict_.empty() &&
      (status == mojom::DiagnosticRoutineStatusEnum::kPassed ||
       status == mojom::DiagnosticRoutineStatusEnum::kFailed)) {
    std::string json;
    base::JSONWriter::Write(output_dict_, &json);
    response->output =
        CreateReadOnlySharedMemoryRegionMojoHandle(base::StringPiece(json));
  }
}

void SmartctlCheckRoutine::OnDebugdResultCallback(const std::string& result) {
  int available_spare;
  int available_spare_threshold;
  int percentage_used;
  int critical_warning;
  if (!ScrapeSmartctlAttributes(result, &available_spare,
                                &available_spare_threshold, &percentage_used,
                                &critical_warning)) {
    LOG(ERROR) << "Unable to parse smartctl output: " << result;
    // TODO(b/260956052): Make the routine only available to NVMe, and return
    // kError in the parsing error.
    UpdateStatusWithProgressPercent(mojom::DiagnosticRoutineStatusEnum::kFailed,
                                    /*percent=*/100,
                                    kSmartctlCheckRoutineFailedToParse);
    return;
  }

  base::Value::Dict result_dict;
  result_dict.Set("availableSpare", available_spare);
  result_dict.Set("availableSpareThreshold", available_spare_threshold);
  result_dict.Set("percentageUsed", percentage_used);
  result_dict.Set("inputPercentageUsedThreshold",
                  static_cast<int>(percentage_used_threshold_));
  result_dict.Set("criticalWarning", critical_warning);
  output_dict_.Set("resultDetails", std::move(result_dict));

  const bool available_spare_check_passed =
      available_spare >= available_spare_threshold;
  const bool percentage_used_check_passed =
      percentage_used <= percentage_used_threshold_;
  const bool critical_warning_check_passed =
      critical_warning == kCriticalWarningNone;
  if (!available_spare_check_passed || !percentage_used_check_passed ||
      !critical_warning_check_passed) {
    LOG(ERROR) << "One or more checks failed. Result - available_spare check: "
               << available_spare_check_passed
               << ", percentage_used check: " << percentage_used_check_passed
               << ", critical_warning check: " << critical_warning_check_passed;
    UpdateStatusWithProgressPercent(mojom::DiagnosticRoutineStatusEnum::kFailed,
                                    /*percent=*/100,
                                    kSmartctlCheckRoutineCheckFailed);
    return;
  }
  UpdateStatusWithProgressPercent(mojom::DiagnosticRoutineStatusEnum::kPassed,
                                  /*percent=*/100,
                                  kSmartctlCheckRoutineSuccess);
}

void SmartctlCheckRoutine::OnDebugdErrorCallback(brillo::Error* error) {
  if (error) {
    LOG(ERROR) << "Debugd error: " << error->GetMessage();
    UpdateStatusWithProgressPercent(mojom::DiagnosticRoutineStatusEnum::kError,
                                    /*percent=*/100,
                                    kSmartctlCheckRoutineDebugdError);
  }
}

}  // namespace diagnostics
