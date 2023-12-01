// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/emmc_lifetime/emmc_lifetime.h"

#include <cstdint>
#include <memory>
#include <sstream>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/json/json_writer.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <debugd/dbus-proxies.h>
#include <re2/re2.h>

#include "diagnostics/base/mojo_utils.h"
#include "diagnostics/cros_healthd/system/debugd_constants.h"

namespace diagnostics {

namespace {

// Regex used to parse mmc output.
inline constexpr LazyRE2 kMmcExtCsdFieldPreEolInfoRegex = {
    R"(\[PRE_EOL_INFO:\s+(0x[0-9a-fA-F]+)\])"};
inline constexpr LazyRE2 kMmcExtCsdFieldDeviceLifeTimeEstTypARegex = {
    R"(\[DEVICE_LIFE_TIME_EST_TYP_A:\s+(0x[0-9a-fA-F]+)\])"};
inline constexpr LazyRE2 kMmcExtCsdFieldDeviceLifeTimeEstTypBRegex = {
    R"(\[DEVICE_LIFE_TIME_EST_TYP_B:\s+(0x[0-9a-fA-F]+)\])"};

// Normal value for Pre-EOL Info.
inline uint8_t kMmcExtCsdFieldPreEolInfoNormal = 0x01;

bool MatchAndSet(const std::string& line,
                 const LazyRE2& re,
                 uint32_t* target,
                 bool* flag) {
  std::string str_value;
  if (RE2::PartialMatch(line, *re, &str_value) &&
      base::HexStringToUInt(str_value, target)) {
    *flag = true;
    return true;
  }
  return false;
}

// A scraper that is coupled to the format of `mmc extcsd read <drive>`.
// Sample output:
//  =============================================
//    Extended CSD rev 1.8 (MMC 5.1)
//  =============================================
//
//  Card Supported Command sets [S_CMD_SET: 0x01]
//  HPI Features [HPI_FEATURE: 0x01]: implementation based on CMD13
// (...omitted)
//  Device life time estimation type B [DEVICE_LIFE_TIME_EST_TYP_B: 0x05]
//   i.e. 40% - 50% device life time used
//  Device life time estimation type A [DEVICE_LIFE_TIME_EST_TYP_A: 0x05]
//   i.e. 40% - 50% device life time used
//  Pre EOL information [PRE_EOL_INFO: 0x01]
//   i.e. Normal
// (...omitted)
bool ScrapeMmcAttributes(const std::string& output,
                         uint32_t* pre_eol_info,
                         uint32_t* device_life_time_est_typ_a,
                         uint32_t* device_life_time_est_typ_b) {
  bool found_pre_eol_info = false;
  bool found_device_life_time_est_typ_a = false;
  bool found_device_life_time_est_typ_b = false;
  std::stringstream sstream(output);
  std::string line;
  while (std::getline(sstream, line)) {
    if ((!found_pre_eol_info &&
         MatchAndSet(line, kMmcExtCsdFieldPreEolInfoRegex, pre_eol_info,
                     &found_pre_eol_info)) ||
        (!found_device_life_time_est_typ_a &&
         MatchAndSet(line, kMmcExtCsdFieldDeviceLifeTimeEstTypARegex,
                     device_life_time_est_typ_a,
                     &found_device_life_time_est_typ_a)) ||
        (!found_device_life_time_est_typ_b &&
         MatchAndSet(line, kMmcExtCsdFieldDeviceLifeTimeEstTypBRegex,
                     device_life_time_est_typ_b,
                     &found_device_life_time_est_typ_b))) {
      if (found_pre_eol_info && found_device_life_time_est_typ_a &&
          found_device_life_time_est_typ_b) {
        return true;
      }
    }
  }
  return false;
}

}  // namespace

namespace mojom = ::ash::cros_healthd::mojom;

EmmcLifetimeRoutine::EmmcLifetimeRoutine(
    org::chromium::debugdProxyInterface* debugd_proxy)
    : debugd_proxy_(debugd_proxy) {
  DCHECK(debugd_proxy_);
}

EmmcLifetimeRoutine::~EmmcLifetimeRoutine() = default;

void EmmcLifetimeRoutine::Start() {
  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kRunning, "");

  auto result_callback =
      base::BindOnce(&EmmcLifetimeRoutine::OnDebugdResultCallback,
                     weak_ptr_factory_.GetWeakPtr());
  auto error_callback =
      base::BindOnce(&EmmcLifetimeRoutine::OnDebugdErrorCallback,
                     weak_ptr_factory_.GetWeakPtr());
  debugd_proxy_->MmcAsync(kMmcExtcsdReadOption, std::move(result_callback),
                          std::move(error_callback));
}

// The routine can only be started.
void EmmcLifetimeRoutine::Resume() {
  LOG(INFO) << "eMMC lifetime routine does not support resume operation.";
}

void EmmcLifetimeRoutine::Cancel() {
  LOG(INFO) << "eMMC lifetime routine does not support cancel operation.";
}

void EmmcLifetimeRoutine::UpdateStatusWithProgressPercent(
    mojom::DiagnosticRoutineStatusEnum status,
    uint32_t percent,
    std::string msg) {
  UpdateStatus(status, std::move(msg));
  percent_ = percent;
}

void EmmcLifetimeRoutine::PopulateStatusUpdate(mojom::RoutineUpdate* response,
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

void EmmcLifetimeRoutine::OnDebugdResultCallback(const std::string& result) {
  uint32_t pre_eol_info;
  uint32_t device_life_time_est_typ_a;
  uint32_t device_life_time_est_typ_b;
  if (!ScrapeMmcAttributes(result, &pre_eol_info, &device_life_time_est_typ_a,
                           &device_life_time_est_typ_b)) {
    LOG(ERROR) << "Failed to parse mmc output: " << result;
    UpdateStatusWithProgressPercent(mojom::DiagnosticRoutineStatusEnum::kError,
                                    /*percent=*/100,
                                    kEmmcLifetimeRoutineParseError);
    return;
  }

  base::Value::Dict result_dict;
  result_dict.Set("PRE_EOL_INFO", static_cast<int>(pre_eol_info));
  result_dict.Set("DEVICE_LIFE_TIME_EST_TYP_A",
                  static_cast<int>(device_life_time_est_typ_a));
  result_dict.Set("DEVICE_LIFE_TIME_EST_TYP_B",
                  static_cast<int>(device_life_time_est_typ_b));
  output_dict_.Set("resultDetails", std::move(result_dict));

  if (pre_eol_info != kMmcExtCsdFieldPreEolInfoNormal) {
    LOG(ERROR) << "PRE_EOL_INFO != " << kMmcExtCsdFieldPreEolInfoNormal
               << " (i.e., not normal), got: " << pre_eol_info
               << ". DEVICE_LIFE_TIME_EST_TYP_A = "
               << device_life_time_est_typ_a
               << " and DEVICE_LIFE_TIME_EST_TYP_B = "
               << device_life_time_est_typ_b;
    UpdateStatusWithProgressPercent(
        mojom::DiagnosticRoutineStatusEnum::kFailed,
        /*percent=*/100, kEmmcLifetimeRoutinePreEolInfoAbnormalError);
    return;
  }
  LOG(INFO) << "PRE_EOL_INFO == " << kMmcExtCsdFieldPreEolInfoNormal
            << " (i.e., normal) with DEVICE_LIFE_TIME_EST_TYP_A = "
            << device_life_time_est_typ_a
            << " and DEVICE_LIFE_TIME_EST_TYP_B = "
            << device_life_time_est_typ_b;
  UpdateStatusWithProgressPercent(mojom::DiagnosticRoutineStatusEnum::kPassed,
                                  /*percent=*/100, kEmmcLifetimeRoutineSuccess);
}

void EmmcLifetimeRoutine::OnDebugdErrorCallback(brillo::Error* error) {
  if (error == nullptr) {
    LOG(ERROR) << "DebugdErrorCallback invoked with null error.";
  } else {
    LOG(ERROR) << "Debugd error: " << error->GetMessage();
  }

  UpdateStatusWithProgressPercent(mojom::DiagnosticRoutineStatusEnum::kError,
                                  /*percent=*/100,
                                  kEmmcLifetimeRoutineDebugdError);
}

}  // namespace diagnostics
