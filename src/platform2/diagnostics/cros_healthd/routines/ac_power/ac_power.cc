// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/ac_power/ac_power.h"

#include <optional>
#include <utility>

#include <base/check_op.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_util.h>

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

// Path to the power_supply directory. All subdirectories will be searched to
// try and find the path to a connected AC adapter.
constexpr char kPowerSupplyDirectoryPath[] = "sys/class/power_supply";
// Names of the two files read by the AC power routine.
constexpr char kOnlineFileName[] = "online";
constexpr char kTypeFileName[] = "type";

// POD struct which holds the whitespace-trimmed contents of the online and type
// files for the power supply under test.
struct PowerSupplyFileContents {
  std::string online;  // Whitespace-trimmed contents of the online file.
  std::string type;    // Whitespace-trimmed contents of the type file.
};

}  // namespace

const char kAcPowerRoutineSucceededMessage[] = "AC Power routine passed.";
const char kAcPowerRoutineFailedNotOnlineMessage[] =
    "Expected online power supply, found offline power supply.";
const char kAcPowerRoutineFailedNotOfflineMessage[] =
    "Expected offline power supply, found online power supply.";
const char kAcPowerRoutineFailedMismatchedPowerTypesMessage[] =
    "Read power type different from expected power type.";
const char kAcPowerRoutineNoValidPowerSupplyMessage[] =
    "No valid AC power supply found.";
const char kAcPowerRoutineCancelledMessage[] = "AC Power routine cancelled.";

// We want a value here that is greater than zero to show that the routine has
// started. But it hasn't really done any work, so the value shouldn't be too
// high.
const uint32_t kAcPowerRoutineWaitingProgressPercent = 33;

AcPowerRoutine::AcPowerRoutine(
    mojom::AcPowerStatusEnum expected_status,
    const std::optional<std::string>& expected_power_type,
    const base::FilePath& root_dir)
    : expected_power_status_(expected_status),
      expected_power_type_(expected_power_type),
      root_dir_(root_dir) {}

AcPowerRoutine::~AcPowerRoutine() = default;

void AcPowerRoutine::Start() {
  DCHECK_EQ(GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);
  // Transition to waiting so the user can plug or unplug the AC adapter as
  // necessary.
  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kWaiting, "");
  CalculateProgressPercent();
}

void AcPowerRoutine::Resume() {
  DCHECK_EQ(GetStatus(), mojom::DiagnosticRoutineStatusEnum::kWaiting);
  RunAcPowerRoutine();
  if (GetStatus() != mojom::DiagnosticRoutineStatusEnum::kPassed)
    LOG(ERROR) << "Routine failed: " << GetStatusMessage();
}

void AcPowerRoutine::Cancel() {
  // Only cancel the routine if it's in the waiting state. Otherwise, it either
  // hasn't begun or has already finished.
  if (GetStatus() == mojom::DiagnosticRoutineStatusEnum::kWaiting) {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kCancelled,
                 kAcPowerRoutineCancelledMessage);
  }
}

void AcPowerRoutine::PopulateStatusUpdate(mojom::RoutineUpdate* response,
                                          bool include_output) {
  auto status = GetStatus();
  if (status == mojom::DiagnosticRoutineStatusEnum::kWaiting) {
    auto interactive_update = mojom::InteractiveRoutineUpdate::New();
    interactive_update->user_message =
        (expected_power_status_ == mojom::AcPowerStatusEnum::kConnected)
            ? mojom::DiagnosticRoutineUserMessageEnum::kPlugInACPower
            : mojom::DiagnosticRoutineUserMessageEnum::kUnplugACPower;
    response->routine_update_union =
        mojom::RoutineUpdateUnion::NewInteractiveUpdate(
            std::move(interactive_update));
  } else {
    auto noninteractive_update = mojom::NonInteractiveRoutineUpdate::New();
    noninteractive_update->status = status;
    noninteractive_update->status_message = GetStatusMessage();

    response->routine_update_union =
        mojom::RoutineUpdateUnion::NewNoninteractiveUpdate(
            std::move(noninteractive_update));
  }

  CalculateProgressPercent();
  response->progress_percent = progress_percent_;
}

void AcPowerRoutine::CalculateProgressPercent() {
  auto status = GetStatus();
  // If the routine has been started and is waiting, assign a reasonable
  // progress percentage that signifies the routine has been started.
  if (status == mojom::DiagnosticRoutineStatusEnum::kWaiting) {
    progress_percent_ = kAcPowerRoutineWaitingProgressPercent;
  } else if (status == mojom::DiagnosticRoutineStatusEnum::kPassed ||
             status == mojom::DiagnosticRoutineStatusEnum::kFailed) {
    // The routine has finished, so report 100.
    progress_percent_ = 100;
  }
}

void AcPowerRoutine::RunAcPowerRoutine() {
  base::FileEnumerator dir_enumerator(
      root_dir_.AppendASCII(kPowerSupplyDirectoryPath),
      false /* is_recursive */,
      base::FileEnumerator::SHOW_SYM_LINKS | base::FileEnumerator::FILES |
          base::FileEnumerator::DIRECTORIES);

  PowerSupplyFileContents contents;
  bool valid_path_found = false;
  for (base::FilePath path = dir_enumerator.Next(); !path.empty();
       path = dir_enumerator.Next()) {
    // Skip all power supplies of unknown type.
    std::string type;
    if (!base::ReadFileToString(path.AppendASCII(kTypeFileName), &type)) {
      continue;
    }

    // Skip all batteries.
    base::TrimWhitespaceASCII(type, base::TRIM_ALL, &type);
    if (type == "Battery")
      continue;

    // Skip all power supplies which don't populate the online file.
    std::string online;
    if (!base::ReadFileToString(path.AppendASCII(kOnlineFileName), &online))
      continue;

    // If we found an online power supply, then that's the power supply we wish
    // to test.
    base::TrimWhitespaceASCII(online, base::TRIM_ALL, &online);
    if (online == "1") {
      valid_path_found = true;
      contents.online = online;
      contents.type = type;
      break;
    }

    // If we have an offline power supply, but haven't found any online power
    // supplies, then we have a candidate for power supply to test.
    if (!valid_path_found) {
      valid_path_found = true;
      contents.online = online;
      contents.type = type;
    }
  }

  if (!valid_path_found) {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kError,
                 kAcPowerRoutineNoValidPowerSupplyMessage);
    return;
  }

  // Test the contents of the path's online file against the input value.
  if (expected_power_status_ == mojom::AcPowerStatusEnum::kConnected &&
      contents.online != "1") {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kFailed,
                 kAcPowerRoutineFailedNotOnlineMessage);
    return;
  } else if (expected_power_status_ ==
                 mojom::AcPowerStatusEnum::kDisconnected &&
             contents.online != "0") {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kFailed,
                 kAcPowerRoutineFailedNotOfflineMessage);
    return;
  }

  // Test the contents of the path's type file against the input value. This is
  // an optional test, and won't be performed if |expected_power_type_| wasn't
  // specified.
  if (expected_power_type_.has_value() &&
      expected_power_type_.value() != contents.type) {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kFailed,
                 kAcPowerRoutineFailedMismatchedPowerTypesMessage);
    return;
  }

  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kPassed,
               kAcPowerRoutineSucceededMessage);
}

}  // namespace diagnostics
