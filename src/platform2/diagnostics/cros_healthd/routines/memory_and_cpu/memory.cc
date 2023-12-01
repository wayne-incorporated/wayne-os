// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/memory_and_cpu/memory.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/json/json_writer.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <re2/re2.h>

#include "diagnostics/base/mojo_utils.h"
#include "diagnostics/cros_healthd/routines/memory_and_cpu/constants.h"
#include "diagnostics/cros_healthd/utils/memory_info.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

// Approximate number of microseconds per byte of memory tested. Derived from
// testing on a nami device.
constexpr double kMicrosecondsPerByte = 0.20;

// Regex to parse out the version of memtester used.
constexpr char kMemtesterVersionRegex[] = R"(memtester version (.+))";
// Regex to parse out the amount of memory tested.
constexpr char kMemtesterBytesTestedRegex[] = R"(got  \d+MB \((\d+) bytes\))";
// Regex to parse out a particular subtest and its result.
constexpr char kMemtesterSubtestRegex[] = R"((.+)\s*: (.+))";
// Failure messages in subtests will begin with this pattern.
constexpr char kMemtesterSubtestFailurePattern[] = "FAILURE:";

// Takes a |raw_string|, potentially with backspace characters ('\b'), and
// processes the backspaces in the string like the console would. For example,
// if |raw_string| was "Hello, Worlb\bd\n", this function would return
// "Hello, World\n". This function operates a single character at a time, and
// should only be used for small inputs.
std::string ProcessBackspaces(const std::string& raw_string) {
  std::string processed;
  for (const char& c : raw_string) {
    if (c == '\b') {
      // std::string::pop_back() causes undefined behavior if the string is
      // empty. We never expect to call this method on an empty string - that
      // would indicate |raw_string| was invalid.
      DCHECK(!processed.empty());
      processed.pop_back();
    } else {
      processed.push_back(c);
    }
  }

  return processed;
}

}  // namespace

MemoryRoutine::MemoryRoutine(Context* context,
                             const base::TickClock* tick_clock)
    : context_(context) {
  DCHECK(context_);

  if (tick_clock) {
    tick_clock_ = tick_clock;
  } else {
    default_tick_clock_ = std::make_unique<base::DefaultTickClock>();
    tick_clock_ = default_tick_clock_.get();
  }
  DCHECK(tick_clock_);
}

MemoryRoutine::~MemoryRoutine() = default;

void MemoryRoutine::Start() {
  DCHECK_EQ(GetStatus(), mojom::DiagnosticRoutineStatusEnum::kReady);

  auto memory_info = MemoryInfo::ParseFrom(context_->root_dir());
  if (!memory_info.has_value()) {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kFailedToStart,
                 kMemoryRoutineFetchingAvailableMemoryFailureMessage);
    return;
  }
  uint32_t available_mem_kib = memory_info.value().available_memory_kib;

  // Ealry check and return if system doesn't have enough memory remains.
  if (available_mem_kib <= kCpuMemoryRoutineReservedSizeKiB) {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kFailedToStart,
                 kMemoryRoutineNotHavingEnoughAvailableMemoryMessage);
    return;
  }

  // Estimate the routine's duration based on the amount of free memory.
  expected_duration_us_ = available_mem_kib * 1024 * kMicrosecondsPerByte;
  start_ticks_ = tick_clock_->NowTicks();

  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kRunning,
               kMemoryRoutineRunningMessage);
  context_->executor()->RunMemtester(
      available_mem_kib - kCpuMemoryRoutineReservedSizeKiB,
      base::BindOnce(&MemoryRoutine::DetermineRoutineResult,
                     weak_ptr_factory_.GetWeakPtr()));
}

// The memory routine cannot be resumed.
void MemoryRoutine::Resume() {}

void MemoryRoutine::Cancel() {
  // Only cancel if the routine is running.
  if (GetStatus() != mojom::DiagnosticRoutineStatusEnum::kRunning)
    return;

  // Make sure any other callbacks won't run - they would override the state
  // and status message.
  weak_ptr_factory_.InvalidateWeakPtrs();

  context_->executor()->KillMemtester();
  UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kCancelled,
               kMemoryRoutineCancelledMessage);
}

void MemoryRoutine::PopulateStatusUpdate(mojom::RoutineUpdate* response,
                                         bool include_output) {
  DCHECK(response);
  auto status = GetStatus();

  // Because the memory routine is non-interactive, we will never include a user
  // message.
  auto update = mojom::NonInteractiveRoutineUpdate::New();
  update->status = status;
  update->status_message = GetStatusMessage();

  response->routine_update_union =
      mojom::RoutineUpdateUnion::NewNoninteractiveUpdate(std::move(update));

  if (include_output && !output_dict_.empty()) {
    std::string json;
    base::JSONWriter::Write(output_dict_, &json);
    response->output =
        CreateReadOnlySharedMemoryRegionMojoHandle(base::StringPiece(json));
  }

  // If the routine has finished, set the progress percent to 100 and don't take
  // the amount of time ran into account.
  if (status == mojom::DiagnosticRoutineStatusEnum::kPassed ||
      status == mojom::DiagnosticRoutineStatusEnum::kFailed) {
    response->progress_percent = 100;
    return;
  }

  if (status == mojom::DiagnosticRoutineStatusEnum::kReady ||
      status == mojom::DiagnosticRoutineStatusEnum::kFailedToStart ||
      expected_duration_us_ <= 0) {
    // The routine has not started.
    response->progress_percent = 0;
    return;
  }

  // Cap the progress at 99, in case it's taking longer than the estimated
  // time.
  base::TimeDelta elapsed_time = tick_clock_->NowTicks() - start_ticks_;
  response->progress_percent =
      std::min<int64_t>(99, static_cast<int64_t>(elapsed_time.InMicroseconds() /
                                                 expected_duration_us_ * 100));
}

void MemoryRoutine::DetermineRoutineResult(
    mojom::ExecutedProcessResultPtr process) {
  ParseMemtesterOutput(process->out);

  int32_t ret = process->return_code;
  if (ret == EXIT_SUCCESS) {
    UpdateStatus(mojom::DiagnosticRoutineStatusEnum::kPassed,
                 kMemoryRoutineSucceededMessage);
    return;
  }

  auto status = mojom::DiagnosticRoutineStatusEnum::kFailed;
  std::string status_message;
  if (ret & MemtesterErrorCodes::kAllocatingLockingInvokingError) {
    // Return the error message from executor if applicable
    status_message +=
        !process->err.empty()
            ? process->err
            : kMemoryRoutineAllocatingLockingInvokingFailureMessage;
    status = mojom::DiagnosticRoutineStatusEnum::kError;
  }

  if (ret & MemtesterErrorCodes::kStuckAddressTestError)
    status_message += kMemoryRoutineStuckAddressTestFailureMessage;

  if (ret & MemtesterErrorCodes::kOtherTestError)
    status_message += kMemoryRoutineOtherTestFailureMessage;

  UpdateStatus(status, std::move(status_message));
}

void MemoryRoutine::ParseMemtesterOutput(const std::string& raw_output) {
  std::vector<std::string> lines = base::SplitString(
      raw_output, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  // The following strings are used to hold values matched from regexes.
  std::string version;
  std::string bytes_tested_str;
  std::string subtest_name;
  std::string subtest_result;
  // Holds the integer value for the number of bytes tested, converted from
  // |bytes_tested_str|.
  uint64_t bytes_tested;
  // Holds the results of all subtests.
  base::Value::Dict subtest_dict;
  // Holds all the parsed output from memtester.
  base::Value::Dict result_dict;
  for (int index = 0; index < lines.size(); index++) {
    std::string line = ProcessBackspaces(lines[index]);

    if (RE2::FullMatch(line, kMemtesterVersionRegex, &version)) {
      result_dict.Set("memtesterVersion", version);
    } else if (RE2::PartialMatch(line, kMemtesterBytesTestedRegex,
                                 &bytes_tested_str) &&
               base::StringToUint64(bytes_tested_str, &bytes_tested)) {
      // Use string here since |base::Value| does not support uint64_t.
      result_dict.Set("bytesTested", base::NumberToString(bytes_tested));
    } else if (RE2::FullMatch(line, kMemtesterSubtestRegex, &subtest_name,
                              &subtest_result) &&
               !base::StartsWith(line, kMemtesterSubtestFailurePattern,
                                 base::CompareCase::SENSITIVE)) {
      // Process |subtest_name| so it's formatted like a JSON key - remove
      // spaces and make sure the first letter is lowercase. For example, Stuck
      // Address should become stuckAddress.
      base::RemoveChars(subtest_name, " ", &subtest_name);
      subtest_name[0] = std::tolower(subtest_name[0]);

      subtest_dict.Set(subtest_name, subtest_result);
    }
  }

  if (!subtest_dict.empty())
    result_dict.Set("subtests", std::move(subtest_dict));
  if (!result_dict.empty())
    output_dict_.Set("resultDetails", std::move(result_dict));
}

}  // namespace diagnostics
