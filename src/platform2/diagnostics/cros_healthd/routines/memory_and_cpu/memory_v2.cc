// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/memory_and_cpu/memory_v2.h"

#include <algorithm>
#include <cstdint>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file.h>
#include <base/files/platform_file.h>
#include <base/strings/string_number_conversions.h>
#include <base/time/time.h>
#include <re2/re2.h>

#include "diagnostics/cros_healthd/executor/utils/scoped_process_control.h"
#include "diagnostics/cros_healthd/routines/memory_and_cpu/constants.h"
#include "diagnostics/cros_healthd/utils/callback_barrier.h"
#include "diagnostics/cros_healthd/utils/memory_info.h"
#include "diagnostics/cros_healthd/utils/mojo_utils.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

// The minimum required memory in KiB for memtester to run successfully.
constexpr uint32_t kMemoryRoutineMinimumRequireKiB = 4;
// Regex to parse out the amount of memory tested. An example input would be:
//
// got  100MB (104857600 bytes)
constexpr char kMemtesterBytesTestedRegex[] = R"(got  \d+MB \((\d+) bytes\))";
// Regex to parse out a particular subtest name. An example input would be:
//
// Compare XOR :
constexpr char kMemtesterSubtestRegex[] = R"(^([^:]+?)\s*: )";
// A substring that exists only in failed memtester subtest.
constexpr char kMemtesterSubtestFailureSubstring[] = "FAILURE:";
// A substring that exists only in successful memtester subtest.
constexpr char kMemtesterSubtestSuccessSubstring[] = "ok";
// A regex to help parse the current progress iteration.
constexpr char kMemtesterSubtestProgressRegex[] =
    R"((?:testing|setting)\s*(\d+))";
// Buffer size for reading from file.
constexpr size_t kBufSize = 1024;

// Matches the subtest name and transform it into the corresponding subtest
// enum.
mojom::MemtesterTestItemEnum SubtestNameToEnum(
    const std::string& subtest_name) {
  if (subtest_name == "StuckAddress") {
    return mojom::MemtesterTestItemEnum::kStuckAddress;
  } else if (subtest_name == "CompareAND") {
    return mojom::MemtesterTestItemEnum::kCompareAND;
  } else if (subtest_name == "CompareDIV") {
    return mojom::MemtesterTestItemEnum::kCompareDIV;
  } else if (subtest_name == "CompareMUL") {
    return mojom::MemtesterTestItemEnum::kCompareMUL;
  } else if (subtest_name == "CompareOR") {
    return mojom::MemtesterTestItemEnum::kCompareOR;
  } else if (subtest_name == "CompareSUB") {
    return mojom::MemtesterTestItemEnum::kCompareSUB;
  } else if (subtest_name == "CompareXOR") {
    return mojom::MemtesterTestItemEnum::kCompareXOR;
  } else if (subtest_name == "SequentialIncrement") {
    return mojom::MemtesterTestItemEnum::kSequentialIncrement;
  } else if (subtest_name == "BitFlip") {
    return mojom::MemtesterTestItemEnum::kBitFlip;
  } else if (subtest_name == "BitSpread") {
    return mojom::MemtesterTestItemEnum::kBitSpread;
  } else if (subtest_name == "BlockSequential") {
    return mojom::MemtesterTestItemEnum::kBlockSequential;
  } else if (subtest_name == "Checkerboard") {
    return mojom::MemtesterTestItemEnum::kCheckerboard;
  } else if (subtest_name == "RandomValue") {
    return mojom::MemtesterTestItemEnum::kRandomValue;
  } else if (subtest_name == "SolidBits") {
    return mojom::MemtesterTestItemEnum::kSolidBits;
  } else if (subtest_name == "WalkingOnes") {
    return mojom::MemtesterTestItemEnum::kWalkingOnes;
  } else if (subtest_name == "WalkingZeroes") {
    return mojom::MemtesterTestItemEnum::kWalkingZeroes;
  } else if (subtest_name == "8-bitWrites") {
    // This test is enabled at compile time and should not be executed by the
    // Chrome OS memtester binary.
    LOG(WARNING) << "Unexpected subtest name in memtester: " << subtest_name;
    return mojom::MemtesterTestItemEnum::k8BitWrites;
  } else if (subtest_name == "16-bitWrites") {
    // This test is enabled at compile time and should not be executed by the
    // Chrome OS memtester binary.
    LOG(WARNING) << "Unexpected subtest name in memtester: " << subtest_name;
    return mojom::MemtesterTestItemEnum::k16BitWrites;
  }
  LOG(ERROR) << "Unknown subtest name: " << subtest_name;
  return mojom::MemtesterTestItemEnum::kUnknown;
}

// Stores information for each subtest that help determines the progress.
struct SubtestProgressInfo {
  // The percentage time that have elapsed up until this subtest.
  int cumulative_percentage;
  // The percentage time running this subtest should take.
  int subtest_percentage;
  // The number of iterations this subtest will run if applicable.
  std::optional<int32_t> max_iterations;
};

// Matches the subtest enum and returns the corresponding info regarding
// cumulative progress.
SubtestProgressInfo SubtestEnumToProgressInfo(
    mojom::MemtesterTestItemEnum subtest_enum) {
// memtester will run different iteration counts based on different
// ULONG_MAX value (taken directly from the memtester source code). The
// percentage are calculated from testing on sample devices, with
// ULONG_MAX == 4294967295UL on Cherry and ULONG_MAX == 18446744073709551615ULL
// on Volteer.
#if ULONG_MAX == 4294967295UL
  switch (subtest_enum) {
    case mojom::MemtesterTestItemEnum::kStuckAddress:
      return {0, 4, 16};
    case mojom::MemtesterTestItemEnum::kRandomValue:
      return {4, 8, std::nullopt};
    case mojom::MemtesterTestItemEnum::kCompareXOR:
      return {8, 0, std::nullopt};
    case mojom::MemtesterTestItemEnum::kCompareSUB:
      return {8, 0, std::nullopt};
    case mojom::MemtesterTestItemEnum::kCompareMUL:
      return {8, 0, std::nullopt};
    case mojom::MemtesterTestItemEnum::kCompareDIV:
      return {8, 0, std::nullopt};
    case mojom::MemtesterTestItemEnum::kCompareOR:
      return {8, 0, std::nullopt};
    case mojom::MemtesterTestItemEnum::kCompareAND:
      return {8, 0, std::nullopt};
    case mojom::MemtesterTestItemEnum::kSequentialIncrement:
      return {8, 0, std::nullopt};
    case mojom::MemtesterTestItemEnum::kSolidBits:
      return {8, 8, 64};
    case mojom::MemtesterTestItemEnum::kBlockSequential:
      return {16, 27, 256};
    case mojom::MemtesterTestItemEnum::kCheckerboard:
      return {43, 7, 64};
    case mojom::MemtesterTestItemEnum::kBitSpread:
      return {50, 7, 64};
    case mojom::MemtesterTestItemEnum::kBitFlip:
      return {57, 30, 256};
    case mojom::MemtesterTestItemEnum::kWalkingOnes:
      return {87, 6, 64};
    case mojom::MemtesterTestItemEnum::kWalkingZeroes:
      return {93, 7, 64};
    case mojom::MemtesterTestItemEnum::k8BitWrites:
    case mojom::MemtesterTestItemEnum::k16BitWrites:
      return {100, 0, std::nullopt};
    case mojom::MemtesterTestItemEnum::kUnmappedEnumField:
    case mojom::MemtesterTestItemEnum::kUnknown:
      LOG(ERROR) << "Unexpected subtest enum for progress information: "
                 << subtest_enum;
      return {0, 0, std::nullopt};
  }
#elif ULONG_MAX == 18446744073709551615ULL
  switch (subtest_enum) {
    case mojom::MemtesterTestItemEnum::kStuckAddress:
      return {0, 2, 16};
    case mojom::MemtesterTestItemEnum::kRandomValue:
      return {2, 2, std::nullopt};
    case mojom::MemtesterTestItemEnum::kCompareXOR:
      return {4, 0, std::nullopt};
    case mojom::MemtesterTestItemEnum::kCompareSUB:
      return {4, 0, std::nullopt};
    case mojom::MemtesterTestItemEnum::kCompareMUL:
      return {4, 0, std::nullopt};
    case mojom::MemtesterTestItemEnum::kCompareDIV:
      return {4, 0, std::nullopt};
    case mojom::MemtesterTestItemEnum::kCompareOR:
      return {4, 0, std::nullopt};
    case mojom::MemtesterTestItemEnum::kCompareAND:
      return {4, 0, std::nullopt};
    case mojom::MemtesterTestItemEnum::kSequentialIncrement:
      return {4, 0, std::nullopt};
    case mojom::MemtesterTestItemEnum::kSolidBits:
      return {4, 4, 64};
    case mojom::MemtesterTestItemEnum::kBlockSequential:
      return {8, 19, 256};
    case mojom::MemtesterTestItemEnum::kCheckerboard:
      return {27, 5, 64};
    case mojom::MemtesterTestItemEnum::kBitSpread:
      return {32, 10, 128};
    case mojom::MemtesterTestItemEnum::kBitFlip:
      return {42, 39, 512};
    case mojom::MemtesterTestItemEnum::kWalkingOnes:
      return {81, 9, 128};
    case mojom::MemtesterTestItemEnum::kWalkingZeroes:
      return {90, 10, 128};
    case mojom::MemtesterTestItemEnum::k8BitWrites:
    case mojom::MemtesterTestItemEnum::k16BitWrites:
      return {100, 0, std::nullopt};
    case mojom::MemtesterTestItemEnum::kUnmappedEnumField:
    case mojom::MemtesterTestItemEnum::kUnknown:
      LOG(ERROR) << "Unexpected subtest enum for progress information: "
                 << subtest_enum;
      return {0, 0, std::nullopt};
  }
#endif
}

}  // namespace

MemoryRoutineV2::MemoryRoutineV2(Context* context,
                                 const mojom::MemoryRoutineArgumentPtr& arg)
    : context_(context), max_testing_mem_kib_(arg->max_testing_mem_kib) {
  DCHECK(context_);
}

MemoryRoutineV2::~MemoryRoutineV2() = default;

void MemoryRoutineV2::OnStart() {
  SetWaitingState(mojom::RoutineStateWaiting::Reason::kWaitingToBeScheduled,
                  "Waiting for memory and CPU resource");
  context_->memory_cpu_resource_queue()->Enqueue(
      base::BindOnce(&MemoryRoutineV2::Run, weak_ptr_factory_.GetWeakPtr()));
}

void MemoryRoutineV2::Run(
    base::ScopedClosureRunner notify_resource_queue_finished) {
  auto memory_info = MemoryInfo::ParseFrom(context_->root_dir());
  if (!memory_info.has_value()) {
    RaiseException("Memory info not found");
    return;
  }

  uint32_t available_mem_kib = memory_info.value().available_memory_kib;

  // Early check and raise exception if system doesn't have enough memory to
  // run a basic memtester test.
  if (available_mem_kib < kMemoryRoutineMinimumRequireKiB) {
    RaiseException(
        "Less than 4 KiB memory available, not enough to run memtester.");
    return;
  }

  uint32_t testing_mem_kib = std::max(static_cast<int64_t>(0),
                                      static_cast<int64_t>(available_mem_kib) -
                                          kCpuMemoryRoutineReservedSizeKiB);
  if (max_testing_mem_kib_.has_value()) {
    testing_mem_kib = std::min(max_testing_mem_kib_.value(), testing_mem_kib);
  }
  testing_mem_kib = std::max(testing_mem_kib, kMemoryRoutineMinimumRequireKiB);

  SetRunningState();
  context_->executor()->RunMemtesterV2(
      testing_mem_kib, scoped_process_control_.BindNewPipeAndPassReceiver());
  scoped_process_control_.AddOnTerminateCallback(
      std::move(notify_resource_queue_finished));

  CallbackBarrier barrier{
      base::BindOnce(&MemoryRoutineV2::DetermineRoutineResult,
                     weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&MemoryRoutineV2::RaiseException,
                     weak_ptr_factory_.GetWeakPtr(),
                     "Error in calling memtester")};

  scoped_process_control_->GetStdout(barrier.Depend(base::BindOnce(
      &MemoryRoutineV2::SetUpStdout, weak_ptr_factory_.GetWeakPtr())));

  scoped_process_control_->GetReturnCode(barrier.Depend(base::BindOnce(
      &MemoryRoutineV2::HandleGetReturnCode, weak_ptr_factory_.GetWeakPtr())));
}

void MemoryRoutineV2::HandleGetReturnCode(int return_code) {
  memtester_return_code_ = return_code;
}

void MemoryRoutineV2::ReadNewMemtesterResult() {
  // Read and parse the new output.
  std::string output;
  char buf[kBufSize];
  int64_t offset = read_stdout_size_;
  int64_t current_stdout_size = stdout_file_.GetLength();

  // Should not happen. But just in case reset everything and reread again.
  if (current_stdout_size < offset) {
    offset = 0;
    read_stdout_size_ = 0;
    // Initialize an empty std::vector<std::vector<std::string>>.
    parsed_memtester_result_ = {{""}};
  }

  while (offset < current_stdout_size) {
    int read_len = stdout_file_.Read(
        offset, buf, std::min<int64_t>(kBufSize, current_stdout_size - offset));
    if (read_len < 0) {
      LOG(ERROR) << "Read memtester stdout unsuccessful";
      return;
    }
    offset += read_len;
    output.append(buf, read_len);
  }

  // Append a new std::vector<std::string> for each line, and
  // delimit the line by '\b' characters.
  read_stdout_size_ = current_stdout_size;
  for (const char& c : output) {
    if (c == '\n') {
      parsed_memtester_result_.emplace_back(std::vector<std::string>{""});
    } else if (c == '\r') {
      continue;
    } else if (c == '\b') {
      if (parsed_memtester_result_.back().back().length() > 0)
        parsed_memtester_result_.back().emplace_back("");
    } else {
      parsed_memtester_result_.back().back().push_back(c);
    }
  }
}

std::optional<int8_t> MemoryRoutineV2::CalculatePercentage() {
  std::string subtest_name;
  if (parsed_memtester_result_.empty() ||
      parsed_memtester_result_.back().empty()) {
    LOG(ERROR) << "Parsed memtester result should never be empty";
    return std::nullopt;
  }
  if (!RE2::PartialMatch(parsed_memtester_result_.back()[0],
                         kMemtesterSubtestRegex, &subtest_name)) {
    return std::nullopt;
  }
  // Process |subtest_name| so it's formatted without whitespace.
  // E.g. | Stuck Address | => |StuckAddress|
  base::RemoveChars(subtest_name, " ", &subtest_name);
  auto subtest_enum = SubtestNameToEnum(subtest_name);
  SubtestProgressInfo progress_info = SubtestEnumToProgressInfo(subtest_enum);

  std::string subtest_iteration_str;
  int subtest_iteration;
  if (parsed_memtester_result_.back().back().find(
          kMemtesterSubtestSuccessSubstring) != std::string::npos) {
    return progress_info.cumulative_percentage +
           progress_info.subtest_percentage;
  } else if (RE2::PartialMatch(parsed_memtester_result_.back().back(),
                               kMemtesterSubtestProgressRegex,
                               &subtest_iteration_str)) {
    if (!base::StringToInt(subtest_iteration_str, &subtest_iteration)) {
      LOG(ERROR) << "subtest progress cannot be converted to integer: "
                 << subtest_iteration_str;
      return std::nullopt;
    }
    if (progress_info.max_iterations.has_value() &&
        progress_info.max_iterations.value() > 0) {
      return progress_info.cumulative_percentage +
             (static_cast<double>(progress_info.subtest_percentage) *
              subtest_iteration / progress_info.max_iterations.value());
    }
  }
  return progress_info.cumulative_percentage;
}

void MemoryRoutineV2::UpdatePercentage() {
  // Read the new output and update the percentage if applicable.
  ReadNewMemtesterResult();

  std::optional<int8_t> percentage_opt = CalculatePercentage();
  if (percentage_opt.has_value() &&
      percentage_opt.value() > state()->percentage &&
      percentage_opt.value() < 100) {
    SetPercentage(percentage_opt.value());
  }

  if (state()->percentage < 99) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&MemoryRoutineV2::UpdatePercentage,
                       weak_ptr_factory_.GetWeakPtr()),
        kMemoryRoutineUpdatePeriod);
  }
}

void MemoryRoutineV2::SetUpStdout(mojo::ScopedHandle handle) {
  base::ScopedPlatformFile stdout_fd =
      mojo_utils::UnwrapMojoHandle(std::move(handle));
  if (!stdout_fd.is_valid()) {
    return;
  }
  stdout_file_ = base::File(std::move(stdout_fd));
  read_stdout_size_ = 0;
  // Initialize an empty std::vector<std::vector<std::string>>.
  parsed_memtester_result_ = {{""}};
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&MemoryRoutineV2::UpdatePercentage,
                     weak_ptr_factory_.GetWeakPtr()),
      kMemoryRoutineUpdatePeriod);
}

// Parses memtester output and return memtester details.
mojom::MemoryRoutineDetailPtr MemoryRoutineV2::ParseMemtesterResult() {
  ReadNewMemtesterResult();
  // The following regexes are pre-compiled for better performance.
  RE2 bytes_tested_regex(kMemtesterBytesTestedRegex);
  RE2 subtest_regex(kMemtesterSubtestRegex);

  auto detail = mojom::MemoryRoutineDetail::New();
  detail->result = mojom::MemtesterResult::New();

  for (const std::vector<std::string>& line : parsed_memtester_result_) {
    // The following strings are used to hold values matched from regexes.
    std::string bytes_tested_str;
    std::string subtest_name;

    if (RE2::PartialMatch(line[0], bytes_tested_regex, &bytes_tested_str)) {
      if (!base::StringToUint64(bytes_tested_str, &detail->bytes_tested)) {
        LOG(ERROR) << "Cannot convert bytes tested to int: "
                   << bytes_tested_str;
        return nullptr;
      }
    } else if (RE2::PartialMatch(line[0], subtest_regex, &subtest_name)) {
      // Process |subtest_name| so it's formatted without whitespace.
      // E.g. | Stuck Address | => |StuckAddress|
      base::RemoveChars(subtest_name, " ", &subtest_name);
      auto subtest_enum = SubtestNameToEnum(subtest_name);
      if (line.back().find(kMemtesterSubtestFailureSubstring) !=
          std::string::npos) {
        detail->result->failed_items.push_back(subtest_enum);
      } else if (line.back().find(kMemtesterSubtestSuccessSubstring) !=
                 std::string::npos) {
        detail->result->passed_items.push_back(subtest_enum);
      } else {
        LOG(ERROR) << "Unable to parse subtest status: " << line.back();
      }
    }
  }
  return detail;
}

void MemoryRoutineV2::DetermineRoutineResult() {
  scoped_process_control_.Reset();

  // A return code of 1 may be given in two scenarios. Both scenarios should
  // raise an exception:
  //    1. The binary failed to run.
  //    2. There was memory allocating lock error in memtester.
  if (memtester_return_code_ &
      MemtesterErrorCodes::kAllocatingLockingInvokingError) {
    RaiseException(
        "Error allocating or locking memory, or invoking the memtester "
        "binary");
    return;
  }
  auto memtester_detail = ParseMemtesterResult();
  if (memtester_detail.is_null()) {
    RaiseException("Error parsing memtester output");
    return;
  }

  bool has_passed = memtester_return_code_ == EXIT_SUCCESS;
  SetFinishedState(
      has_passed, mojom::RoutineDetail::NewMemory(std::move(memtester_detail)));
}

}  // namespace diagnostics
