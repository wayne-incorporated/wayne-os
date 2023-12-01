// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_MEMORY_AND_CPU_CONSTANTS_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_MEMORY_AND_CPU_CONSTANTS_H_

#include <base/time/time.h>

namespace diagnostics {

// Different bit flags which can be encoded in the return value for memtester.
// See https://linux.die.net/man/8/memtester for details. Note that this is not
// an enum class so that it can be implicitly converted to a bit flag.
enum MemtesterErrorCodes {
  // An error allocating or locking memory, or invoking the memtester binary.
  kAllocatingLockingInvokingError = 0x01,
  // Stuck address test found an error.
  kStuckAddressTestError = 0x02,
  // Any test other than the stuck address test found an error.
  kOtherTestError = 0x04,
};

// Fleet-wide default value for the urandom routine's parameter.
// TODO(crbug/1131609): get a better default value with some rationale behind
// it.
const base::TimeDelta kUrandomDefaultLength = base::Seconds(10);

// Ensure the operating system is left with at least the following size to avoid
// out of memory error.
constexpr int kCpuMemoryRoutineReservedSizeKiB = 500 * 1024;  // 500 MiB.

// This is the minimum required memory to run stressapptest successfully,
// otherwise the program will crash.
// The stressapptest will fail when page number is small (b/80264616), and we
// choose an arbitrary value that is large enough to not crash the app.
const int kStressAppTestRoutineMinimumRequiredKiB = 128 * 1024;  // 128 MiB.

// Default runtime for routines which stress the CPU.
const base::TimeDelta kDefaultCpuStressRuntime = base::Minutes(1);

// Status messages the memory routine can report.
inline constexpr char kMemoryRoutineSucceededMessage[] =
    "Memory routine passed.";
inline constexpr char kMemoryRoutineRunningMessage[] = "Memory routine running";
inline constexpr char kMemoryRoutineCancelledMessage[] =
    "Memory routine cancelled.";

// Error messages for memtester precondition.
inline constexpr char kMemoryRoutineMemtesterAlreadyRunningMessage[] =
    "Error Memtester process already running.";
inline constexpr char kMemoryRoutineFetchingAvailableMemoryFailureMessage[] =
    "Error fetching available memory.\n";
inline constexpr char kMemoryRoutineNotHavingEnoughAvailableMemoryMessage[] =
    "Error not having enough available memory.\n";

// Error messages for memtester failure.
inline constexpr char kMemoryRoutineAllocatingLockingInvokingFailureMessage[] =
    "Error allocating or locking memory, or invoking the memtester binary.\n";
inline constexpr char kMemoryRoutineStuckAddressTestFailureMessage[] =
    "Error during the stuck address test.\n";
inline constexpr char kMemoryRoutineOtherTestFailureMessage[] =
    "Error during a test other than the stuck address test.\n";

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_MEMORY_AND_CPU_CONSTANTS_H_
