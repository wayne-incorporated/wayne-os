// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_UTIL_H_
#define ML_UTIL_H_

#include <optional>

#include <base/files/file_path.h>

namespace ml {

// The memory usage (typically of a process).
// One can extend this struct to include more terms. Currently, it only
// includes `VmSwap` and `VmRSS` to fulfill the needs.
struct MemoryUsage {
  size_t VmRSSKb;
  size_t VmSwapKb;

  bool operator==(const MemoryUsage& other) const;
};

// Gets the memory usage by parsing a file (typically `/proc/[pid]/status`)
// This function assumes that the memory unit used in /proc/[pid]/status is
// "kB".
// Return true if successful, false otherwise.
bool GetProcessMemoryUsageFromFile(MemoryUsage* memory_usage,
                                   const base::FilePath& file_path);

// Get the memory usage of a process whose PID is `pid`.
// Return true if successful, false otherwise.
bool GetProcessMemoryUsage(MemoryUsage* memory_usage, pid_t pid);

// Same as GetProcessMemoryUsageFromFile(memory_usage, "/prod/[pid]/status")
// for the calling process's pid.
// Return true if successful, false otherwise.
bool GetProcessMemoryUsage(MemoryUsage* memory_usage);

// Gets the total memory usage for this process, which we define as VmSwap+VmRSS
// extracted from the /proc/pid/status file.
// Return true if successful, false otherwise.
bool GetTotalProcessMemoryUsage(size_t* total_memory);

// "dlopen() with RTLD_DEEPBIND" does not work with ASAN. So currently we only
// support services using this (e.g. HandwritingLibrary) when the "sanitizer" is
// not enabled (see https://crbug.com/1082632).
constexpr bool IsAsan() {
  return __has_feature(address_sanitizer);
}

// Gives resolved path using realpath(3), or empty Optional upon error. Leaves
// realpath's errno unchanged.
std::optional<base::FilePath> GetRealPath(const base::FilePath& path);

// Returns true if the given path is a valid path for DLC.
// This allows ML Service to enforce a security check on the path received via
// mojo.
bool IsDlcPathValid(const base::FilePath& path);

}  // namespace ml

#endif  // ML_UTIL_H_
