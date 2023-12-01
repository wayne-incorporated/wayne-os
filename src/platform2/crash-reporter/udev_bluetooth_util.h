// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_UDEV_BLUETOOTH_UTIL_H_
#define CRASH_REPORTER_UDEV_BLUETOOTH_UTIL_H_

#include <string>

#include <base/files/file_path.h>

namespace bluetooth_util {

// Executable name for bluetooth devcoredump.
extern const char kBluetoothDevCoredumpExecName[];

// Check if the bluetooth devcoredump feature is enabled. This is populated by
// Chrome-BlueZ whenever the chrome feature flag is updated, which is also used
// by BlueZ-kernel to check whether the feature is enabled.
// TODO(b/203034370): Remove this once the feature is fully launched and the
// feature flag is removed.
bool IsCoredumpEnabled();
// Create a crash signature for bluetooth devcoredump.
std::string CreateCrashSig(const std::string& driver_name,
                           const std::string& vendor_name,
                           const std::string& controller_name,
                           const std::string& pc);
// Read parsed bluetooth devcoredump to create a crash signature.
bool ReadCrashSig(const base::FilePath& target_path, std::string* crash_sig);
// Check if it is a bluetooth devcoredump.
bool IsBluetoothCoredump(const base::FilePath& coredump_path);
// Parse bluetooth devcoredump and creates a crash report.
bool ProcessBluetoothCoredump(const base::FilePath& coredump_path,
                              const base::FilePath& target_path,
                              std::string* crash_sig);

}  // namespace bluetooth_util

#endif  // CRASH_REPORTER_UDEV_BLUETOOTH_UTIL_H_
