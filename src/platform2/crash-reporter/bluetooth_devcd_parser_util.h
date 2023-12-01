// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_BLUETOOTH_DEVCD_PARSER_UTIL_H_
#define CRASH_REPORTER_BLUETOOTH_DEVCD_PARSER_UTIL_H_

#include <string>

#include <base/files/file.h>
#include <base/files/file_path.h>

namespace bluetooth_util {

// Parse a bluetooth devcoredump and create a text representation suitable for
// a crash report.
bool ParseBluetoothCoredump(const base::FilePath& coredump_path,
                            const base::FilePath& output_dir,
                            bool save_dump_data,
                            std::string* crash_sig);

}  // namespace bluetooth_util

#endif  // CRASH_REPORTER_BLUETOOTH_DEVCD_PARSER_UTIL_H_
