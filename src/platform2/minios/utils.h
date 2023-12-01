// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_UTILS_H_
#define MINIOS_UTILS_H_

#include <memory>
#include <string>
#include <tuple>

#include <base/files/file_path.h>

#include "minios/process_manager.h"

namespace minios {

// Alert Log error categories.
extern const char kCategoryInit[];
extern const char kCategoryReboot[];
extern const char kCategoryUpdate[];

extern const base::FilePath kDefaultArchivePath;

// Reads the content of `file_path` from `start_offset` to `end_offset` with
// maximum characters per line being `max_columns` at max. If the file ends
// before reading all bytes between `start_offset` and `end_offset` it will
// return true.
// - bool: Success or failure.
// - std::string: The content read.
std::tuple<bool, std::string> ReadFileContentWithinRange(
    const base::FilePath& file_path,
    int64_t start_offset,
    int64_t end_offset,
    int num_cols);

// Reads the content of `file_path` from `offset`.
// The `num_lines` and `num_cols` is the maximum amount of lines and characters
// per line that will be read.
// The return will include:
// - bool: Success or failure.
// - std::string: The content read.
// - int64_t: The number of bytes read.
// Note: The number of bytes read can differ than the length of the content
// output in the second tuple element because the content read is formatted to
// number of lines and columns format to fit onto the requested area of
// `num_lines` * `num_cols`.
std::tuple<bool, std::string, int64_t> ReadFileContent(
    const base::FilePath& file_path,
    int64_t offset,
    int num_lines,
    int num_cols);

// Gets VPD region data given a key. Returns false on failure.
bool GetCrosRegionData(ProcessManagerInterface* process_manager,
                       std::string key,
                       std::string* value);

// Gets XKB keyboard data and extracts country code from it. Defaults to "us" on
// failure.
std::string GetKeyboardLayout(ProcessManagerInterface* process_manager);

// Read frecon created symbolic link and return the virtual terminal path.
base::FilePath GetLogConsole();

bool TriggerShutdown();

// Create a tag that can be added to an Error log message to allow easier
// filtering from listnr logs. Expected to be used as the first field of a log
// message. e.g.: `LOG(ERROR) << AlertLogTag(kCategoryName) << err_msg << ....;`
inline std::string AlertLogTag(const std::string& category) {
  return base::StringPrintf("[CoreServicesAlert<%s>] ", category.c_str());
}

// Mount the stateful partition at `/stateful/` if its not currently mounted.
// Returns true if successfully mounted, false otherwise.
bool MountStatefulPartition(ProcessManagerInterface* process_manager);

// Compress a pre-determined list of NBR logs and save it to the provided path.
// Returns the result of running a `tar` command.
int CompressLogs(std::unique_ptr<ProcessManagerInterface> process_manager,
                 const base::FilePath& archive_path = kDefaultArchivePath);

}  // namespace minios
#endif  // MINIOS_UTILS_H__
