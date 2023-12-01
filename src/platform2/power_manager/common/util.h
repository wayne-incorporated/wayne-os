// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_COMMON_UTIL_H_
#define POWER_MANAGER_COMMON_UTIL_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/time/time.h>

namespace power_manager::util {

// Clamps |percent| in the range [0.0, 100.0].
double ClampPercent(double percent);

// Returns |delta| as a string of the format "4h3m45s".
std::string TimeDeltaToString(base::TimeDelta delta);

// Writes the given buffer into the file, overwriting any data that was
// previously there. Returns true if all bytes are written or false otherwise.
bool WriteFileFully(const base::FilePath& filename, const char* data, int size);

// Writes the base-10 representation of |value| to |path| without a trailing
// newline. Logs an error and returns false on failure.
bool WriteInt64File(const base::FilePath& path, int64_t value);

// Reads a string value from |path| to |value|, ignoring trailing whitespace.
// Logs an error and returns false on failure.
bool ReadStringFile(const base::FilePath& path, std::string* value_out);

// Reads a string value from |path| to |value|, ignoring trailing whitespace.
// Returns false on failure without error logging.
bool MaybeReadStringFile(const base::FilePath& path, std::string* value_out);

// Reads a base-10 int64 value from |path| to |value|, ignoring trailing
// whitespace. Logs an error and returns false on failure.
bool ReadInt64File(const base::FilePath& path, int64_t* value_out);

// Reads a base-10 uint64 value from |path| to |value|, ignoring trailing
// whitespace. Logs an error and returns false on failure.
bool ReadUint64File(const base::FilePath& path, uint64_t* value_out);

// Reads a base-16 uint32 value from |path| to |value|, ignoring trailing
// whitespace. Logs an error and returns false on failure.
bool ReadHexUint32File(const base::FilePath& path, uint32_t* value_out);

// Deletes the file specified by |path|. Returns true if the file does not exist
// afterwards.
bool DeleteFile(const base::FilePath& path);

// Joins |paths| using |separator|.
std::string JoinPaths(const std::vector<base::FilePath>& paths,
                      const std::string& separator);

}  // namespace power_manager::util

#endif  // POWER_MANAGER_COMMON_UTIL_H_
