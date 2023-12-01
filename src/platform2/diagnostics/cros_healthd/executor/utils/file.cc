// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/executor/utils/file.h"

#include <algorithm>
#include <limits>

#include <base/check.h>
#include <base/files/file.h>
#include <base/logging.h>
#include <base/numerics/safe_conversions.h>
#include <base/time/time.h>
#include <sys/stat.h>
#include <sys/time.h>

namespace diagnostics {

namespace {
// Converts a statx_timestamp struct to `base::Time`.
base::Time ConvertStatxTimestampToTime(const struct statx_timestamp& sts) {
  struct timespec ts;
  ts.tv_sec = sts.tv_sec;
  ts.tv_nsec = sts.tv_nsec;
  return base::Time::FromTimeSpec(ts);
}
}  // namespace

bool GetCreationTime(const base::FilePath& file_path, base::Time& out) {
  CHECK(file_path.IsAbsolute())
      << "File name in GetCreationTime must be absolute";
  struct statx statx_result;
  if (statx(/*dirfd=ignored*/ 0, file_path.value().c_str(), /*flags=*/0,
            /*masks=*/STATX_BTIME, &statx_result) != 0) {
    PLOG(ERROR) << "statx failed for file " << file_path;
    return false;
  }
  if (!(statx_result.stx_mask & STATX_BTIME)) {
    // Creation time is not obtained even though statx succeeded.
    PLOG(ERROR)
        << "statx failed to obtain creation time even though statx succeeded "
        << file_path;
    return false;
  }

  out = ConvertStatxTimestampToTime(statx_result.stx_btime);
  return true;
}

std::optional<std::string> ReadFilePart(const base::FilePath& file_path,
                                        uint64_t begin,
                                        std::optional<uint64_t> size) {
  base::File file(file_path, base::File::FLAG_OPEN | base::File::FLAG_READ);
  if (!file.IsValid()) {
    PLOG(ERROR) << "Failed to open file " << file_path;
    return std::nullopt;
  }

  base::File::Info info;
  if (!file.GetInfo(&info)) {
    PLOG(ERROR) << "Failed to obtain the info of " << file_path;
    return std::nullopt;
  }

  if (info.is_directory) {
    LOG(ERROR) << "Reading a directory " << file_path << " is unsupported.";
    return std::nullopt;
  }

  if (info.size < begin) {
    // We would get a negative read_size.
    LOG(ERROR) << "Can't read from a location larger than the file size.";
    return std::nullopt;
  }

  const int read_size = std::min(
      base::checked_cast<int>(info.size) - base::checked_cast<int>(begin),
      // We treat the absence of `size` as reading until EOF. Ideally, this
      // should be done by letting the caller pass in
      // `std::numeric_limits<uint64_t>::max()`. However, due to the casting
      // logic here, it may not be safely cast to `int`. Treating it as a
      // special value creates confusing behavior:
      // `std::numeric_limits<uint64_t>::max()` indicates reading until EOF,
      // while `std::numeric_limits<uint64_t>::max() - 1` causes cast error.
      //
      // Changing the type of `size` to `int` does not work either, because a
      // mojom function can only specify a fixed size integer and some cast
      // logic is inevitable.
      size.has_value() ? base::checked_cast<int>(size.value())
                       : std::numeric_limits<int>::max());
  if (read_size == 0) {
    // No need to actually do the IO and read the file.
    return "";
  }
  std::string content(read_size, '\0');
  if (file.Read(base::checked_cast<int64_t>(begin), content.data(),
                read_size) != read_size) {
    PLOG(ERROR) << "Failed to read file " << file_path << " from " << begin
                << " for size " << read_size;
    return std::nullopt;
  }
  return content;
}
}  // namespace diagnostics
