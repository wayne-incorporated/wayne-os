// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/common/util.h"

#include <stdint.h>

#include <algorithm>
#include <cstdlib>
#include <string>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/format_macros.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

namespace power_manager::util {
namespace {

// Reads a string value from |path| and uses StringToType function to convert it
// to |value_out|. Logs an error and returns false on failure.
template <typename T>
bool ReadTypeFile(const base::FilePath& path,
                  bool (*StringToType)(base::StringPiece, T*),
                  T* value_out) {
  DCHECK(value_out);

  std::string str;
  if (!ReadStringFile(path, &str))
    return false;

  if (!StringToType(str, value_out)) {
    LOG(ERROR) << "Unable to parse \"" << str << "\" from " << path.value();
    return false;
  }
  return true;
}

}  // namespace

double ClampPercent(double percent) {
  if (std::isnan(percent)) {
    return 0.0;
  }
  return std::max(0.0, std::min(100.0, percent));
}

std::string TimeDeltaToString(base::TimeDelta delta) {
  std::string output;
  if (delta < base::TimeDelta())
    output += "-";

  int64_t total_seconds = llabs(delta.InSeconds());

  const int64_t hours = total_seconds / 3600;
  if (hours)
    output += base::StringPrintf("%" PRId64 "h", hours);

  const int64_t minutes = (total_seconds % 3600) / 60;
  if (minutes)
    output += base::StringPrintf("%" PRId64 "m", minutes);

  const int64_t seconds = total_seconds % 60;
  if (seconds || !total_seconds)
    output += base::StringPrintf("%" PRId64 "s", seconds);

  return output;
}

bool WriteFileFully(const base::FilePath& filename,
                    const char* data,
                    int size) {
  return base::WriteFile(filename, data, size) == size;
}

bool WriteInt64File(const base::FilePath& path, int64_t value) {
  std::string buf = base::NumberToString(value);
  if (!WriteFileFully(path, buf.data(), buf.size())) {
    PLOG(ERROR) << "Unable to write \"" << buf << "\" to " << path.value();
    return false;
  }
  return true;
}

bool ReadStringFile(const base::FilePath& path, std::string* value_out) {
  if (!MaybeReadStringFile(path, value_out)) {
    PLOG(ERROR) << "Unable to read from " << path.value();
    return false;
  }
  return true;
}

bool MaybeReadStringFile(const base::FilePath& path, std::string* value_out) {
  DCHECK(value_out);

  if (!base::ReadFileToString(path, value_out))
    return false;
  base::TrimWhitespaceASCII(*value_out, base::TRIM_TRAILING, value_out);
  return true;
}

bool ReadInt64File(const base::FilePath& path, int64_t* value_out) {
  return ReadTypeFile(path, base::StringToInt64, value_out);
}

bool ReadUint64File(const base::FilePath& path, uint64_t* value_out) {
  return ReadTypeFile(path, base::StringToUint64, value_out);
}

bool ReadHexUint32File(const base::FilePath& path, uint32_t* value_out) {
  return ReadTypeFile(path, base::HexStringToUInt, value_out);
}

bool DeleteFile(const base::FilePath& path) {
  // |base::DeleteFile| should return true if |path| doesn't exist, but in fact
  // returns false when the directory doesn't exist. Hence additionally check
  // that path does not exist.
  return base::DeleteFile(path) || !base::PathExists(path);
}

std::string JoinPaths(const std::vector<base::FilePath>& paths,
                      const std::string& separator) {
  std::string str;
  for (const auto& path : paths)
    str += (str.empty() ? std::string() : separator) + path.value();
  return str;
}

}  // namespace power_manager::util
