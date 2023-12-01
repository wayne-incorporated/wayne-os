// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/syslog/rotator.h"

#include <algorithm>
#include <vector>

#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>

namespace vm_tools {
namespace syslog {

// Creating a new log file for Forwarder is handled outside this code.

namespace {
int FileIndexFromName(const base::FilePath& file_path) {
  int index = 0;
  std::string s = file_path.FinalExtension();
  base::StringPiece final_extension(s);
  if (base::StartsWith(final_extension, ".")) {
    final_extension.remove_prefix(1);
    if (!base::StringToInt(final_extension, &index)) {
      index = 0;
    }
  }
  return index;
}
}  // namespace

void Rotator::GetSortedFileInfo(
    const base::FilePath& root_path,
    const std::string& pattern,
    std::vector<base::FileEnumerator::FileInfo>* info) {
  base::FileEnumerator file_enumerator(root_path, false,
                                       base::FileEnumerator::FILES, pattern);
  VLOG(1) << "Searching for " << pattern << " in " << root_path;
  while (!file_enumerator.Next().empty()) {
    info->push_back(file_enumerator.GetInfo());
  }

  std::sort(info->begin(), info->end(),
            [](const base::FileEnumerator::FileInfo& lhs,
               const base::FileEnumerator::FileInfo& rhs) {
              // Sort by name descending, interpreting final extension as
              // a number.
              base::FilePath lhs_base = lhs.GetName().RemoveFinalExtension();
              base::FilePath rhs_base = rhs.GetName().RemoveFinalExtension();
              if (lhs_base != rhs_base) {
                return lhs_base.value() > rhs_base.value();
              }
              return FileIndexFromName(lhs.GetName()) >
                     FileIndexFromName(rhs.GetName());
            });
}

void Rotator::RotateLogFiles(const base::FilePath& root_path, int max_index) {
  std::vector<base::FileEnumerator::FileInfo> info;
  GetSortedFileInfo(root_path, "*.log*", &info);

  // We are now iterating the files in reverse order (highest numeric suffix
  // first in each sequence). We can simply increment each file's index,
  // explicitly deleting those with an index out of range.
  for (const auto& file_info : info) {
    base::FilePath base_path = file_info.GetName();
    int file_index = FileIndexFromName(base_path);

    base::FilePath from_path = root_path.Append(base_path);

    if (file_index != 0) {
      if (file_index >= max_index) {
        // Delete files with higher indices. To protect a file
        // from deletion, it should use a different suffix from ".log.N"
        if (!base::DeleteFile(from_path)) {
          LOG(ERROR) << "Error deleting " << from_path << ": "
                     << base::File::ErrorToString(
                            base::File::GetLastFileError());
        } else {
          VLOG(1) << "Deleted file " << from_path;
        }
        continue;
      }
    }

    base::FilePath to_path = from_path;
    if (file_index > 0) {
      to_path = to_path.RemoveFinalExtension();
    }
    to_path = to_path.AddExtension(base::NumberToString(file_index + 1));

    if (!base::Move(from_path, to_path)) {
      LOG(ERROR) << "File error while moving " << from_path << " to " << to_path
                 << ": "
                 << base::File::ErrorToString(base::File::GetLastFileError());
    }
  }
}

}  // namespace syslog
}  // namespace vm_tools
