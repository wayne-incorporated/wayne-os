// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "secanomalyd/mounts.h"

#include <optional>
#include <string>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>

namespace secanomalyd {

namespace {
constexpr char kProcSelfMountsPath[] = "/proc/self/mounts";
}

MaybeMountEntries ReadMounts(MountFilter filter) {
  std::string proc_mounts;
  if (!base::ReadFileToStringNonBlocking(base::FilePath(kProcSelfMountsPath),
                                         &proc_mounts)) {
    PLOG(ERROR) << "Failed to read " << kProcSelfMountsPath;
    return std::nullopt;
  }

  return ReadMountsFromString(proc_mounts, filter);
}

MaybeMountEntries ReadMountsFromString(const std::string& mounts,
                                       MountFilter filter) {
  std::vector<base::StringPiece> pieces = base::SplitStringPiece(
      mounts, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  if (pieces.empty()) {
    return std::nullopt;
  }

  MountEntries res;
  for (const auto& piece : pieces) {
    MountEntry e = MountEntry(piece);
    if (filter == MountFilter::kUploadableOnly && e.IsUsbDriveOrArchive()) {
      // Don't upload USB drive or archive mounts.
      continue;
    }
    res.push_back(e);
  }

  return MaybeMountEntries(res);
}

}  // namespace secanomalyd
