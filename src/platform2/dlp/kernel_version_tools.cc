// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dlp/kernel_version_tools.h"

#include <sys/utsname.h>
#include <vector>

#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>

namespace dlp {

std::pair<int, int> GetKernelVersion() {
  struct utsname buf;
  if (uname(&buf))
    return std::make_pair(INT_MIN, INT_MIN);

  // Parse uname result in the form of x.yy.zzz. The parsed data should be in
  // the expected format.
  std::vector<base::StringPiece> versions = base::SplitStringPiece(
      buf.release, ".", base::WhitespaceHandling::TRIM_WHITESPACE,
      base::SplitResult::SPLIT_WANT_ALL);
  DCHECK_EQ(versions.size(), 3);
  DCHECK(!versions[0].empty());
  DCHECK(!versions[1].empty());
  int version;
  bool result = base::StringToInt(versions[0], &version);
  DCHECK(result);
  int major_revision;
  result = base::StringToInt(versions[1], &major_revision);
  DCHECK(result);
  return std::make_pair(version, major_revision);
}

}  // namespace dlp
