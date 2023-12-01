// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/log_parser.h"

#include <string>
#include <utility>

#include <base/logging.h>

namespace {

std::string StripLeadingNull(std::string&& entire_line) {
  int null_len = 0;
  for (; null_len < entire_line.size(); null_len++) {
    if (entire_line[null_len] != '\0')
      break;
  }

  return entire_line.substr(null_len);
}

}  // anonymous namespace

namespace croslog {

MaybeLogEntry LogParser::Parse(std::string&& entire_line) {
  // This hack is the temporary solution for crbug.com/1132182.
  // TODO(yoshiki): remove this after solving the issue.
  if (!entire_line.empty() && entire_line[0] == '\0') {
    LOG(WARNING) << "The line has leading NULLs. This is unresolved bug. "
                    "Please report this to crbug.com/1132182. Content: "
                 << entire_line;

    entire_line = StripLeadingNull(std::move(entire_line));
  }

  return ParseInternal(std::move(entire_line));
}

}  // namespace croslog
