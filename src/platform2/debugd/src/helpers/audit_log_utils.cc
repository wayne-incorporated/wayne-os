// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/helpers/audit_log_utils.h"

#include <array>
#include <string>
#include <vector>

#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <re2/re2.h>

namespace debugd {

namespace {

enum {
  AUDIT_TYPE_AVC,
  AUDIT_TYPE_SYSCALL,
};

// e.g. type=AVC msg=audit(12/10/21 22:31:04.221:217) : avc:  denied  { map }
// for  scontext=u:r:dexoptanalyzer:s0 tcontext=u:object_r:app_data_file:s0 ...
constexpr char kAvcRegex[] =
    R"((type=AVC msg=audit\(.+\) ?: avc:  (denied|granted)  {.+} for  )(.+))";

// e.g. type=SYSCALL msg=audit(12/10/21 22:31:04.221:218) : arch=x86_64
// syscall=openat success=yes exit=4 a0=0xffffff9c a1=0x5c7adae22fc0 ...
constexpr char kSyscallRegex[] = R"((type=SYSCALL msg=audit\(.+\) ?: )(.+))";

constexpr std::array kAllowedAvcTags{
    "pid",      "comm",     "path",   "dev",        "ino",
    "scontext", "tcontext", "tclass", "permissive",
};

constexpr std::array kAllowedSyscallTags{
    "arch",  "syscall", "per",  "success", "exit",  "a0",   "a1",
    "a2",    "a3",      "a4",   "a5",      "ppid",  "pid",  "auid",
    "uid",   "gid",     "euid", "suid",    "fsuid", "egid", "sgid",
    "fsgid", "ses",     "comm", "exe",     "subj",
};

}  // namespace

std::string FilterAuditLine(const std::string& line) {
  std::string trimmed_line;
  base::TrimString(line, "\n", &trimmed_line);
  int type;
  std::string header, body, unused;
  if (RE2::FullMatch(trimmed_line, kAvcRegex, &header, &unused, &body)) {
    type = AUDIT_TYPE_AVC;
  } else if (RE2::FullMatch(trimmed_line, kSyscallRegex, &header, &body)) {
    type = AUDIT_TYPE_SYSCALL;
  } else {
    // Unsupported type or invalid format.
    return "";
  }

  // Filter out key=value pairs in body if key is not in the allowlist.
  std::vector<std::string> key_value_pairs = base::SplitString(
      body, " ", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  std::vector<std::string> filtered_key_value_pairs;
  for (const std::string& key_value_str : key_value_pairs) {
    std::vector<std::string> key_value = base::SplitString(
        key_value_str, "=", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
    if (key_value.size() != 2) {
      continue;
    }
    if (type == AUDIT_TYPE_AVC) {
      auto it = std::find(kAllowedAvcTags.begin(), kAllowedAvcTags.end(),
                          key_value[0]);
      if (it == kAllowedAvcTags.end()) {
        continue;
      }
    }
    if (type == AUDIT_TYPE_SYSCALL) {
      auto it = std::find(kAllowedSyscallTags.begin(),
                          kAllowedSyscallTags.end(), key_value[0]);
      if (it == kAllowedSyscallTags.end()) {
        continue;
      }
    }
    filtered_key_value_pairs.push_back(key_value_str);
  }

  return header + base::JoinString(filtered_key_value_pairs, " ");
}

}  // namespace debugd
