// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/check.h>
#include <base/strings/string_util.h>

#include "vm_tools/garcon/ini_parse_util.h"

namespace vm_tools {
namespace garcon {

base::StringPiece ParseGroupName(base::StringPiece group_line) {
  if (group_line.empty() || group_line.front() != '[' ||
      group_line.back() != ']') {
    return base::StringPiece();
  }
  return group_line.substr(1, group_line.size() - 2);
}

bool ParseBool(const std::string& s) {
  return s == "true";
}

std::string ExtractKeyLocale(const std::string& key) {
  if (key.back() != ']') {
    return "";
  }
  size_t bracket_pos = key.find_first_of('[');
  if (bracket_pos == std::string::npos) {
    return "";
  }
  return key.substr(bracket_pos + 1, key.length() - bracket_pos - 2);
}

std::pair<std::string, std::string> ExtractKeyValuePair(
    base::StringPiece entry_line) {
  size_t equal_pos = entry_line.find_first_of('=');
  if (equal_pos == std::string::npos) {
    return std::make_pair(std::string(entry_line), "");
  }
  base::StringPiece key = base::TrimWhitespaceASCII(
      entry_line.substr(0, equal_pos), base::TRIM_TRAILING);
  base::StringPiece value = base::TrimWhitespaceASCII(
      entry_line.substr(equal_pos + 1), base::TRIM_LEADING);
  return std::make_pair(std::string(key), std::string(value));
}

std::string UnescapeString(const std::string& s) {
  std::string retval;
  bool is_escaped = false;
  for (auto c : s) {
    if (is_escaped) {
      switch (c) {
        case 's':
          retval.push_back(' ');
          break;
        case 't':
          retval.push_back('\t');
          break;
        case 'r':
          retval.push_back('\r');
          break;
        case 'n':
          retval.push_back('\n');
          break;
        default:
          retval.push_back(c);
          break;
      }
      is_escaped = false;
      continue;
    }
    if (c == '\\') {
      is_escaped = true;
      continue;
    }
    retval.push_back(c);
  }
  return retval;
}

void ParseMultiString(const std::string& s,
                      std::vector<std::string>* out,
                      const char delimiter) {
  CHECK(out);
  std::string curr;
  bool use_next = false;
  for (auto c : s) {
    if (use_next) {
      use_next = false;
      curr.push_back(c);
      continue;
    }
    if (c == delimiter) {
      out->emplace_back(UnescapeString(curr));
      curr.clear();
      continue;
    }
    if (c == '\\') {
      // Leave the backslashes in there since we will be unescaping this string
      // still.
      use_next = true;
    }
    curr.push_back(c);
  }
  if (!curr.empty()) {
    out->emplace_back(UnescapeString(curr));
  }
}

}  // namespace garcon
}  // namespace vm_tools
