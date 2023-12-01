// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "authpolicy/anonymizer.h"

#include <algorithm>
#include <vector>

#include <base/check_op.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <pcrecpp.h>

#include "authpolicy/samba_helper.h"

namespace {

constexpr char kNewLineChars[] = "\r\n";
constexpr char kSeparator = ':';

void ApplyRegex(const std::string& regex, std::string* str) {
  pcrecpp::RE re(regex, pcrecpp::RE_Options());
  DCHECK_EQ(1, re.NumberOfCapturingGroups());
  pcrecpp::StringPiece text(*str);
  re.PartialMatch(text, str);
}

}  // namespace

namespace authpolicy {

Anonymizer::Anonymizer() = default;

void Anonymizer::SetReplacement(const std::string& string_to_replace,
                                const std::string& replacement) {
  if (string_to_replace.empty())
    return;
  replacements_[string_to_replace] = replacement;
}

void Anonymizer::SetReplacementAllCases(const std::string& string_to_replace,
                                        const std::string& replacement) {
  if (string_to_replace.empty())
    return;
  replacements_[base::ToLowerASCII(string_to_replace)] = replacement;
  replacements_[base::ToUpperASCII(string_to_replace)] = replacement;
  replacements_[string_to_replace] = replacement;
}

void Anonymizer::ReplaceSearchArg(const std::string& search_keyword,
                                  const std::string& replacement,
                                  const std::string& regex) {
  if (search_keyword.empty())
    return;
  search_replacements_[search_keyword] = {replacement, regex};
}

void Anonymizer::ResetSearchArgReplacements() {
  search_replacements_.clear();
}

std::string Anonymizer::Process(const std::string& input) {
  process_called_for_testing_ = true;

  // Gather all search args and add them to replacements_.
  if (search_replacements_.size() > 0) {
    std::vector<std::string> lines = base::SplitString(
        input, kNewLineChars, base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
    std::string string_to_replace;
    for (const std::string& line : lines) {
      for (const auto& data : search_replacements_) {
        const std::string& search_keyword = data.first;
        const std::string& replacement = data.second.replacement;
        const std::string& regex = data.second.regex;
        if (FindTokenInLine(line, kSeparator, search_keyword,
                            &string_to_replace)) {
          if (regex.size() > 0)
            ApplyRegex(regex, &string_to_replace);
          SetReplacement(string_to_replace, replacement);
          break;
        }
      }
    }
  }

  // If turned off, just return the input. Still do the stuff above, though, so
  // Process() will work properly once the anonymizer is re-enabled.
  if (disabled_)
    return input;

  // Now handle string replacements.
  std::string output = input;
  for (const auto& replacement : replacements_) {
    base::ReplaceSubstringsAfterOffset(&output, 0, replacement.first,
                                       replacement.second);
  }
  return output;
}

}  // namespace authpolicy
