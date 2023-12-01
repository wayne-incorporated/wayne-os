// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef AUTHPOLICY_ANONYMIZER_H_
#define AUTHPOLICY_ANONYMIZER_H_

#include <map>
#include <string>

#include <base/logging.h>

namespace authpolicy {

// Log anonymizer that performs simple search&replace operations on log strings.
// This approach is taken instead of regex replacements since Samba and kinit
// are pretty much black boxes and finding regular expressions to match all
// occurances of sensitive data in their logs would be very cumbersome and
// insecure because we cannot guarantee that all code paths are hit. This
// sledgehammer approach is more secure.
class Anonymizer {
 public:
  Anonymizer();
  Anonymizer(const Anonymizer&) = delete;
  Anonymizer& operator=(const Anonymizer&) = delete;

  // Causes Process() to replace |string_to_replace| by |replacement|.
  void SetReplacement(const std::string& string_to_replace,
                      const std::string& replacement);

  // Same as SetReplacement(), but additionally replaces lower- and upper-case
  // versions of |string_to_replace| by |replacement|.
  void SetReplacementAllCases(const std::string& string_to_replace,
                              const std::string& replacement);

  // Causes Process() to search for "|search_keyword| : <value>" and to
  // set the replacement <value> -> |replacement| before all replacements are
  // applied to the input string. This is useful for logging results from
  // searching sensitive data (e.g. net ads search for user names). It solves
  // the chicken-egg-problem where one would usually like to log results before
  // parsing them (or in case parsing fails), but replacements cannot be set
  // before the results are parsed.
  // If |regex| is given, it is applied to <value>. The pattern must have
  // exactly one capturing group. <value> is changed to the value of that group.
  // Useful regular expression syntax: +? is a non-greedy (lazy) +.
  void ReplaceSearchArg(const std::string& search_keyword,
                        const std::string& replacement,
                        const std::string& regex = std::string());

  // Resets all calls to ReplaceSearchArg(), but keeps the replacements set by
  // a call to Process() in between. Should be done after a search log has been
  // logged.
  void ResetSearchArgReplacements();

  // Runs the anonymizer on the given |input|, replacing all strings with their
  // given replacement. Returns the anonymized string.
  std::string Process(const std::string& input);

  // If set to true, Process() just returns the initial |input|.
  void set_disabled(bool disabled) { disabled_ = disabled; }

  // Returns true iff Process() was called.
  bool process_called_for_testing() const {
    return process_called_for_testing_;
  }

 private:
  // Sorts by string length first (descending), then alphabetically. This order
  // is used while iterating |replacements_|. It prevents that keys being
  // substrings of longer keys are replaced first, e.g. we don't want to replace
  // "KEY" before "KEY_123", "ABC_KEY" or "XYZ_KEY".
  struct StringLengthDescendingComparer {
    inline bool operator()(const std::string& a, const std::string& b) const {
      if (a.size() != b.size())
        return a.size() > b.size();
      return a < b;
    }
  };

  // Maps string-to-replace to their replacement.
  std::map<std::string, std::string, StringLengthDescendingComparer>
      replacements_;

  struct ReplacementData {
    std::string replacement;
    std::string regex;
  };

  // Maps search keywords to the replacement of the search value.
  std::map<std::string, ReplacementData> search_replacements_;

  bool process_called_for_testing_ = false;
  bool disabled_ = false;
};

}  // namespace authpolicy

#endif  // AUTHPOLICY_ANONYMIZER_H_
