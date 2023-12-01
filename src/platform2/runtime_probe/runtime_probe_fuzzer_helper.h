// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_RUNTIME_PROBE_FUZZER_HELPER_H_
#define RUNTIME_PROBE_RUNTIME_PROBE_FUZZER_HELPER_H_

#include <base/strings/utf_string_conversions.h>

#include <string>

using std::string;

string JsonSafe(const string& in) {
  string utf8, s(in);

  // filter \ and ", which will cause json parse error.
  std::replace(s.begin(), s.end(), '\\', '"');
  s.erase(std::remove(s.begin(), s.end(), '"'), s.end());

  // convert to utf8
  std::wstring ws(s.begin(), s.end());
  base::WideToUTF8(ws.c_str(), ws.length(), &utf8);
  return utf8;
}

#endif  // RUNTIME_PROBE_RUNTIME_PROBE_FUZZER_HELPER_H_
