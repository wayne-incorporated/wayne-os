// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/paths.h"

#include <base/strings/string_util.h>

namespace paths {

namespace {

// The path prefix that'll be used for testing.
const base::FilePath* g_test_prefix;

}  // namespace

void SetPrefixForTesting(const base::FilePath& prefix) {
  if (g_test_prefix) {
    delete g_test_prefix;
    g_test_prefix = nullptr;
  }
  if (!prefix.empty())
    g_test_prefix = new base::FilePath(prefix);
}

base::FilePath Get(base::StringPiece file_path) {
  if (g_test_prefix) {
    if (base::StartsWith(file_path, "/"))
      file_path.remove_prefix(1);
    return g_test_prefix->Append(file_path);
  }
  return base::FilePath(file_path);
}

base::FilePath GetAt(base::StringPiece directory, base::StringPiece base_name) {
  return Get(directory).Append(base_name);
}
}  // namespace paths
