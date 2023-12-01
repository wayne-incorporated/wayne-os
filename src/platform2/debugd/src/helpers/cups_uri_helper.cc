// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This helper accepts a URI as its sole argument and exits 0 if the URI
// appears valid. It exits with a nonzero exit code if the URI appears
// invalid. This helper does not write anything meaningful to stdout or
// stderr.

#include <string>

#include "debugd/src/helpers/cups_uri_helper_utils.h"

int main(int argc, char* argv[]) {
  if (argc < 2) {
    return -1;
  }
  if (debugd::cups_helper::UriSeemsReasonable(argv[1])) {
    return 0;
  }
  return 1;
}
