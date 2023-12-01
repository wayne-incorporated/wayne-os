// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Stub implementation of kpasswd.

#include "authpolicy/stub_common.h"

int main(int argc, const char* const* argv) {
  return authpolicy::kExitCodeOk;
}
