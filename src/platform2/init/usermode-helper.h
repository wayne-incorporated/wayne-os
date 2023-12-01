// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INIT_USERMODE_HELPER_H_
#define INIT_USERMODE_HELPER_H_

#include <string>

namespace usermode_helper {

// Whether the program and its arguments are permitted.
bool ValidateProgramArgs(int argc, const char* argv[]);

}  // namespace usermode_helper

#endif  // INIT_USERMODE_HELPER_H_
