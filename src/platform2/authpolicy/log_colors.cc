// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "authpolicy/log_colors.h"

namespace authpolicy {

// Other useful colors: light gray=37, white=97

constexpr char kColorReset[] = "\033[0m";
constexpr char kColorCommand[] = "\033[31m";              // Red
constexpr char kColorCommandStdout[] = "\033[33m";        // Yellow
constexpr char kColorCommandStderr[] = "\033[35m";        // Magenta
constexpr char kColorKrb5Trace[] = "\033[36m";            // Cyan
constexpr char kColorPolicy[] = "\033[34m";               // Blue
constexpr char kColorGpo[] = "\033[32m";                  // Green
constexpr char kColorFlags[] = "\033[90m";                // Dark gray
constexpr char kColorStatus[] = "\033[94m";               // Bright blue
constexpr char kColorCaches[] = "\033[93m";               // Light yellow
constexpr char kColorRequest[] = "\033[107;1;30m";        // Bold black on white
constexpr char kColorRequestSuccess[] = "\033[42;1;97m";  // Bold white on green
constexpr char kColorRequestFail[] = "\033[41;1;97m";     // Bold white on red

}  // namespace authpolicy
