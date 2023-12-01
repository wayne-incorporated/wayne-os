// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/flag_helper.h>

namespace {}  // namespace

int main(int argc, char* argv[]) {
  // Flags
  brillo::FlagHelper::Init(
      argc, argv,
      "typecd_tool is an executable for interfacing with the Type-C Daemon.");
}
