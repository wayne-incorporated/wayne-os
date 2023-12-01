// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// This tool provides a basic CLI to control battery saver mode (BSM)
// on ChromeOS.

#include "power_manager/tools/battery_saver/battery_saver.h"

int main(int argc, char* argv[]) {
  return power_manager::BatterySaverCli(argc, argv);
}
