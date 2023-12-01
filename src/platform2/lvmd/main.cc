// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sysexits.h>

#include <iostream>
#include <memory>

#include <brillo/blkdev_utils/lvm.h>

#include "lvmd/lvmd.h"

namespace {

void PrintUsage() {
  std::cout << "Usage: lvmd\n";
}

}  // namespace

int main(int argc, char* argv[]) {
  if (argc != 1) {
    PrintUsage();
    return EX_USAGE;
  }

  auto lvm = std::make_unique<brillo::LogicalVolumeManager>();

  lvmd::Lvmd daemon(std::move(lvm));
  daemon.Run();

  return EX_OK;
}
