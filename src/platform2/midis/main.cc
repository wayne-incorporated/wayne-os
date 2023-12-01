// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/logging.h>

#include "midis/daemon.h"

int main(int argc, char* argv[]) {
  LOG(INFO) << "Starting MIDI native service\n";
  midis::Daemon daemon;

  daemon.Run();
  return 0;
}
