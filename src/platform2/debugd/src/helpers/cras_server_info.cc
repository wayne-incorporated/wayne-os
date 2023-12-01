// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// setuid cras helper. We need to ask cras for some system info when generating
// debug data, but cras is only useable by user cras or group cras, and putting
// debugd into group cras would allow it to manipulate system audio arbitrarily.
// Instead, this helper is installed setuid cras and hardcoded to run the
// command we need.

#include <unistd.h>

namespace {

const char kClient[] = "/usr/bin/cras_test_client";

}  // namespace

int main() {
  return execl(kClient, kClient, "--dump_server_info", nullptr);
}
