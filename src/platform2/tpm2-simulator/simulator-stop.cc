// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/command_line.h>
#include <base/hash/sha1.h>
#include <base/logging.h>
#include <brillo/syslog_logging.h>
#include <vboot/tlcl.h>

// This program send the commands to the TPM that typically are used by the
// firmware to shutdown the TPM
int main(int argc, char* argv[]) {
  // Initialize command line configuration early, as logging will require
  // command line to be initialized
  base::CommandLine::Init(argc, argv);
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);

  TlclLibInit();
  TlclSaveState();
}
