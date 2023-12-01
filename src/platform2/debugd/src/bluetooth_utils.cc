// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/bluetooth_utils.h"

#include <stdio.h>
#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <brillo/files/file_util.h>
#include <brillo/process/process.h>

#include "debugd/src/sandboxed_process.h"

namespace debugd {

namespace {

constexpr char kBunzip2Command[] = "/bin/bunzip2";
constexpr char kBtmonCommand[] = "/usr/bin/btmon";

constexpr char btsnoop_infile[] = "/var/log/bluetooth/log.bz2";
constexpr char btsnoop_outfile[] = "/var/log/bluetooth/log";
// The bluetooth_quality_report file is a standalone file and is not part of
// the system_logs. This report file is only generated if a user logs in
// with a Google account. The file would not be attached by the chrome unless
// the Googler opts in to "Attach Bluetooth Logs" in the feedback UI.
constexpr char report_file[] = "/var/log/bluetooth/bluetooth_quality_report";

constexpr char BQR_UNAVAILABLE[] = "; Bluetooth quality report unavailable";

}  // namespace

void GetBluetoothBqr() {
  int ret;

  if (!base::PathExists(base::FilePath(btsnoop_infile))) {
    PLOG(WARNING) << "The btsnoop file does not exist: " << btsnoop_infile
                  << BQR_UNAVAILABLE;
    return;
  }

  // Remove btsnoop_outfile at exit.
  base::ScopedClosureRunner delete_outfile(
      base::BindOnce(base::IgnoreResult(&brillo::DeleteFile),
                     base::FilePath(btsnoop_outfile)));

  // The process is used to decompress the Bluetooth log.
  //   - input: btsnoop_infile
  //   - output: btsnoop_outfile
  // Note: kBunzip2Command has been sandboxed so ProcessImpl is employed.
  brillo::ProcessImpl p;
  p.AddArg(kBunzip2Command);
  p.AddArg("--keep");
  p.AddArg("--force");
  p.AddArg(btsnoop_infile);
  ret = p.Run();
  if (ret) {
    PLOG(WARNING) << "Failed to decompress " << btsnoop_infile
                  << BQR_UNAVAILABLE;
    return;
  }

  // The process is used to create the summary report.
  //   - input: btsnoop_outfile
  //   - output: report_file
  // Note: this process should be sandboxed.
  SandboxedProcess sp;
  sp.SandboxAs("bluetooth", "bluetooth");
  sp.AddArg(kBtmonCommand);
  sp.AddArg("--analyze");
  sp.AddArg(btsnoop_outfile);
  sp.RedirectUsingFile(STDOUT_FILENO, std::string(report_file));
  ret = sp.Run();
  if (ret)
    PLOG(WARNING) << "Failed to btmon analyze " << btsnoop_outfile
                  << BQR_UNAVAILABLE;
}

}  // namespace debugd
