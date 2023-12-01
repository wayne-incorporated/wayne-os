// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <brillo/file_utils.h>
#include <brillo/syslog_logging.h>

#include "hwsec-test-utils/attestation_injected_keys/utility.h"

namespace {

constexpr char kLogToStderrSwitch[] = "log-to-stderr";
constexpr char kOutputFilePathSwitch[] = "output";
constexpr char kDefaultKeyDataPath[] = "/run/attestation/google_keys.data";

}  // namespace

int main(int argc, char* argv[]) {
  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  int flags = brillo::kLogToSyslog;
  if (cl->HasSwitch(kLogToStderrSwitch)) {
    flags |= brillo::kLogToStderr;
  }
  brillo::InitLog(flags);

  std::string output_path = kDefaultKeyDataPath;
  if (cl->HasSwitch(kOutputFilePathSwitch))
    output_path = cl->GetSwitchValueASCII(kDefaultKeyDataPath);

  std::string serialized;
  if (!hwsec_test_utils::GenerateAttestationGoogleKeySet().SerializeToString(
          &serialized)) {
    LOG(ERROR) << ": Failed to generate the Google key file content.";
    return 1;
  }

  // Write to file.
  if (!brillo::WriteStringToFile(base::FilePath(output_path), serialized)) {
    LOG(ERROR) << ": Failed to write Google key data.";
    return 1;
  }

  return 0;
}
