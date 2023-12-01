// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/gsc_collector.h"

#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/process/process.h>

using brillo::ProcessImpl;

namespace {

const char kGscFirmwarePath[] = "/opt/google/ti50/firmware";
const char kGscToolPath[] = "/usr/sbin/gsctool";

}  // namespace

GscCollectorBase::Status GscCollector::GetTi50Flog(std::string* flog_output) {
  ProcessImpl gsctool;
  gsctool.AddArg(kGscToolPath);
  gsctool.AddArg("-a");           // spi/i2c AP-to-GSC interface
  gsctool.AddArg("--dauntless");  // Communicate with Dauntless chip.
  gsctool.AddArg("--flog");       // Retrieve contents of the flash log
  // Combine stdout and stderr.
  gsctool.RedirectOutputToMemory(true);

  const int result = gsctool.Run();
  *flog_output = gsctool.GetOutputString(STDOUT_FILENO);
  if (result != 0) {
    LOG(ERROR) << "Failed to run gsctool. Error: '" << result << "'";
    return Status::Fail;
  }

  return Status::Success;
}

GscCollectorBase::Status GscCollector::GetGscFlog(std::string* flog_output) {
  if (base::PathExists(base::FilePath(kGscFirmwarePath))) {
    return GetTi50Flog(flog_output);
  }

  LOG(INFO) << "Unsupported GSC present on board. Unable to query GSC crashes.";
  return Status::Fail;
}
