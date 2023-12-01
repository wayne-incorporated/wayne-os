// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <brillo/syslog_logging.h>

#include "tpm2-simulator/tpm_executor_version.h"

using tpm2_simulator::TpmExecutorVersion;

namespace {
const char kTpmVersionFile[] =
    "/mnt/stateful_partition/unencrypted/tpm2-simulator/tpm_executor_version";

constexpr TpmExecutorVersion GetDefaultTpmExecutorVersion() {
#if USE_TI50
  return TpmExecutorVersion::kTi50;
#elif USE_TPM2
  return TpmExecutorVersion::kTpm2;
#elif USE_TPM1
  return TpmExecutorVersion::kTpm1;
#endif
}
}  // namespace

namespace tpm2_simulator {

TpmExecutorVersion GetTpmExecutorVersion() {
  base::FilePath file_path(kTpmVersionFile);
  std::string file_content;

  if (!base::ReadFileToString(file_path, &file_content)) {
    // Use the default version.
    return GetDefaultTpmExecutorVersion();
  }

  std::string version_str;
  base::TrimWhitespaceASCII(file_content, base::TRIM_ALL, &version_str);

  int executor_version = 0;
  if (!base::StringToInt(version_str, &executor_version)) {
    LOG(ERROR) << "Executor version is not a number";
    return GetDefaultTpmExecutorVersion();
  }
  return static_cast<TpmExecutorVersion>(executor_version);
}

}  // namespace tpm2_simulator
