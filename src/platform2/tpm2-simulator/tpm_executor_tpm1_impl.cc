// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <stdlib.h>
#include <string>

#include <base/logging.h>
#include <libtpms/tpm_error.h>
#include <libtpms/tpm_library.h>
#include <linux/vtpm_proxy.h>

#include "tpm2-simulator/constants.h"
#include "tpm2-simulator/tpm_command_utils.h"
#include "tpm2-simulator/tpm_executor_tpm1_impl.h"
#include "tpm2-simulator/tpm_vendor_cmd_locality.h"

namespace {

constexpr char kEnvTpmPath[] = "TPM_PATH";
constexpr char kTpmDataPath[] = ".";  // Using the current location.

constexpr unsigned char kStartupCommand[] = {
    0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00};

}  // namespace

namespace tpm2_simulator {

TpmExecutorTpm1Impl::TpmExecutorTpm1Impl() {
  vendor_commands_.emplace_back(std::make_unique<TpmVendorCommandLocality>());
}

void TpmExecutorTpm1Impl::InitializeVTPM() {
  setenv(kEnvTpmPath, kTpmDataPath, 0);
  TPM_RESULT res;
  res = TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_1_2);
  if (res) {
    LOG(ERROR) << "TPMLIB_ChooseTPMVersion failed with: " << res;
    return;
  }

  res = TPMLIB_MainInit();
  if (res) {
    LOG(ERROR) << "TPMLIB_MainInit failed with: " << res;
    return;
  }

  RunCommand(std::string(reinterpret_cast<const char*>(kStartupCommand),
                         sizeof(kStartupCommand)));

  for (const auto& vendor_cmd : vendor_commands_) {
    if (!vendor_cmd->Init()) {
      LOG(ERROR) << "Failed to initialize vendor command.";
    }
  }

  LOG(INFO) << "vTPM Initialize.";
}

size_t TpmExecutorTpm1Impl::GetCommandSize(const std::string& command) {
  uint32_t size;
  if (!ExtractCommandSize(command, &size)) {
    LOG(ERROR) << "Command too small.";
    return command.size();
  }
  return size;
}

std::string TpmExecutorTpm1Impl::RunCommand(const std::string& command) {
  unsigned char* rbuffer = nullptr;
  uint32_t rlength;
  uint32_t rtotal = 0;

  for (const auto& vendor_cmd : vendor_commands_) {
    if (vendor_cmd->IsVendorCommand(command)) {
      return vendor_cmd->RunCommand(command);
    }
  }

  std::string command_copy = command;
  unsigned char* command_ptr =
      reinterpret_cast<unsigned char*>(command_copy.data());

  TPM_RESULT res;
  res =
      TPMLIB_Process(&rbuffer, &rlength, &rtotal, command_ptr, command.size());

  return std::string(reinterpret_cast<char*>(rbuffer), rlength);
}

}  // namespace tpm2_simulator
