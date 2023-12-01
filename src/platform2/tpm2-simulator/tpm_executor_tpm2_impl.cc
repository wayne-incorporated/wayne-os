// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tpm2-simulator/tpm_executor_tpm2_impl.h"

#include <memory>
#include <string>

#include <base/logging.h>
#include <linux/vtpm_proxy.h>
#include <tpm2/tpm_simulator.hpp>

#include "tpm2-simulator/constants.h"
#include "tpm2-simulator/tpm_command_utils.h"
#include "tpm2-simulator/tpm_vendor_cmd_locality.h"
#include "tpm2-simulator/tpm_vendor_cmd_pinweaver.h"

namespace tpm2_simulator {

TpmExecutorTpm2Impl::TpmExecutorTpm2Impl() {
  vendor_commands_.emplace_back(std::make_unique<TpmVendorCommandLocality>());
  vendor_commands_.emplace_back(std::make_unique<TpmVendorCommandPinweaver>());
}

void TpmExecutorTpm2Impl::InitializeVTPM() {
  // Initialize TPM.
  tpm2::_plat__Signal_PowerOn();
  /*
   * Make sure NV RAM metadata is initialized, needed to check
   * manufactured status. This is a speculative call which will have to
   * be repeated in case the TPM has not been through the manufacturing
   * sequence yet. No harm in calling it twice in that case.
   */
  tpm2::_TPM_Init();
  tpm2::_plat__SetNvAvail();

  if (!tpm2::tpm_manufactured()) {
    tpm2::TPM_Manufacture(true);
    // TODO(b/132145000): Verify if the second call to _TPM_Init() is necessary.
    tpm2::_TPM_Init();
    if (!tpm2::tpm_endorse())
      LOG(ERROR) << __func__ << " Failed to endorse TPM with a fixed key.";
  }

  for (const auto& vendor_cmd : vendor_commands_) {
    if (!vendor_cmd->Init()) {
      LOG(ERROR) << "Failed to initialize vendor command.";
    }
  }

  LOG(INFO) << "vTPM Initialize.";
}

size_t TpmExecutorTpm2Impl::GetCommandSize(const std::string& command) {
  uint32_t size;
  if (!ExtractCommandSize(command, &size)) {
    LOG(ERROR) << "Command too small.";
    return command.size();
  }
  return size;
}

std::string TpmExecutorTpm2Impl::RunCommand(const std::string& command) {
  // TODO(yich): ExecuteCommand would mutate the command buffer, so we created a
  // copy of the input command at here.
  std::string command_copy = command;
  unsigned char* command_ptr =
      reinterpret_cast<unsigned char*>(command_copy.data());

  for (const auto& vendor_cmd : vendor_commands_) {
    if (vendor_cmd->IsVendorCommand(command)) {
      return vendor_cmd->RunCommand(command);
    }
  }

  unsigned int response_size;
  unsigned char* response;
  tpm2::ExecuteCommand(command.size(), command_ptr, &response_size, &response);
  return std::string(reinterpret_cast<char*>(response), response_size);
}

}  // namespace tpm2_simulator
