// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/tpm_simulator_handle.h"

#include <iterator>
#include <unistd.h>
#include <utility>

#include <base/check_op.h>
#include <base/functional/callback.h>
#include <base/hash/sha1.h>
#include <base/logging.h>
#include <crypto/sha2.h>

extern "C" {
#include <tpm2/_TPM_Init_fp.h>
#include <tpm2/BaseTypes.h>
#include <tpm2/ExecCommand_fp.h>
#include <tpm2/tpm_manufacture.h>
#include <tpm2/TpmBuildSwitches.h>
#include <tpm2/Manufacture_fp.h>  // NOLINT(build/include_alpha) - needs TpmBuildSwitches.h
#include <tpm2/Platform.h>
}  // extern "C"

#include "trunks/error_codes.h"

namespace {

// Resizes extend_data to size crypto::kSHA256Length and uses the result to
// extend the indicated PCR.
void ExtendPcr(unsigned int pcr_index, const std::string& extend_data) {
  std::string mode_digest = extend_data;
  mode_digest.resize(crypto::kSHA256Length);
  trunks::TPM_RC result = extend_pcr(pcr_index, mode_digest.data());
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << "Failed to extend PCR" << pcr_index
               << trunks::GetErrorString(result);
  }
}

// According to the specified boot mode, extends PCR0 as GSC does.
// It should only be called once after the PCR0 value is set to all 0s
// (e.g. running Startup with Clear). Calling it twice without resetting the PCR
// will leave the TPM in an unknown boot mode.
//  - developer_mode: 1 if in developer mode, 0 otherwise,
//  - recovery_mode: 1 if in recovery mode, 0 otherwise,
//  - verified_firmware: 1 if verified firmware, 0 if developer firmware.
void ExtendPcr0BootMode(const char developer_mode,
                        const char recovery_mode,
                        const char verified_firmware) {
  const std::string mode({developer_mode, recovery_mode, verified_firmware});
  ExtendPcr(/*pcr_index=*/0, base::SHA1HashString(mode));
}

}  // namespace

namespace trunks {

TpmSimulatorHandle::TpmSimulatorHandle(std::string simulator_state_directory)
    : simulator_state_directory_(simulator_state_directory) {}

TpmSimulatorHandle::~TpmSimulatorHandle() {}

bool TpmSimulatorHandle::Init() {
  CHECK_EQ(chdir(simulator_state_directory_.c_str()), 0);
  if (!init_) {
    InitializeSimulator();
    init_ = true;
  }
  return true;
}

void TpmSimulatorHandle::InitializeSimulator() {
  // Initialize TPM.
  _plat__Signal_PowerOn();
  /*
   * Make sure NV RAM metadata is initialized, needed to check
   * manufactured status. This is a speculative call which will have to
   * be repeated in case the TPM has not been through the manufacturing
   * sequence yet. No harm in calling it twice in that case.
   */
  _TPM_Init();
  _plat__SetNvAvail();

  if (!tpm_manufactured()) {
    TPM_Manufacture(TRUE);
    // TODO(b/132145000): Verify if the second call to _TPM_Init() is necessary.
    _TPM_Init();
    if (!tpm_endorse())
      LOG(ERROR) << __func__ << " Failed to endorse TPM with a fixed key.";
  }

  // Send TPM2_Startup(TPM_SU_CLEAR), ignore the result. This is normally done
  // by firmware. Without TPM2_Startup, TpmUtility::CheckState() fails,
  // ResourceManager aborts initialization, and trunks daemon dies.
  unsigned int response_size;
  unsigned char* response;
  unsigned char startup_cmd[] = {
      0x80, 0x01,             /* TPM_ST_NO_SESSIONS */
      0x00, 0x00, 0x00, 0x0c, /* commandSize = 12 */
      0x00, 0x00, 0x01, 0x44, /* TPM_CC_Startup */
      0x00, 0x00              /* TPM_SU_CLEAR */
  };
  ExecuteCommand(sizeof(startup_cmd), startup_cmd, &response_size, &response);
  LOG(INFO) << "TPM2_Startup(TPM_SU_CLEAR) sent.";

  ExtendPcr0BootMode(/*developer_mode=*/1, /*recovery_mode=*/0,
                     /*verified_firmware=*/0);
  // Assign an arbitrary value to PCR1.
  ExtendPcr(/*pcr_index=*/1, /*extend_data=*/"PCR1");
}

void TpmSimulatorHandle::SendCommand(const std::string& command,
                                     ResponseCallback callback) {
  std::move(callback).Run(SendCommandAndWait(command));
}

std::string TpmSimulatorHandle::SendCommandAndWait(const std::string& command) {
  if (!init_) {
    InitializeSimulator();
    init_ = true;
  }
  unsigned int response_size;
  unsigned char* response;
  std::string mutable_command(command);
  ExecuteCommand(command.size(),
                 reinterpret_cast<unsigned char*>(std::data(mutable_command)),
                 &response_size, &response);
  return std::string(reinterpret_cast<char*>(response), response_size);
}

}  // namespace trunks
