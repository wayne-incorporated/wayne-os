// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/command_line.h>
#include <base/hash/sha1.h>
#include <base/logging.h>
#include <brillo/syslog_logging.h>
#include <crypto/sha2.h>
#include <vboot/tlcl.h>

namespace {

// The Anti-rollback firmware version data.
constexpr uint32_t kFwIndex = 0x1007;
constexpr char kFwVerRollback[] = "SIMU_FW";

constexpr uint32_t kPPWrite = 1U << 0;
constexpr uint32_t kBootWriteLock = 1U << 14;
constexpr uint32_t kPPRead = 1U << 16;
constexpr uint32_t kAuthRead = 1U << 18;
constexpr uint32_t kPlatformCreate = 1U << 30;

constexpr uint32_t kFwNvAttr =
    kPPWrite | kBootWriteLock | kPPRead | kAuthRead | kPlatformCreate;

// Resizes extend_data to size crypto::kSHA256Length and uses the result to
// extend the indicated PCR.
void ExtendPcr(unsigned int pcr_index, const std::string& extend_data) {
  std::string mode_digest = extend_data;
  mode_digest.resize(crypto::kSHA256Length);
  const uint8_t* extend = reinterpret_cast<const uint8_t*>(mode_digest.c_str());
  TlclExtend(pcr_index, extend, nullptr);
}

// According to the specified boot mode, extends PCR0 as cr50 does.
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

// This program send the commands to the TPM that typically are used by the
// firmware to initialize the TPM
int main(int argc, char* argv[]) {
  // Initialize command line configuration early, as logging will require
  // command line to be initialized
  base::CommandLine::Init(argc, argv);
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);

  TlclLibInit();
  TlclStartup();
  ExtendPcr0BootMode(/*developer_mode=*/1, /*recovery_mode=*/0,
                     /*verified_firmware=*/1);
  // Assign an arbitrary value to PCR1.
  ExtendPcr(/*pcr_index=*/1, /*extend_data=*/"PCR1");

  // Set the anti-rollback firmware version data.
  TlclDefineSpace(kFwIndex, kFwNvAttr, sizeof(kFwVerRollback));
  TlclWrite(kFwIndex, kFwVerRollback, sizeof(kFwVerRollback));

  TlclLockPhysicalPresence();
  TlclSetGlobalLock();
}
