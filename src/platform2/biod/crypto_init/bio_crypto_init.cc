// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "biod/crypto_init/bio_crypto_init.h"

#include <fcntl.h>
#include <sys/types.h>

#include <algorithm>
#include <optional>
#include <vector>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/process/process.h>
#include <brillo/daemons/daemon.h>
#include <brillo/secure_blob.h>
#include <brillo/syslog_logging.h>
#include <libec/ec_command.h>

#include "biod/cros_fp_device.h"

using ec::FpSeedCommand;

namespace biod {

// Helper function to ensure data of a file is removed.
bool BioCryptoInit::NukeFile(const base::FilePath& filepath) {
  // Write all zeros to the FD.
  bool ret = true;
  std::vector<uint8_t> zero_vec(FpSeedCommand::kTpmSeedSize, 0);
  if (base::WriteFile(filepath, reinterpret_cast<const char*>(zero_vec.data()),
                      FpSeedCommand::kTpmSeedSize) !=
      FpSeedCommand::kTpmSeedSize) {
    PLOG(ERROR) << "Failed to write all-zero to tmpfs file.";
    ret = false;
  }

  if (!base::DeleteFile(filepath)) {
    PLOG(ERROR) << "Failed to delete TPM seed file: " << filepath.value();
    ret = false;
  }

  return ret;
}

bool BioCryptoInit::WriteSeedToCrosFp(const brillo::SecureVector& seed) {
  if (!InitCrosFp()) {
    return false;
  }

  std::optional<uint32_t> firmware_fp_template_format_version =
      GetFirmwareTemplateVersion();
  if (!firmware_fp_template_format_version.has_value()) {
    return false;
  }

  if (!CrosFpTemplateVersionCompatible(*firmware_fp_template_format_version,
                                       FP_TEMPLATE_FORMAT_VERSION)) {
    LOG(ERROR) << "Incompatible template version between FPMCU ("
               << *firmware_fp_template_format_version << ") and biod ("
               << FP_TEMPLATE_FORMAT_VERSION << ").";
    return false;
  }

  auto fp_seed_cmd = ec_command_factory_->FpSeedCommand(
      seed, *firmware_fp_template_format_version);

  if (!fp_seed_cmd->Run(cros_fp_fd_.get())) {
    LOG(ERROR) << "Failed to set TPM seed.";
    return false;
  }

  LOG(INFO) << "Successfully set FP seed.";

  return true;
}

bool BioCryptoInit::DoProgramSeed(const brillo::SecureVector& tpm_seed) {
  bool ret = true;

  if (!WriteSeedToCrosFp(tpm_seed)) {
    LOG(ERROR) << "Failed to send seed to CrOS FP device.";
    ret = false;
  }

  return ret;
}

base::ScopedFD BioCryptoInit::OpenCrosFpDevice() {
  return base::ScopedFD(
      open(biod::CrosFpDevice::kCrosFpPath, O_RDWR | O_CLOEXEC));
}

bool BioCryptoInit::WaitOnEcBoot(const base::ScopedFD& cros_fp_fd,
                                 ec_image expected_image) {
  return biod::CrosFpDevice::WaitOnEcBoot(cros_fp_fd, expected_image);
}

bool BioCryptoInit::CrosFpTemplateVersionCompatible(
    const uint32_t firmware_fp_template_format_version,
    const uint32_t biod_fp_template_format_version) {
  // We should modify the rule here when we uprev the template format version.
  switch (firmware_fp_template_format_version) {
    case 3:
    case 4:
      break;
    default:
      return false;
  }
  switch (biod_fp_template_format_version) {
    case 3:
    case 4:
      break;
    default:
      return false;
  }
  // If biod has template version 4, firmware with version 3 is still
  // compatible until we deprecate it.
  if (firmware_fp_template_format_version == 3 &&
      biod_fp_template_format_version == 4)
    return true;
  return firmware_fp_template_format_version == biod_fp_template_format_version;
}

bool BioCryptoInit::InitCrosFp() {
  cros_fp_fd_ = OpenCrosFpDevice();
  if (!cros_fp_fd_.is_valid()) {
    PLOG(ERROR) << "Couldn't open FP device for ioctl.";
    return false;
  }

  if (!WaitOnEcBoot(cros_fp_fd_, EC_IMAGE_RW)) {
    LOG(ERROR) << "FP device did not boot to RW.";
    return false;
  }

  return true;
}

std::optional<uint32_t> BioCryptoInit::GetFirmwareTemplateVersion() {
  auto fp_info_cmd = ec_command_factory_->FpInfoCommand();
  if (!fp_info_cmd->RunWithMultipleAttempts(
          cros_fp_fd_.get(), biod::CrosFpDevice::kMaxIoAttempts)) {
    LOG(ERROR) << "Checking template format compatibility: failed to get FP "
                  "information.";
    return std::nullopt;
  }

  return fp_info_cmd->template_info()->version;
}

}  // namespace biod
