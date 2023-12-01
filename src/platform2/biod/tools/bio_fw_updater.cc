// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>
#include <stdlib.h>

#include <string>

#include <base/command_line.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/time/time.h>
#include <base/timer/elapsed_timer.h>
#include <brillo/daemons/daemon.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>
#include <base/strings/stringprintf.h>
#include <cros_config/cros_config.h>

#include "biod/biod_config.h"
#include "biod/biod_metrics.h"
#include "biod/biod_version.h"
#include "biod/cros_fp_device.h"
#include "biod/updater/cros_fp_updater.h"
#include "biod/updater/update_reason.h"
#include "biod/updater/update_status.h"
#include "biod/updater/update_utils.h"

using UpdateStatus = biod::updater::UpdateStatus;
using UpdateReason = biod::updater::UpdateReason;
using FwUpdaterStatus = biod::BiodMetrics::FwUpdaterStatus;
using FindFirmwareFileStatus = biod::updater::FindFirmwareFileStatus;

namespace {

constexpr char kHelpText[] =
    "bio_fw_updater ensures the fingerprint mcu has the latest firmware\n";

void LogFWFileVersion(const biod::CrosFpFirmware& fw) {
  biod::CrosFpFirmware::ImageVersion ver = fw.GetVersion();
  LOG(INFO) << "FWFile RO Version: '" << ver.ro_version << "'";
  LOG(INFO) << "FWFile RW Version: '" << ver.rw_version << "'";
}

void LogFPMCUVersion(const biod::CrosFpDevice::EcVersion& ver) {
  LOG(INFO) << "FPMCU RO Version: '" << ver.ro_version << "'";
  LOG(INFO) << "FPMCU RW Version: '" << ver.rw_version << "'";
  LOG(INFO) << "FPMCU Active Image: "
            << biod::CrosFpDeviceUpdate::EcCurrentImageToString(
                   ver.current_image);
}

void LogSetupDirectory(const base::FilePath& log_dir_path) {
  const auto log_file_path = log_dir_path.Append(base::StringPrintf(
      "bio_fw_updater.%s",
      brillo::GetTimeAsLogString(base::Time::Now()).c_str()));

  brillo::UpdateLogSymlinks(log_dir_path.Append("bio_fw_updater.LATEST"),
                            log_dir_path.Append("bio_fw_updater.PREVIOUS"),
                            log_file_path);

  logging::LoggingSettings logging_settings;
  logging_settings.logging_dest = logging::LOG_TO_FILE;
  logging_settings.log_file_path = log_file_path.value().c_str();
  logging_settings.lock_log = logging::DONT_LOCK_LOG_FILE;
  logging::InitLogging(logging_settings);
  logging::SetLogItems(true,    // process ID
                       true,    // thread ID
                       true,    // timestamp
                       false);  // tickcount
}

class UpdaterMetrics {
 public:
  void SetUpdateReason(UpdateReason reason) { update_reason_ = reason; }
  void Finished(FwUpdaterStatus status) {
    uint64_t overall = runtime_.Elapsed().InMilliseconds();
    DLOG(INFO) << "Runtime took " << overall << "ms.";
    metrics_.SendFwUpdaterStatus(status, update_reason_,
                                 static_cast<int>(overall));
  }

 private:
  biod::BiodMetrics metrics_;
  UpdateReason update_reason_ = UpdateReason::kNone;
  base::ElapsedTimer runtime_;
};

}  // namespace

int main(int argc, char* argv[]) {
  UpdaterMetrics metrics;

  DEFINE_string(log_dir, "/var/log/biod", "Directory where logs are written.");
  brillo::FlagHelper::Init(argc, argv, kHelpText);

  const auto log_dir_path = base::FilePath(FLAGS_log_dir);
  if (base::DirectoryExists(log_dir_path)) {
    LogSetupDirectory(log_dir_path);
  } else {
    LOG(ERROR) << "Log directory '" << log_dir_path.value()
               << "' does not exist, using syslog and stderr logging.";
    brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty |
                    brillo::kLogHeader);
  }

  biod::LogVersion();

  biod::BiodSystem system;

  // Check for firmware disable mechanism
  if (biod::updater::UpdateDisallowed(system)) {
    LOG(INFO) << "FPMCU update disabled, exiting.";
    return EXIT_SUCCESS;
  }

  // Check if model supports fingerprint
  brillo::CrosConfig cros_config;
  if (!biod::FingerprintSupported(&cros_config)) {
    LOG(INFO) << "Fingerprint is not supported on this model, exiting.";
    return EXIT_SUCCESS;
  }

  // Find a firmware file that matches the firmware file pattern
  base::FilePath file;
  auto status = biod::updater::FindFirmwareFile(
      base::FilePath(biod::updater::kFirmwareDir), &cros_config, &file);

  if (status == FindFirmwareFileStatus::kBoardUnavailable) {
    LOG(ERROR) << "Fingerprint board name unavailable.";
    return EXIT_FAILURE;
  }

  if (status == FindFirmwareFileStatus::kNoDirectory ||
      status == FindFirmwareFileStatus::kFileNotFound) {
    LOG(INFO) << "No firmware "
              << ((status == FindFirmwareFileStatus::kNoDirectory) ? "directory"
                                                                   : "file")
              << " on rootfs, exiting.";

    return EXIT_SUCCESS;
  }
  if (status == FindFirmwareFileStatus::kMultipleFiles) {
    LOG(ERROR) << "Found more than one firmware file, aborting.";
    metrics.Finished(FwUpdaterStatus::kFailureFirmwareFileMultiple);
    return EXIT_FAILURE;
  }

  biod::CrosFpFirmware fw(file);
  if (!fw.IsValid()) {
    LOG(ERROR) << "Failed to load firmware file '" << fw.GetPath().value()
               << "': " << fw.GetStatusString();
    LOG(ERROR) << "We are aborting update.";
  }
  switch (fw.GetStatus()) {
    case biod::CrosFpFirmware::Status::kUninitialized:
      NOTREACHED();
      return EXIT_FAILURE;
    case biod::CrosFpFirmware::Status::kOk:
      break;
    case biod::CrosFpFirmware::Status::kNotFound:
      metrics.Finished(FwUpdaterStatus::kFailureFirmwareFileNotFound);
      return EXIT_FAILURE;
    case biod::CrosFpFirmware::Status::kOpenError:
      metrics.Finished(FwUpdaterStatus::kFailureFirmwareFileOpen);
      return EXIT_FAILURE;
    case biod::CrosFpFirmware::Status::kBadFmap:
      metrics.Finished(FwUpdaterStatus::kFailureFirmwareFileFmap);
      return EXIT_FAILURE;
  }
  LogFWFileVersion(fw);

  biod::CrosFpDeviceUpdate ec_device;
  biod::CrosFpBootUpdateCtrl boot_ctrl;

  auto ecver = ec_device.GetVersion();
  if (!ecver) {
    LOG(INFO) << "Failed to fetch EC version, aborting.";
    metrics.Finished(FwUpdaterStatus::kFailurePreUpdateVersionCheck);
    return EXIT_FAILURE;
  }
  LogFPMCUVersion(*ecver);

  auto result =
      biod::updater::DoUpdate(ec_device, boot_ctrl, fw, system, &cros_config);
  metrics.SetUpdateReason(result.reason);
  switch (result.status) {
    case UpdateStatus::kUpdateFailedGetVersion:
      LOG(INFO) << "Failed to fetch EC version, aborting.";
      metrics.Finished(FwUpdaterStatus::kFailureUpdateVersionCheck);
      return EXIT_FAILURE;
    case UpdateStatus::kUpdateFailedFlashProtect:
      LOG(ERROR) << "Failed to fetch flash protect status, aborting.";
      metrics.Finished(FwUpdaterStatus::kFailureUpdateFlashProtect);
      return EXIT_FAILURE;
    case UpdateStatus::kUpdateFailedRO:
      LOG(ERROR) << "Failed to update RO image, aborting.";
      metrics.Finished(FwUpdaterStatus::kFailureUpdateRO);
      return EXIT_FAILURE;
    case UpdateStatus::kUpdateFailedRW:
      LOG(ERROR) << "Failed to update RW image, aborting.";
      metrics.Finished(FwUpdaterStatus::kFailureUpdateRW);
      return EXIT_FAILURE;
    case UpdateStatus::kUpdateSucceeded:
    case UpdateStatus::kUpdateSucceededNeedPowerReset:
      if (result.status == UpdateStatus::kUpdateSucceededNeedPowerReset) {
        LOG(WARNING) << "FPMCU software write protect enabled while system"
                        " hardware write protect is disabled. FPMCU won't"
                        " respond after flashing until DUT reboot due to"
                        " http://go/flashrom-fpmcu-wp-bug. Skip version"
                        " check.";
      } else {
        ecver = ec_device.GetVersion();
        if (!ecver) {
          LOG(ERROR) << "Failed to fetch final EC version, update failed.";
          metrics.Finished(FwUpdaterStatus::kFailurePostUpdateVersionCheck);
          return EXIT_FAILURE;
        }
        LogFPMCUVersion(*ecver);
      }

      LOG(INFO) << "The update was successful.";
      metrics.Finished(FwUpdaterStatus::kSuccessful);
      return EXIT_SUCCESS;
    case UpdateStatus::kUpdateNotNecessary:
      LOG(INFO) << "Update was not necessary.";
      metrics.Finished(FwUpdaterStatus::kUnnecessary);
      return EXIT_SUCCESS;
  }

  NOTREACHED();
  return EXIT_SUCCESS;
}
