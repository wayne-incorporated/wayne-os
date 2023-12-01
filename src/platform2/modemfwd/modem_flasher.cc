// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "modemfwd/modem_flasher.h"

#include <algorithm>
#include <memory>
#include <utility>
#include <vector>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/stl_util.h>
#include <base/strings/stringprintf.h>
#include <chromeos/switches/modemfwd_switches.h>
#include <dbus/modemfwd/dbus-constants.h>

#include "modemfwd/error.h"
#include "modemfwd/firmware_file.h"
#include "modemfwd/logging.h"
#include "modemfwd/metrics.h"
#include "modemfwd/modem.h"
#include "modemfwd/notification_manager.h"
#include "modemfwd/upstart_job_controller.h"

namespace modemfwd {

namespace {

class InhibitMode {
 public:
  explicit InhibitMode(Modem* modem) : modem_(modem) {
    if (!modem_->SetInhibited(true))
      ELOG(INFO) << "Inhibiting failed";
  }
  ~InhibitMode() {
    if (!modem_->SetInhibited(false))
      ELOG(INFO) << "Uninhibiting failed";
  }

 private:
  Modem* modem_;
};

std::string GetFirmwareVersion(Modem* modem, std::string type) {
  if (type == kFwMain)
    return modem->GetMainFirmwareVersion();
  else if (type == kFwCarrier)
    return modem->GetCarrierFirmwareVersion();
  else if (type == kFwOem)
    return modem->GetOemFirmwareVersion();
  else
    return modem->GetAssocFirmwareVersion(type);
}

}  // namespace

ModemFlasher::ModemFlasher(FirmwareDirectory* firmware_directory,
                           std::unique_ptr<Journal> journal,
                           NotificationManager* notification_mgr,
                           Metrics* metrics)
    : journal_(std::move(journal)),
      firmware_directory_(firmware_directory),
      notification_mgr_(notification_mgr),
      metrics_(metrics) {}

void ModemFlasher::ProcessFailedToPrepareFirmwareFile(
    const base::Location& code_location,
    FlashState* flash_state,
    const std::string& firmware_path,
    brillo::ErrorPtr* err) {
  Error::AddTo(err, code_location, kErrorResultFailedToPrepareFirmwareFile,
               base::StringPrintf("Failed to prepare firmware file: %s",
                                  firmware_path.c_str()));
  notification_mgr_->NotifyUpdateFirmwareCompletedFailure(err->get());
  flash_state->fw_flashed_ = false;
  flash_state->fw_types_flashed_ = 0;
}

base::OnceClosure ModemFlasher::TryFlashForTesting(Modem* modem,
                                                   const std::string& variant,
                                                   brillo::ErrorPtr* err) {
  firmware_directory_->OverrideVariantForTesting(variant);
  return TryFlash(modem, scoped_refptr<dbus::Bus>(), err);
}

uint32_t ModemFlasher::GetFirmwareTypesForMetrics(
    std::vector<FirmwareConfig> flash_cfg) {
  uint32_t fw_types = 0;
  if (flash_cfg.empty())
    return 0;
  for (const auto& info : flash_cfg) {
    std::string fw_type = info.fw_type;
    if (fw_type == kFwMain)
      fw_types |=
          static_cast<int>(metrics::ModemFirmwareType::kModemFirmwareTypeMain);
    else if (fw_type == kFwOem)
      fw_types |=
          static_cast<int>(metrics::ModemFirmwareType::kModemFirmwareTypeOem);
    else if (fw_type == kFwCarrier)
      fw_types |= static_cast<int>(
          metrics::ModemFirmwareType::kModemFirmwareTypeCarrier);
    else if (fw_type == kFwAp)
      fw_types |=
          static_cast<int>(metrics::ModemFirmwareType::kModemFirmwareTypeAp);
    else if (fw_type == kFwDev)
      fw_types |=
          static_cast<int>(metrics::ModemFirmwareType::kModemFirmwareTypeDev);
    else
      fw_types |= static_cast<int>(
          metrics::ModemFirmwareType::kModemFirmwareTypeUnknown);
  }

  ELOG(INFO) << "metrics_fw_types " << fw_types;

  return fw_types;
}

base::OnceClosure ModemFlasher::TryFlash(Modem* modem,
                                         scoped_refptr<dbus::Bus> bus,
                                         brillo::ErrorPtr* err) {
  std::string equipment_id = modem->GetEquipmentId();
  FlashState* flash_state = &modem_info_[equipment_id];
  if (!flash_state->ShouldFlash()) {
    Error::AddTo(
        err, FROM_HERE, kErrorResultFlashFailure,
        base::StringPrintf("Modem with equipment ID \"%s\" failed to flash too "
                           "many times; not flashing",
                           equipment_id.c_str()));
    notification_mgr_->NotifyUpdateFirmwareCompletedFailure(err->get());
    flash_state->fw_flashed_ = false;
    flash_state->fw_types_flashed_ = 0;
    return base::OnceClosure();
  }

  std::string device_id = modem->GetDeviceId();
  std::string current_carrier = modem->GetCarrierId();
  // The real carrier ID before it might be replaced by the generic one
  std::string real_carrier = current_carrier;
  flash_state->OnCarrierSeen(current_carrier);
  FirmwareDirectory::Files files = firmware_directory_->FindFirmware(
      device_id, current_carrier.empty() ? nullptr : &current_carrier);

  // Clear the attach APN if needed for a specific modem/carrier combination.
  if (!real_carrier.empty() && !modem->ClearAttachAPN(real_carrier))
    ELOG(INFO) << "Clear attach APN failed for current carrier.";

  std::vector<FirmwareConfig> flash_cfg;

  std::vector<std::pair<std::string, const FirmwareFileInfo*>> flash_infos;
  if (files.main_firmware.has_value())
    flash_infos.emplace_back(kFwMain, &files.main_firmware.value());
  if (files.oem_firmware.has_value())
    flash_infos.emplace_back(kFwOem, &files.oem_firmware.value());
  for (const auto& assoc_entry : files.assoc_firmware)
    flash_infos.emplace_back(assoc_entry.first, &assoc_entry.second);

  std::map<std::string, std::unique_ptr<FirmwareFile>> flash_files;
  for (const auto& flash_info : flash_infos) {
    const FirmwareFileInfo& file_info = *flash_info.second;
    base::FilePath fw_path = GetFirmwarePath(file_info);
    if (!flash_state->ShouldFlashFirmware(flash_info.first, fw_path))
      continue;

    std::string existing_version = GetFirmwareVersion(modem, flash_info.first);
    ELOG(INFO) << "Found " << flash_info.first << " firmware blob "
               << file_info.version << ", currently installed "
               << flash_info.first << " firmware version: " << existing_version;
    if (file_info.version == existing_version) {
      // We don't need to check the firmware again if there's nothing new.
      // Pretend that we successfully flashed it.
      flash_state->OnFlashedFirmware(flash_info.first, fw_path);
      continue;
    }

    auto firmware_file = std::make_unique<FirmwareFile>();
    if (!firmware_file->PrepareFrom(firmware_directory_->GetFirmwarePath(),
                                    file_info)) {
      ProcessFailedToPrepareFirmwareFile(FROM_HERE, flash_state,
                                         file_info.firmware_path, err);
      return base::OnceClosure();
    }

    // We found different firmware! Add it to the list of firmware to flash.
    flash_cfg.push_back({flash_info.first, firmware_file->path_on_filesystem(),
                         file_info.version});
    flash_files[flash_info.first] = std::move(firmware_file);
  }

  // Check if we need to update the carrier firmware.
  if (!current_carrier.empty() && files.carrier_firmware.has_value() &&
      flash_state->ShouldFlashFirmware(
          kFwCarrier, GetFirmwarePath(files.carrier_firmware.value()))) {
    const FirmwareFileInfo& file_info = files.carrier_firmware.value();

    ELOG(INFO) << "Found carrier firmware blob " << file_info.version
               << " for carrier " << current_carrier;

    // Carrier firmware operates a bit differently. We need to flash if
    // the carrier or the version has changed, or if there wasn't any carrier
    // firmware to begin with.
    std::string carrier_fw_id = modem->GetCarrierFirmwareId();
    std::string carrier_fw_version = modem->GetCarrierFirmwareVersion();
    bool has_carrier_fw =
        !(carrier_fw_id.empty() || carrier_fw_version.empty());
    if (has_carrier_fw) {
      ELOG(INFO) << "Currently installed carrier firmware version "
                 << carrier_fw_version << " for carrier " << carrier_fw_id;
    } else {
      ELOG(INFO) << "No carrier firmware is currently installed";
    }

    if (!has_carrier_fw ||
        !firmware_directory_->IsUsingSameFirmware(device_id, carrier_fw_id,
                                                  current_carrier) ||
        carrier_fw_version != file_info.version) {
      auto firmware_file = std::make_unique<FirmwareFile>();
      if (!firmware_file->PrepareFrom(firmware_directory_->GetFirmwarePath(),
                                      file_info)) {
        ProcessFailedToPrepareFirmwareFile(FROM_HERE, flash_state,
                                           file_info.firmware_path, err);
        return base::OnceClosure();
      }

      flash_cfg.push_back(
          {kFwCarrier, firmware_file->path_on_filesystem(), file_info.version});
      flash_files[kFwCarrier] = std::move(firmware_file);
    }
  } else {
    // Log why we are not flashing the carrier firmware for debug
    if (current_carrier.empty()) {
      ELOG(INFO) << "No carrier found. Is a SIM card inserted?";
    } else if (!files.carrier_firmware.has_value()) {
      // Check if we have carrier firmware matching the SIM's carrier. If not,
      // there's nothing to flash.
      ELOG(INFO) << "No carrier firmware found for carrier " << current_carrier;
    } else {
      // ShouldFlashCarrierFirmware() was false
      ELOG(INFO) << "Already flashed carrier firmware for " << current_carrier;
    }
  }

  // Flash if we have new firmwares
  if (flash_cfg.empty()) {
    // This message is used by tests to track the end of flashing.
    LOG(INFO) << "The modem already has the correct firmware installed";
    notification_mgr_->NotifyUpdateFirmwareCompletedSuccess(
        flash_state->fw_flashed_, flash_state->fw_types_flashed_);
    flash_state->fw_flashed_ = false;
    flash_state->fw_types_flashed_ = 0;
    return base::OnceClosure();
  }
  std::vector<std::string> fw_types;
  std::transform(flash_cfg.begin(), flash_cfg.end(),
                 std::back_inserter(fw_types),
                 [](const FirmwareConfig& cfg) { return cfg.fw_type; });

  InhibitMode _inhibit(modem);
  journal_->MarkStartOfFlashingFirmware(fw_types, device_id, current_carrier);
  metrics_->StartFwFlashTimer();
  if (!modem->FlashFirmwares(flash_cfg)) {
    flash_state->OnFlashFailed();
    journal_->MarkEndOfFlashingFirmware(device_id, current_carrier);
    Error::AddTo(err, FROM_HERE, kErrorResultFailureReturnedByHelper,
                 "Helper failed to flash firmware files");
    notification_mgr_->NotifyUpdateFirmwareCompletedFlashFailure(
        err->get(), GetFirmwareTypesForMetrics(flash_cfg));
    flash_state->fw_flashed_ = false;
    flash_state->fw_types_flashed_ = 0;
    // Stop the flashing timer. We will not report flashing
    // times in failure cases as it will be inconclusive.
    metrics_->StopFwFlashTimer();
    return base::OnceClosure();
  }
  // Report flashing time in successful cases
  metrics_->SendFwFlashTime();
  flash_state->fw_flashed_ = true;
  flash_state->fw_types_flashed_ = GetFirmwareTypesForMetrics(flash_cfg);

  for (const auto& info : flash_cfg) {
    std::string fw_type = info.fw_type;
    base::FilePath path_for_logging = flash_files[fw_type]->path_for_logging();
    flash_state->OnFlashedFirmware(fw_type, path_for_logging);
    ELOG(INFO) << "Flashed " << fw_type << " firmware (" << path_for_logging
               << ") to the modem";
  }
  return base::BindOnce(&Journal::MarkEndOfFlashingFirmware,
                        base::Unretained(journal_.get()), device_id,
                        current_carrier);
}

base::FilePath ModemFlasher::GetFirmwarePath(const FirmwareFileInfo& info) {
  return firmware_directory_->GetFirmwarePath().Append(info.firmware_path);
}

}  // namespace modemfwd
