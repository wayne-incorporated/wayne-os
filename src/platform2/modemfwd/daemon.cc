// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "modemfwd/daemon.h"
#include "modemfwd/modem_sandbox.h"

#include <signal.h>
#include <sysexits.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/containers/contains.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_runner.h>
#include <base/time/time.h>
#include <cros_config/cros_config.h>
#include <dbus/modemfwd/dbus-constants.h>
#include <sys/wait.h>

#include "modemfwd/dlc_manager.h"
#include "modemfwd/error.h"
#include "modemfwd/firmware_directory.h"
#include "modemfwd/logging.h"
#include "modemfwd/metrics.h"
#include "modemfwd/modem.h"
#include "modemfwd/modem_flasher.h"
#include "modemfwd/modem_helper_directory.h"
#include "modemfwd/modem_tracker.h"
#include "modemfwd/notification_manager.h"

#include "modemfwd/proto_bindings/firmware_manifest_v2.pb.h"

namespace {

const char kManifestName[] = "firmware_manifest.textproto";
const char kManifestNameLegacy[] = "firmware_manifest.prototxt";
constexpr base::TimeDelta kWedgeCheckDelay = base::Minutes(5);
constexpr base::TimeDelta kRebootCheckDelay = base::Minutes(1);
constexpr base::TimeDelta kDlcRemovalDelay = base::Minutes(2);
constexpr char kDisableAutoUpdatePref[] =
    "/var/lib/modemfwd/disable_auto_update";

// 3 failures 20 seconds apart gives a strong signal that the modem is in a bad
// state. These values were chosen to try and maximize the time between polls
// to minimize power impact, without relying on too few datapoints. Furthermore
// 60 seconds of detection + 25 seconds of modem reset (targeting FM350 stalls)
// Will allow recovery well before the 120 second suspend timeout and shutdown.
constexpr base::TimeDelta kHeartbeatDelay = base::Seconds(20);
constexpr base::TimeDelta kCmdKillDelay = base::Seconds(1);
const uint8_t kFailedHeartbeatsBeforeRecovery = 3;

// Returns the modem firmware variant for the current model of the device by
// reading the /modem/firmware-variant property of the current model via
// chromeos-config. Returns an empty string if it fails to read the modem
// firmware variant from chromeos-config or no modem firmware variant is
// specified.
std::string GetModemFirmwareVariant() {
  brillo::CrosConfig config;
  std::string variant;
  if (!config.GetString("/modem", "firmware-variant", &variant)) {
    LOG(INFO) << "No modem firmware variant is specified";
    return std::string();
  }

  LOG(INFO) << "Use modem firmware variant: " << variant;
  return variant;
}

std::string ToOnOffString(bool b) {
  return b ? "on" : "off";
}

// Returns the delay to wait before rebooting the modem if it hasn't appeared
// on the USB bus by reading the /modem/wedge-reboot-delay-ms property of the
// current model via chromeos-config, or using the default `kWedgeCheckDelay`
// constant if it fails to read it from chromeos-config or nothing is specified.
base::TimeDelta GetModemWedgeCheckDelay() {
  brillo::CrosConfig config;
  std::string delay_ms;
  if (!config.GetString("/modem", "wedge-reboot-delay-ms", &delay_ms)) {
    return kWedgeCheckDelay;
  }

  int64_t ms;
  if (!base::StringToInt64(delay_ms, &ms)) {
    LOG(WARNING) << "Invalid wedge-reboot-delay-ms attribute " << delay_ms
                 << " using default " << kWedgeCheckDelay;
    return kWedgeCheckDelay;
  }

  base::TimeDelta wedge_delay = base::Milliseconds(ms);
  LOG(INFO) << "Use customized wedge reboot delay: " << wedge_delay;
  return wedge_delay;
}

bool IsAutoUpdateDisabledByPref() {
  const base::FilePath pref_path(kDisableAutoUpdatePref);
  std::string contents;
  if (!base::ReadFileToString(pref_path, &contents))
    return false;

  int pref_value;
  if (!base::StringToInt(base::TrimWhitespaceASCII(contents, base::TRIM_ALL),
                         &pref_value))
    return false;

  return (pref_value == 1);
}

}  // namespace

namespace modemfwd {

DBusAdaptor::DBusAdaptor(scoped_refptr<dbus::Bus> bus, Daemon* daemon)
    : org::chromium::ModemfwdAdaptor(this),
      dbus_object_(nullptr, bus, dbus::ObjectPath(kModemfwdServicePath)),
      daemon_(daemon) {
  DCHECK(daemon);
}

void DBusAdaptor::RegisterAsync(
    brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb) {
  RegisterWithDBusObject(&dbus_object_);
  dbus_object_.RegisterAsync(std::move(cb));
}

void DBusAdaptor::SetDebugMode(bool debug_mode) {
  g_extra_logging = debug_mode;
  LOG(INFO) << "Debug mode is now " << ToOnOffString(ELOG_IS_ON());
}

bool DBusAdaptor::ForceFlash(const std::string& device_id,
                             const brillo::VariantDictionary& args) {
  std::string carrier_uuid =
      brillo::GetVariantValueOrDefault<std::string>(args, "carrier_uuid");
  std::string variant =
      brillo::GetVariantValueOrDefault<std::string>(args, "variant");
  bool use_modems_fw_info =
      brillo::GetVariantValueOrDefault<bool>(args, "use_modems_fw_info");
  return daemon_->ForceFlashForTesting(device_id, carrier_uuid, variant,
                                       use_modems_fw_info);
}

Daemon::Daemon(const std::string& journal_file,
               const std::string& helper_directory,
               const std::string& firmware_directory)
    : DBusServiceDaemon(kModemfwdServiceName),
      journal_file_path_(journal_file),
      helper_dir_path_(helper_directory),
      fw_manifest_dir_path_(firmware_directory),
      weak_ptr_factory_(this) {}

int Daemon::OnInit() {
  int exit_code = brillo::DBusServiceDaemon::OnInit();
  if (exit_code != EX_OK)
    return exit_code;
  DCHECK(!helper_dir_path_.empty());

  std::unique_ptr<MetricsLibraryInterface> metrics_library =
      std::make_unique<MetricsLibrary>();
  metrics_ = std::make_unique<Metrics>(std::move(metrics_library));
  metrics_->Init();

  notification_mgr_ = std::make_unique<NotificationManager>(dbus_adaptor_.get(),
                                                            metrics_.get());
  if (!base::DirectoryExists(helper_dir_path_)) {
    auto err = Error::Create(
        FROM_HERE, kErrorResultInitFailure,
        base::StringPrintf(
            "Supplied modem-specific helper directory %s does not exist",
            helper_dir_path_.value().c_str()));
    notification_mgr_->NotifyUpdateFirmwareCompletedFailure(err.get());
    return EX_UNAVAILABLE;
  }

  variant_ = GetModemFirmwareVariant();
  helper_directory_ =
      CreateModemHelperDirectory(helper_dir_path_, variant_, bus_);
  if (!helper_directory_) {
    auto err =
        Error::Create(FROM_HERE,
                      (variant_.empty() ? kErrorResultInitFailureNonLteSku
                                        : kErrorResultInitFailure),
                      base::StringPrintf("No suitable helpers found in %s",
                                         helper_dir_path_.value().c_str()));
    notification_mgr_->NotifyUpdateFirmwareCompletedFailure(err.get());
    return EX_UNAVAILABLE;
  }

  // If no firmware directory was supplied, we can't run.
  if (fw_manifest_dir_path_.empty())
    return EX_UNAVAILABLE;

  if (!base::DirectoryExists(fw_manifest_dir_path_)) {
    auto err = Error::Create(
        FROM_HERE, kErrorResultInitFailure,
        base::StringPrintf("Supplied firmware directory %s does not exist",
                           fw_manifest_dir_path_.value().c_str()));
    notification_mgr_->NotifyUpdateFirmwareCompletedFailure(err.get());
    return EX_UNAVAILABLE;
  }

  return SetupFirmwareDirectory();
}

int Daemon::SetupFirmwareDirectory() {
  CHECK(!fw_manifest_dir_path_.empty());

  std::map<std::string, Dlc> dlc_per_variant;
  auto file_name = base::PathExists(fw_manifest_dir_path_.Append(kManifestName))
                       ? kManifestName
                       : kManifestNameLegacy;
  fw_index_ = ParseFirmwareManifestV2(fw_manifest_dir_path_.Append(file_name),
                                      dlc_per_variant);
  if (!fw_index_) {
    auto err = Error::Create(
        FROM_HERE, kErrorResultInitManifestFailure,
        "Could not load firmware manifest directory (bad manifest?)");
    notification_mgr_->NotifyUpdateFirmwareCompletedFailure(err.get());
    return EX_UNAVAILABLE;
  }

  if (!dlc_per_variant.empty()) {
    LOG(INFO) << "Creating DLC manager";
    dlc_manager_ = std::make_unique<modemfwd::DlcManager>(
        bus_, metrics_.get(), std::move(dlc_per_variant), variant_);
    if (dlc_manager_->DlcId().empty()) {
      LOG(ERROR) << "Unexpected empty DlcId value";
      auto err = Error::Create(FROM_HERE, error::kUnexpectedEmptyDlcId,
                               "Unexpected empty DlcId value");
      metrics_->SendDlcInstallResultFailure(err.get());
    } else {
      InstallModemDlcOnceCallback cb = base::BindOnce(
          &Daemon::InstallDlcCompleted, weak_ptr_factory_.GetWeakPtr());
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE,
          base::BindOnce(&DlcManager::InstallModemDlc,
                         base::Unretained(dlc_manager_.get()), std::move(cb)));
      return EX_OK;
    }
  }
  metrics_->SendFwUpdateLocation(metrics::FwUpdateLocation::kRootFS);
  CompleteInitialization();
  return EX_OK;
}

void Daemon::InstallDlcCompleted(const std::string& mount_path,
                                 const brillo::Error* error) {
  if (error || mount_path.empty()) {
    LOG(INFO) << "Failed to install DLC. Falling back to rootfs";
    metrics_->SendFwUpdateLocation(
        metrics::FwUpdateLocation::kFallbackToRootFS);
    CompleteInitialization();
    return;
  }

  if (dlc_manager_->IsDlcEmpty()) {
    LOG(INFO) << "Ignoring DLC contents, loading FW from rootfs";
    metrics_->SendFwUpdateLocation(metrics::FwUpdateLocation::kRootFS);
  } else {
    fw_manifest_directory_ = CreateFirmwareDirectory(
        std::move(fw_index_), base::FilePath(mount_path), variant_);
    metrics_->SendFwUpdateLocation(metrics::FwUpdateLocation::kDlc);
  }
  CompleteInitialization();
}

void Daemon::CompleteInitialization() {
  if (!fw_manifest_directory_)
    fw_manifest_directory_ = CreateFirmwareDirectory(
        std::move(fw_index_), fw_manifest_dir_path_, variant_);
  DCHECK(fw_manifest_directory_);

  auto journal = OpenJournal(journal_file_path_, fw_manifest_directory_.get(),
                             helper_directory_.get());
  if (!journal) {
    auto err = Error::Create(FROM_HERE, kErrorResultInitJournalFailure,
                             "Could not open journal file");
    notification_mgr_->NotifyUpdateFirmwareCompletedFailure(err.get());
    QuitWithExitCode(EX_UNAVAILABLE);
  }

  modem_flasher_ = std::make_unique<modemfwd::ModemFlasher>(
      fw_manifest_directory_.get(), std::move(journal), notification_mgr_.get(),
      metrics_.get());

  modem_tracker_ = std::make_unique<modemfwd::ModemTracker>(
      bus_,
      base::BindRepeating(&Daemon::OnModemCarrierIdReady,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindRepeating(&Daemon::OnModemDeviceSeen,
                          weak_ptr_factory_.GetWeakPtr()));

  if (dlc_manager_) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&DlcManager::RemoveUnecessaryModemDlcs,
                       base::Unretained(dlc_manager_.get())),
        kDlcRemovalDelay);
  }

  // Check if we have any qcom soc based modems that require a flash before they
  // boot.
  const char kSocInternalDeviceId[] = "soc:*:* (Internal)";
  if (helper_directory_->GetHelperForDeviceId(kSocInternalDeviceId))
    ForceFlash(kSocInternalDeviceId);

  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&Daemon::CheckForWedgedModems,
                     weak_ptr_factory_.GetWeakPtr()),
      GetModemWedgeCheckDelay());
}

void Daemon::OnModemDeviceSeen(std::string device_id,
                               std::string equipment_id) {
  ELOG(INFO) << "Modem seen with equipment ID \"" << equipment_id << "\""
             << " and device ID [" << device_id << "]";
  // Record that we've seen this modem so we don't reboot/auto-force-flash it.
  device_ids_seen_.insert(device_id);

  if (modem_reappear_callbacks_.count(equipment_id) > 0) {
    std::move(modem_reappear_callbacks_[equipment_id]).Run();
    modem_reappear_callbacks_.erase(equipment_id);
  }
}

void Daemon::OnModemCarrierIdReady(
    std::unique_ptr<org::chromium::flimflam::DeviceProxy> device) {
  auto modem = CreateModem(bus_, std::move(device), helper_directory_.get());
  if (!modem)
    return;

  std::string equipment_id = modem->GetEquipmentId();
  std::string device_id = modem->GetDeviceId();

  // Store the modem object to track its health state during its lifetime
  modems_[device_id] = std::move(modem);

  ELOG(INFO) << "Modem with equipment ID \"" << equipment_id << "\""
             << " and device ID [" << device_id << "] ready to flash";

  if (IsAutoUpdateDisabledByPref()) {
    LOG(INFO) << "Update disabled by pref";
    notification_mgr_->NotifyUpdateFirmwareCompletedSuccess(false, 0);
    return;
  }
  brillo::ErrorPtr err;
  StopHeartbeatTimer();
  base::OnceClosure cb =
      modem_flasher_->TryFlash(modems_[device_id].get(), bus_, &err);
  StartHeartbeatTimer();
  if (!cb.is_null())
    modem_reappear_callbacks_[equipment_id] = std::move(cb);
}

void Daemon::RegisterDBusObjectsAsync(
    brillo::dbus_utils::AsyncEventSequencer* sequencer) {
  dbus_adaptor_.reset(new DBusAdaptor(bus_, this));
  dbus_adaptor_->RegisterAsync(
      sequencer->GetHandler("RegisterAsync() failed", true));
}

bool Daemon::ForceFlash(const std::string& device_id) {
  auto stub_modem =
      CreateStubModem(device_id, "", helper_directory_.get(), false);
  if (!stub_modem)
    return false;

  ELOG(INFO) << "Force-flashing modem with device ID [" << device_id << "]";
  brillo::ErrorPtr err;
  StopHeartbeatTimer();
  base::OnceClosure cb = modem_flasher_->TryFlash(stub_modem.get(), bus_, &err);
  StartHeartbeatTimer();
  // We don't know the equipment ID of this modem, and if we're force-flashing
  // then we probably already have a problem with the modem coming up, so
  // cleaning up at this point is not a problem. Run the callback now if we
  // got one.
  if (!cb.is_null())
    std::move(cb).Run();
  return !err;
}

bool Daemon::ForceFlashForTesting(const std::string& device_id,
                                  const std::string& carrier_uuid,
                                  const std::string& variant,
                                  bool use_modems_fw_info) {
  auto stub_modem = CreateStubModem(
      device_id, carrier_uuid, helper_directory_.get(), use_modems_fw_info);
  if (!stub_modem)
    return false;

  ELOG(INFO) << "Force-flashing modem with device ID [" << device_id << "], "
             << "variant [" << variant << "], carrier_uuid [" << carrier_uuid
             << "], use_modems_fw_info [" << use_modems_fw_info << "]";
  brillo::ErrorPtr err;
  StopHeartbeatTimer();
  base::OnceClosure cb =
      modem_flasher_->TryFlashForTesting(stub_modem.get(), variant, &err);
  StartHeartbeatTimer();
  // We don't know the equipment ID of this modem, and if we're force-flashing
  // then we probably already have a problem with the modem coming up, so
  // cleaning up at this point is not a problem. Run the callback now if we
  // got one.
  if (!cb.is_null())
    std::move(cb).Run();
  return !err;
}

void Daemon::CheckForWedgedModems() {
  EVLOG(1) << "Running wedged modems check...";

  // Start long-running monitoring task
  StartHeartbeatTimer();

  helper_directory_->ForEachHelper(
      base::BindRepeating(&Daemon::ForceFlashIfWedged, base::Unretained(this)));
}

void Daemon::ForceFlashIfWedged(const std::string& device_id,
                                ModemHelper* helper) {
  if (device_ids_seen_.count(device_id) > 0) {
    metrics_->SendCheckForWedgedModemResult(
        metrics::CheckForWedgedModemResult::kModemPresent);
    return;
  }

  if (!helper->FlashModeCheck()) {
    LOG(WARNING) << "Modem not found, trying to reset it...";
    if (helper->Reboot()) {
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
          FROM_HERE,
          base::BindOnce(&Daemon::ForceFlashIfNeverAppeared,
                         weak_ptr_factory_.GetWeakPtr(), device_id),
          kRebootCheckDelay);
    } else {
      EVLOG(1) << "Couldn't reboot modem with device ID [" << device_id
               << "], it may not be present";
      // |kFailedToRebootModem| will be sent only on devices with a modem
      // firmware-variant, since devices without a modem will always fail to
      // reboot the non existing modem and will pollute the metrics.
      if (!variant_.empty()) {
        metrics_->SendCheckForWedgedModemResult(
            metrics::CheckForWedgedModemResult::kFailedToRebootModem);
      }
    }
    return;
  }

  metrics_->SendCheckForWedgedModemResult(
      metrics::CheckForWedgedModemResult::kModemWedged);
  LOG(INFO) << "Modem with device ID [" << device_id
            << "] appears to be wedged, attempting recovery";
  ForceFlash(device_id);
}

void Daemon::ForceFlashIfNeverAppeared(const std::string& device_id) {
  if (device_ids_seen_.count(device_id) > 0) {
    metrics_->SendCheckForWedgedModemResult(
        metrics::CheckForWedgedModemResult::kModemPresentAfterReboot);
    return;
  }

  LOG(INFO) << "Modem with device ID [" << device_id
            << "] did not appear after reboot, attempting recovery";
  metrics_->SendCheckForWedgedModemResult(
      metrics::CheckForWedgedModemResult::kModemAbsentAfterReboot);
  ForceFlash(device_id);
}

void Daemon::StartHeartbeatTimer() {
  // Start periodic monitoring task
  for (auto const& modem_info : modems_)
    modem_info.second->ResetHeartbeatFailures();
  heartbeat_timer_.Start(FROM_HERE, kHeartbeatDelay, this,
                         &Daemon::CheckModemIsResponsive);
}

void Daemon::StopHeartbeatTimer() {
  // Stop periodic monitoring task
  for (auto const& modem_info : modems_)
    modem_info.second->ResetHeartbeatFailures();
  heartbeat_timer_.Stop();
}

void Daemon::CheckModemIsResponsive() {
  for (auto const& modem_info : modems_) {
    // We ignore any modems for which we haven't identified a primary port.
    // We either don't have an ability to ping them, or an ability to recover
    // them, so they are ignored.
    if (modem_info.second->GetPrimaryPort().empty())
      continue;

    std::vector<std::string> cmd_args;

    cmd_args.push_back("/usr/bin/mbimcli");
    cmd_args.push_back("-d");
    cmd_args.push_back("/dev/" + modem_info.second->GetPrimaryPort());
    cmd_args.push_back("-p");
    cmd_args.push_back("--query-device-caps");

    const base::FilePath mbimcli_seccomp_policy_file(base::StringPrintf(
        "%s/modemfwd-mbimcli-seccomp.policy", kSeccompPolicyDirectory));
    int ret =
        RunProcessInSandboxWithTimeout(cmd_args, mbimcli_seccomp_policy_file,
                                       true, nullptr, nullptr, kCmdKillDelay);

    HandleModemCheckResult(modem_info.second->GetDeviceId(), ret == 0);
  }
}

void Daemon::ResetModemWithHelper(const std::string& device_id,
                                  ModemHelper* helper) {
  if (!base::Contains(device_id, "pci:14c3:4d75")) {
    LOG(WARNING) << "Not FM350, not attempting recovery";
    metrics_->SendModemRecoveryState(
        metrics::ModemRecoveryState::kRecoveryStateSkipped);
    return;
  }
  // Attempt recovery
  if (helper->Reboot()) {
    LOG(INFO) << "Reboot succeeded";
    modems_[device_id]->ResetHeartbeatFailures();
    metrics_->SendModemRecoveryState(
        metrics::ModemRecoveryState::kRecoveryStateSuccess);
  } else {
    LOG(ERROR) << "Reboot failed";
    metrics_->SendModemRecoveryState(
        metrics::ModemRecoveryState::kRecoveryStateFailure);
  }
}

void Daemon::HandleModemCheckResult(const std::string& device_id,
                                    bool check_result) {
  if (check_result) {
    modems_[device_id]->ResetHeartbeatFailures();
    return;  // All good
  }
  LOG(WARNING) << "Modem ping failed";

  modems_[device_id]->IncrementHeartbeatFailures();
  if (modems_[device_id]->GetHeartbeatFailures() <
      kFailedHeartbeatsBeforeRecovery)
    return;

  ResetModemWithHelper(device_id,
                       helper_directory_->GetHelperForDeviceId(device_id));
}

}  // namespace modemfwd
