// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <brillo/errors/error_codes.h>
#include <chromeos/dbus/service_constants.h>
#include <google-lpa/lpa/core/lpa.h>
#include <google-lpa/lpa/data/activation_code.h>
#include <google-lpa/lpa/data/proto/euicc_info_1.pb.h>
#include <metrics/structured_events.h>

// USE_INTERNAL is set if ChromeOS is being compiled.
#if USE_INTERNAL
#include <ThalesCOSUpdate/COSUpdateHermesManager.h>
#endif

#include "hermes/euicc.h"
#include "hermes/euicc_cache.h"
#include "hermes/executor.h"
#include "hermes/hermes_common.h"
#include "hermes/lpa_util.h"
#include "hermes/type_traits.h"

using lpa::proto::ProfileInfo;

namespace hermes {

namespace {

const char kDefaultProdRootSmds[] = "1$lpa.ds.gsma.com$";
const char kDefaultTestRootSmds[] = "1$testrootsmds.example.com$";

void PrintEuiccEventResult(int err) {
  if (err) {
    LOG(ERROR) << "ProcessEuiccEvent failed with err=" << err;
    return;
  }
  VLOG(2) << "ProcessEuiccEvent succeeded";
}

}  // namespace

Euicc::Euicc(uint8_t physical_slot, EuiccSlotInfo slot_info)
    : physical_slot_(physical_slot),
      slot_info_(std::move(slot_info)),
      is_test_mode_(false),
      use_test_certs_(false),
      context_(Context::Get()),
      dbus_adaptor_(context_->adaptor_factory()->CreateEuiccAdaptor(this)),
      weak_factory_(this) {
  dbus_adaptor_->SetPhysicalSlot(physical_slot_);
  if (EuiccCache::CacheExists(physical_slot)) {
    CachedEuicc cached_euicc;
    EuiccCache::Read(physical_slot, &cached_euicc);
    dbus_adaptor_->SetProfilesRefreshedAtLeastOnce(
        cached_euicc.profiles_refreshed_at_least_once());
  } else {
    dbus_adaptor_->SetProfilesRefreshedAtLeastOnce(false);
  }
  UpdateSlotInfo(slot_info_);
}

void Euicc::UpdateSlotInfo(EuiccSlotInfo slot_info) {
  slot_info_ = std::move(slot_info);
  dbus_adaptor_->SetEid(slot_info_.eid_);
  dbus_adaptor_->SetIsActive(slot_info_.IsActive());
}

void Euicc::UpdateLogicalSlot(std::optional<uint8_t> logical_slot) {
  slot_info_.SetLogicalSlot(std::move(logical_slot));
  dbus_adaptor_->SetIsActive(slot_info_.IsActive());
}

void Euicc::InstallProfileFromActivationCode(
    std::string activation_code,
    std::string confirmation_code,
    DbusResult<dbus::ObjectPath> dbus_result) {
  std::unique_ptr<lpa::data::ActivationCode> ac_ptr =
      lpa::data::ActivationCode::FromString(activation_code);
  LOG(INFO) << __func__ << ": SMDP="
            << (ac_ptr ? std::hash<std::string>{}(ac_ptr->smdp_addr()) : 0);
  if (context_->dbus_ongoing_) {
    context_->executor()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&Euicc::InstallProfileFromActivationCode,
                       weak_factory_.GetWeakPtr(), std::move(activation_code),
                       std::move(confirmation_code), std::move(dbus_result)),
        kLpaRetryDelay);
    return;
  }
  context_->dbus_ongoing_ = true;
  auto download_profile =
      base::BindOnce(&Euicc::DownloadProfile, weak_factory_.GetWeakPtr(),
                     std::move(activation_code), std::move(confirmation_code));
  InitEuicc(InitEuiccStep::CHECK_IF_INITIALIZED, std::move(download_profile),
            std::move(dbus_result));
}

void Euicc::DownloadProfile(std::string activation_code,
                            std::string confirmation_code,
                            DbusResult<dbus::ObjectPath> dbus_result) {
  LOG(INFO) << __func__;
  auto profile_cb = [dbus_result{std::move(dbus_result)}, this](
                        lpa::proto::ProfileInfo& info, int error) mutable {
    OnProfileInstalled(info, error, std::move(dbus_result));
  };
  if (activation_code.empty()) {
    context_->lpa()->GetDefaultProfileFromSmdp("", context_->executor(),
                                               std::move(profile_cb));
    return;
  }

  lpa::core::Lpa::DownloadOptions options;
  options.enable_profile = false;
  options.allow_policy_rules = false;
  options.confirmation_code = confirmation_code;
  context_->lpa()->DownloadProfile(activation_code, std::move(options),
                                   context_->executor(), std::move(profile_cb));
}

void Euicc::InstallPendingProfile(dbus::ObjectPath profile_path,
                                  std::string confirmation_code,
                                  DbusResult<dbus::ObjectPath> dbus_result) {
  LOG(INFO) << __func__ << " " << GetObjectPathForLog(profile_path);
  auto iter =
      find_if(profiles_.begin(), profiles_.end(),
              [&profile_path](
                  const std::pair<const std::string, std::unique_ptr<Profile>>&
                      iccid_profile_pair) {
                return iccid_profile_pair.second->object_path() == profile_path;
              });
  if (iter == profiles_.end()) {
    dbus_result.Error(brillo::Error::Create(
        FROM_HERE, brillo::errors::dbus::kDomain, kErrorInvalidParameter,
        "Could not find Profile " + profile_path.value()));
    return;
  }

  std::string activation_code = iter->second.get()->GetActivationCode();
  InstallProfileFromActivationCode(std::move(activation_code),
                                   std::move(confirmation_code),
                                   std::move(dbus_result));
}

void Euicc::UninstallProfile(dbus::ObjectPath profile_path,
                             DbusResult<> dbus_result) {
  LOG(INFO) << __func__ << " " << GetObjectPathForLog(profile_path);
  if (context_->dbus_ongoing_) {
    context_->executor()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&Euicc::UninstallProfile, weak_factory_.GetWeakPtr(),
                       std::move(profile_path), std::move(dbus_result)),
        kLpaRetryDelay);
    return;
  }
  context_->dbus_ongoing_ = true;
  const Profile* matching_profile = nullptr;
  for (auto& profile : profiles_) {
    if (profile.second->object_path() == profile_path) {
      matching_profile = profile.second.get();
      break;
    }
  }
  if (!matching_profile) {
    dbus_result.Error(brillo::Error::Create(
        FROM_HERE, brillo::errors::dbus::kDomain, kErrorInvalidParameter,
        "Could not find Profile " + profile_path.value()));
    return;
  }

  auto delete_profile =
      base::BindOnce(&Euicc::DeleteProfile, weak_factory_.GetWeakPtr(),
                     matching_profile->GetIccid());
  context_->modem_control()->ProcessEuiccEvent(
      {physical_slot_, EuiccStep::START},
      base::BindOnce(&Euicc::RunOnSuccess<>, weak_factory_.GetWeakPtr(),
                     EuiccOp::UNINSTALL, std::move(delete_profile),
                     std::move(dbus_result)));
}

void Euicc::DeleteProfile(std::string iccid, DbusResult<> dbus_result) {
  context_->lpa()->DeleteProfile(
      iccid, context_->executor(),
      [dbus_result{std::move(dbus_result)}, iccid, this](int error) mutable {
        OnProfileUninstalled(std::move(iccid), error, std::move(dbus_result));
      });
}

void Euicc::UpdateProfilesProperty() {
  std::vector<dbus::ObjectPath> profile_paths;
  LOG(INFO) << __func__;
  for (auto& profile : profiles_) {
    profile_paths.push_back(profile.second->object_path());
  }
  dbus_adaptor_->SetInstalledProfiles(profile_paths);
  dbus_adaptor_->SetProfiles(profile_paths);
  if (EuiccCache::CacheExists(physical_slot_)) {
    CachedEuicc cached_euicc;
    EuiccCache::Read(physical_slot_, &cached_euicc);
    cached_euicc.set_profiles_refreshed_at_least_once(true);
    if (!EuiccCache::Write(physical_slot_, std::move(cached_euicc))) {
      LOG(ERROR) << "Couldn't write EID to cache.";
    }
  }
  dbus_adaptor_->SetProfilesRefreshedAtLeastOnce(true);
}

void Euicc::OnProfileInstalled(const lpa::proto::ProfileInfo& profile_info,
                               int error,
                               DbusResult<dbus::ObjectPath> dbus_result) {
  LOG(INFO) << __func__;
  auto decoded_error = LpaErrorToBrillo(FROM_HERE, error);
  if (decoded_error) {
    EndEuiccOp(EuiccOp::INSTALL, dbus_result, std::move(decoded_error), error);
    return;
  }

  std::unique_ptr<Profile> profile;
  if (profiles_.find(profile_info.iccid()) != profiles_.end()) {
    DCHECK(profiles_[profile_info.iccid()]->GetState() == profile::kPending);
    profiles_[profile_info.iccid()]->SetState(profile::kInactive);
  } else {
    profile = Profile::Create(profile_info, physical_slot_, slot_info_.eid_,
                              /*is_pending*/ false,
                              base::BindRepeating(&Euicc::OnProfileEnabled,
                                                  weak_factory_.GetWeakPtr()));
    if (!profile) {
      auto profile_error = brillo::Error::Create(
          FROM_HERE, brillo::errors::dbus::kDomain, kErrorInternalLpaFailure,
          "Failed to create Profile object");
      EndEuiccOp(EuiccOp::INSTALL, dbus_result, std::move(profile_error),
                 kDefaultError);
      return;
    }
    profiles_[profile->GetIccid()] = (std::move(profile));
  }

  UpdateProfilesProperty();
  // Send notifications and refresh LPA profile cache. No errors will be raised
  // if these operations fail since the profile installation already succeeded.
  context_->lpa()->SendNotifications(
      context_->executor(),
      [this, dbus_result{std::move(dbus_result)},
       profile_path{profiles_[profile_info.iccid()]->object_path()}](
          int /*err*/) {
        // Send notifications has completed, refresh the profile cache.
        context_->lpa()->GetInstalledProfiles(
            context_->executor(),
            [this, dbus_result{std::move(dbus_result)}, profile_path](
                std::vector<lpa::proto::ProfileInfo>& profile_infos,
                int /*error*/) {
              EndEuiccOp(EuiccOp::INSTALL, dbus_result, profile_path);
            });
      });
}

void Euicc::OnProfileEnabled(const std::string& iccid) {
  for (auto& installed_profile : profiles_) {
    if (installed_profile.second->GetState() == profile::kPending)
      continue;
    installed_profile.second->SetState(installed_profile.first == iccid
                                           ? profile::kActive
                                           : profile::kInactive);
  }
}

void Euicc::OnProfileUninstalled(std::string iccid,
                                 int error,
                                 DbusResult<> dbus_result) {
  LOG(INFO) << __func__;
  auto decoded_error = LpaErrorToBrillo(FROM_HERE, error);
  if (decoded_error) {
    EndEuiccOp(EuiccOp::UNINSTALL, dbus_result, std::move(decoded_error),
               error);
    return;
  }
  CHECK(profiles_.find(iccid) != profiles_.end());
  profiles_.erase(iccid);
  UpdateProfilesProperty();
  SendNotifications(EuiccOp::UNINSTALL, std::move(dbus_result));
}

void Euicc::SendNotifications(
    EuiccOp euicc_op,
    DbusResult<> dbus_result) {  // Send notifications and refresh LPA profile
                                 // cache. No errors will be raised
  // if these operations fail since the profile operation already succeeded.
  context_->lpa()->SendNotifications(
      context_->executor(),
      [this, euicc_op, dbus_result{std::move(dbus_result)}](int /*err*/) {
        context_->lpa()->GetInstalledProfiles(
            context_->executor(),
            [this, euicc_op, dbus_result{std::move(dbus_result)}](
                std::vector<lpa::proto::ProfileInfo>& profile_infos,
                int /*error*/) { EndEuiccOp(euicc_op, dbus_result); });
      });
}

void Euicc::RefreshInstalledProfiles(bool restore_slot,
                                     DbusResult<> dbus_result) {
  LOG(INFO) << __func__ << ": restore_slot=" << restore_slot;
  if (context_->dbus_ongoing_) {
    context_->executor()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&Euicc::RefreshInstalledProfiles,
                       weak_factory_.GetWeakPtr(), restore_slot,
                       std::move(dbus_result)),
        kLpaRetryDelay);
    return;
  }
  context_->dbus_ongoing_ = true;
  auto get_installed_profiles = base::BindOnce(
      &Euicc::GetInstalledProfiles, weak_factory_.GetWeakPtr(), restore_slot);
  InitEuicc(InitEuiccStep::CHECK_IF_INITIALIZED,
            std::move(get_installed_profiles), std::move(dbus_result));
}

void Euicc::GetInstalledProfiles(bool restore_slot, DbusResult<> dbus_result) {
  context_->lpa()->GetInstalledProfiles(
      context_->executor(),
      [restore_slot, dbus_result{std::move(dbus_result)}, this](
          std::vector<lpa::proto::ProfileInfo>& profile_infos,
          int error) mutable {
        OnInstalledProfilesReceived(profile_infos, error, restore_slot,
                                    std::move(dbus_result));
      });
}

void Euicc::OnInstalledProfilesReceived(
    const std::vector<lpa::proto::ProfileInfo>& profile_infos,
    int error,
    bool restore_slot,
    DbusResult<> dbus_result) {
  LOG(INFO) << __func__;
  auto decoded_error = LpaErrorToBrillo(FROM_HERE, error);
  if (decoded_error) {
    LOG(ERROR) << "Failed to retrieve installed profiles";
    EndEuiccOp(EuiccOp::REFRESH_INSTALLED, dbus_result,
               std::move(decoded_error), error);
    return;
  }
  for (auto it = profiles_.cbegin(); it != profiles_.cend();) {
    if (it->second->GetState() != profile::kPending) {
      it = profiles_.erase(it);
    } else {
      ++it;
    }
  }
  for (const auto& info : profile_infos) {
    if (!is_test_mode_ &&
        info.profile_class() == lpa::proto::ProfileClass::TESTING)
      continue;
    auto profile =
        Profile::Create(info, physical_slot_, slot_info_.eid_,
                        /*is_pending*/ false,
                        base::BindRepeating(&Euicc::OnProfileEnabled,
                                            weak_factory_.GetWeakPtr()));
    if (profile) {
      profiles_[profile->GetIccid()] = std::move(profile);
    }
  }
  UpdateProfilesProperty();
  if (!restore_slot) {
    EndEuiccOp(EuiccOp::REFRESH_INSTALLED, dbus_result);
    return;
  }
  // Restore the active slot and Run end_euicc_op.
  auto end_euicc_op =
      base::BindOnce(&Euicc::EndEuiccOpNoObject, weak_factory_.GetWeakPtr(),
                     EuiccOp::REFRESH_INSTALLED);
  context_->modem_control()->RestoreActiveSlot(
      base::BindOnce(&Euicc::RunOnSuccess<>, weak_factory_.GetWeakPtr(),
                     EuiccOp::REFRESH_INSTALLED, std::move(end_euicc_op),
                     std::move(dbus_result)));
}

/* Deprecated in favor of RefreshPendingProfiles */
void Euicc::RequestPendingProfiles(DbusResult<> dbus_result,
                                   std::string root_smds) {
  LOG(INFO) << __func__;
  if (!context_->lpa()->IsLpaIdle()) {
    context_->executor()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&Euicc::RequestPendingProfiles,
                       weak_factory_.GetWeakPtr(), std::move(dbus_result),
                       std::move(root_smds)),
        kLpaRetryDelay);
    return;
  }
  auto get_pending_profiles_from_smds =
      base::BindOnce(&Euicc::GetPendingProfilesFromSmds,
                     weak_factory_.GetWeakPtr(), std::move(root_smds));
  InitEuicc(InitEuiccStep::CHECK_IF_INITIALIZED,
            std::move(get_pending_profiles_from_smds), std::move(dbus_result));
}

/* Deprecated in favor of RefreshPendingProfiles */
void Euicc::GetPendingProfilesFromSmds(std::string root_smds,
                                       DbusResult<> dbus_result) {
  auto default_smds =
      use_test_certs_ ? kDefaultTestRootSmds : kDefaultProdRootSmds;
  auto smds = root_smds.empty() ? default_smds : root_smds;
  context_->lpa()->GetPendingProfilesFromSmds(
      smds, context_->executor(),
      [dbus_result{std::move(dbus_result)}, this](
          std::vector<lpa::proto::ProfileInfo>& profile_infos,
          int error) mutable {
        OnPendingProfilesReceived(profile_infos, error, std::move(dbus_result));
      });
}

void Euicc::RefreshSmdxProfiles(
    DbusResult<std::vector<dbus::ObjectPath>, std::string> dbus_result,
    const std::string& activation_code,
    bool restore_slot) {
  LOG(INFO) << __func__ << " restore_slot: " << restore_slot;
  VLOG(2) << "activation code: " << activation_code;
  if (!context_->lpa()->IsLpaIdle()) {
    context_->executor()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&Euicc::RefreshSmdxProfiles, weak_factory_.GetWeakPtr(),
                       std::move(dbus_result), std::move(activation_code),
                       restore_slot),
        kLpaRetryDelay);
    return;
  }
  auto get_pending_profiles_from_smds = base::BindOnce(
      &Euicc::GetPendingProfilesFromSmdx, weak_factory_.GetWeakPtr(),
      std::move(activation_code), restore_slot);
  InitEuicc(InitEuiccStep::CHECK_IF_INITIALIZED,
            std::move(get_pending_profiles_from_smds), std::move(dbus_result));
}

void Euicc::GetPendingProfilesFromSmdx(
    std::string activation_code,
    bool restore_slot,
    DbusResult<std::vector<dbus::ObjectPath>, std::string> dbus_result) {
  auto default_smds =
      use_test_certs_ ? kDefaultTestRootSmds : kDefaultProdRootSmds;
  auto smds = activation_code.empty() ? default_smds : activation_code;
  context_->lpa()->GetPendingProfilesFromSmds(
      smds, context_->executor(),
      [dbus_result{std::move(dbus_result)}, restore_slot, this](
          std::vector<lpa::proto::ProfileInfo>& profile_infos,
          int error) mutable {
        OnSmdxProfilesReceived(restore_slot, profile_infos, error,
                               std::move(dbus_result));
      });
}

void Euicc::OnSmdxProfilesReceived(
    bool restore_slot,
    const std::vector<lpa::proto::ProfileInfo>& profile_infos,
    int error,
    DbusResult<std::vector<dbus::ObjectPath>, std::string> dbus_result) {
  LOG(INFO) << __func__;
  auto decoded_error = LpaErrorToBrillo(FROM_HERE, error);
  std::vector<dbus::ObjectPath> profile_paths;
  for (const auto& info : profile_infos) {
    // Do not create a profile if the profile has already been exposed on DBus.
    if (profiles_.find(info.iccid()) != profiles_.end()) {
      profile_paths.push_back(profiles_[info.iccid()]->object_path());
      continue;
    }
    auto profile =
        Profile::Create(info, physical_slot_, slot_info_.eid_,
                        /*is_pending*/ true,
                        base::BindRepeating(&Euicc::OnProfileEnabled,
                                            weak_factory_.GetWeakPtr()));
    if (profile) {
      profile_paths.push_back(profile->object_path());
      profiles_[profile->GetIccid()] = std::move(profile);
    }
  }
  UpdateProfilesProperty();
  if (decoded_error) {
    LOG(ERROR) << "Failed to retrieve pending profiles: "
               << decoded_error->GetCode();
  }
  auto last_scan_err = decoded_error ? decoded_error->GetCode() : "";
  if (!restore_slot) {
    EndEuiccOpPendingProfiles(std::move(profile_paths), last_scan_err,
                              std::move(dbus_result));
    return;
  }
  // Restore the active slot and Run end_euicc_op.
  auto end_euicc_op = base::BindOnce(
      &Euicc::EndEuiccOpPendingProfiles, weak_factory_.GetWeakPtr(),
      std::move(profile_paths), std::move(last_scan_err));
  context_->modem_control()->RestoreActiveSlot(base::BindOnce(
      &Euicc::RunOnSuccess<std::vector<dbus::ObjectPath>, std::string>,
      weak_factory_.GetWeakPtr(), EuiccOp::REQUEST_PENDING,
      std::move(end_euicc_op), std::move(dbus_result)));
}

// OnPendingProfilesReceived will be deprecated once OnSmdxProfilesReceived is
// used by Chrome. b/256892838
void Euicc::OnPendingProfilesReceived(
    const std::vector<lpa::proto::ProfileInfo>& profile_infos,
    int error,
    DbusResult<> dbus_result) {
  LOG(INFO) << __func__;
  auto decoded_error = LpaErrorToBrillo(FROM_HERE, error);

  std::vector<dbus::ObjectPath> profile_paths;
  for (const auto& info : profile_infos) {
    // Do not create a profile if the profile has already been exposed on DBus.
    if (profiles_.find(info.iccid()) != profiles_.end()) {
      continue;
    }
    auto profile =
        Profile::Create(info, physical_slot_, slot_info_.eid_,
                        /*is_pending*/ true,
                        base::BindRepeating(&Euicc::OnProfileEnabled,
                                            weak_factory_.GetWeakPtr()));
    if (profile) {
      profile_paths.push_back(profile->object_path());
      profiles_[profile->GetIccid()] = std::move(profile);
    }
  }
  UpdateProfilesProperty();
  if (decoded_error) {
    LOG(ERROR) << "Failed to retrieve pending profiles";
    EndEuiccOp(EuiccOp::REQUEST_PENDING, dbus_result, std::move(decoded_error),
               error);
    return;
  }
  EndEuiccOp(EuiccOp::REQUEST_PENDING, dbus_result);
}

void Euicc::SetTestModeHelper(bool is_test_mode, DbusResult<> dbus_result) {
  VLOG(2) << __func__ << " : is_test_mode" << is_test_mode;
  if (!context_->lpa()->IsLpaIdle()) {
    context_->executor()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&Euicc::SetTestModeHelper, weak_factory_.GetWeakPtr(),
                       is_test_mode, std::move(dbus_result)),
        kLpaRetryDelay);
    return;
  }
  is_test_mode_ = is_test_mode;
  auto set_test_mode_internal = base::BindOnce(
      &Euicc::SetTestMode, weak_factory_.GetWeakPtr(), is_test_mode);
  context_->modem_control()->ProcessEuiccEvent(
      {physical_slot_, EuiccStep::START, EuiccOp::SET_TEST_MODE},
      base::BindOnce(&Euicc::RunOnSuccess<>, weak_factory_.GetWeakPtr(),
                     EuiccOp::SET_TEST_MODE, std::move(set_test_mode_internal),
                     std::move(dbus_result)));
}

void Euicc::SetTestMode(bool is_test_mode, DbusResult<> dbus_result) {
  VLOG(2) << __func__ << " : is_test_mode" << is_test_mode;
  context_->lpa()->SetTestMode(
      is_test_mode, context_->executor(),
      [this, dbus_result{std::move(dbus_result)}](int error) {
        auto decoded_error = LpaErrorToBrillo(FROM_HERE, error);
        if (decoded_error) {
          EndEuiccOp(EuiccOp::SET_TEST_MODE, dbus_result,
                     std::move(decoded_error), error);
          return;
        }
        EndEuiccOp(EuiccOp::SET_TEST_MODE, dbus_result);
      });
}

void Euicc::UseTestCerts(bool use_test_certs) {
  const std::string kPath("/usr/share/hermes-ca-certificates/");
  // TODO(pholla): b/180422014 - all euicc's share the same LPA. Setting a euicc
  // to use test certs will make other euiccs use test certs too.
  context_->lpa()->SetTlsCertsDir(kPath + (use_test_certs ? "test/" : "prod/"));
  use_test_certs_ = use_test_certs;
}

void Euicc::ResetMemoryHelper(DbusResult<> dbus_result, int reset_options) {
  VLOG(2) << __func__ << " : reset_options: " << reset_options;
  if (!context_->lpa()->IsLpaIdle()) {
    context_->executor()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&Euicc::ResetMemoryHelper, weak_factory_.GetWeakPtr(),
                       std::move(dbus_result), reset_options),
        kLpaRetryDelay);
    return;
  }
  if (reset_options != lpa::data::reset_options::kDeleteOperationalProfiles &&
      reset_options !=
          lpa::data::reset_options::kDeleteFieldLoadedTestProfiles) {
    dbus_result.Error(brillo::Error::Create(
        FROM_HERE, brillo::errors::dbus::kDomain, kErrorInvalidParameter,
        "Illegal value for reset_options."));
    return;
  }

  auto reset_memory_internal = base::BindOnce(
      &Euicc::ResetMemory, weak_factory_.GetWeakPtr(), reset_options);
  InitEuicc(InitEuiccStep::CHECK_IF_INITIALIZED,
            std::move(reset_memory_internal), std::move(dbus_result));
}

void Euicc::ResetMemory(int reset_options, DbusResult<> dbus_result) {
  bool reset_uicc = false;  // Ignored by the lpa.
  context_->lpa()->ResetMemory(
      reset_options, reset_uicc, context_->executor(),
      [this, dbus_result{std::move(dbus_result)}](int error) {
        auto decoded_error = LpaErrorToBrillo(FROM_HERE, error);
        if (decoded_error) {
          EndEuiccOp(EuiccOp::RESET_MEMORY, dbus_result,
                     std::move(decoded_error), error);
          return;
        }
        profiles_.clear();
        UpdateProfilesProperty();
        SendNotifications(EuiccOp::RESET_MEMORY, std::move(dbus_result));
      });
}

void Euicc::IsTestEuicc(DbusResult<bool> dbus_result) {
  LOG(INFO) << __func__;
  if (!context_->lpa()->IsLpaIdle()) {
    context_->executor()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&Euicc::IsTestEuicc, weak_factory_.GetWeakPtr(),
                       std::move(dbus_result)),
        kLpaRetryDelay);
    return;
  }
  auto get_euicc_info_1 =
      base::BindOnce(&Euicc::GetEuiccInfo1, weak_factory_.GetWeakPtr());
  context_->modem_control()->ProcessEuiccEvent(
      {physical_slot_, EuiccStep::START, EuiccOp::GET_EUICC_INFO1},
      base::BindOnce(&Euicc::RunOnSuccess<bool>, weak_factory_.GetWeakPtr(),
                     EuiccOp::GET_EUICC_INFO1, std::move(get_euicc_info_1),
                     std::move(dbus_result)));
}

void Euicc::GetEuiccInfo1(DbusResult<bool> dbus_result) {
  LOG(INFO) << __func__;

  context_->lpa()->GetEuiccInfo1(
      context_->executor(),
      [this, dbus_result{std::move(dbus_result)}](
          lpa::proto::EuiccInfo1& euicc_info_1, int error) {
        LOG(INFO) << "euicc_info_1:" << euicc_info_1.DebugString();
        auto decoded_error = LpaErrorToBrillo(FROM_HERE, error);
        if (decoded_error) {
          EndEuiccOp(EuiccOp::GET_EUICC_INFO1, dbus_result,
                     std::move(decoded_error), error);
          return;
        }
        constexpr char kTestEuiccInfo1[] =
            "665A1433D67C1A2C5DB8B52C967F10A057BA5CB2";
        for (const auto& pkid : euicc_info_1.pkid_for_verif()) {
          if (pkid == kTestEuiccInfo1) {
            EndEuiccOp(EuiccOp::GET_EUICC_INFO1, dbus_result, true);
            return;
          }
        }
        EndEuiccOp(EuiccOp::GET_EUICC_INFO1, dbus_result, false);
      });
}

template <typename... T>
void Euicc::EndEuiccOp(EuiccOp euicc_op,
                       DbusResult<T...> dbus_result,
                       T... object) {
  auto send_dbus_response = base::BindOnce(
      [](EuiccOp euicc_op, Context* context,
         const DbusResult<T...>& dbus_result, const T&... object, int err) {
        PrintEuiccEventResult(err);
        dbus_result.Success(object...);
        context->dbus_ongoing_ = false;
        ::metrics::structured::events::cellular::HermesOp()
            .SetOperation(to_underlying(euicc_op))
            .SetResult(kSuccess)
            .Record();
      },
      euicc_op, this->context_, dbus_result, object...);
  context_->modem_control()->ProcessEuiccEvent({physical_slot_, EuiccStep::END},
                                               std::move(send_dbus_response));
}

// Remove variadic template, and polymorphism on EndEuiccOp for use in lambdas
// and callbacks.
void Euicc::EndEuiccOpNoObject(EuiccOp euicc_op, DbusResult<> dbus_result) {
  EndEuiccOp(euicc_op, std::move(dbus_result));
}

void Euicc::EndEuiccOpPendingProfiles(
    std::vector<dbus::ObjectPath> profile_paths,
    std::string last_scan_err,
    DbusResult<std::vector<dbus::ObjectPath>, std::string> dbus_result) {
  EndEuiccOp(EuiccOp::REQUEST_PENDING, std::move(dbus_result),
             std::move(profile_paths), std::move(last_scan_err));
}

template <typename... T>
void Euicc::EndEuiccOp(EuiccOp euicc_op,
                       DbusResult<T...> dbus_result,
                       brillo::ErrorPtr error,
                       int error_code_for_metrics) {
  auto send_dbus_response = base::BindOnce(
      [](const EuiccOp euicc_op, Context* context,
         const DbusResult<T...>& dbus_result, brillo::ErrorPtr error,
         int error_code_for_metrics, int euicc_event_err) {
        PrintEuiccEventResult(euicc_event_err);
        dbus_result.Error(error);
        context->dbus_ongoing_ = false;
        ::metrics::structured::events::cellular::HermesOp()
            .SetOperation(to_underlying(euicc_op))
            .SetResult(error_code_for_metrics)
            .Record();
      },
      euicc_op, this->context_, dbus_result, std::move(error),
      error_code_for_metrics);
  context_->modem_control()->ProcessEuiccEvent(
      {physical_slot_, EuiccStep::END, euicc_op},
      std::move(send_dbus_response));
}

template <typename... T>
void Euicc::RunOnSuccess(EuiccOp euicc_op,
                         base::OnceCallback<void(DbusResult<T...>)> cb,
                         DbusResult<T...> dbus_result,
                         int err) {
  if (err) {
    LOG(ERROR) << "Received modem error: " << err;
    auto decoded_error = brillo::Error::Create(
        FROM_HERE, brillo::errors::dbus::kDomain, GetDBusError(err),
        "QMI/MBIM operation failed with code: " + std::to_string(err));
    EndEuiccOp(euicc_op, dbus_result, std::move(decoded_error), err);
    return;
  }
  std::move(cb).Run(std::move(dbus_result));
}

#if USE_INTERNAL
template <typename... T>
void Euicc::OnFWUpdated(
    base::OnceCallback<void(DbusResult<T...>)> passthrough_cb,
    DbusResult<T...> dbus_result,
    int os_update_result) {
  VLOG(2) << __func__ << os_update_result;
  if (os_update_result ==
      Thales::Device::COS::COSUpdateHermesManager::COSUPDATE_RESULT_FAILED) {
    auto decoded_error =
        brillo::Error::Create(FROM_HERE, brillo::errors::dbus::kDomain,
                              kErrorUnknown, "eSIM OS update failed");
    EndEuiccOp(EuiccOp::FW_UPDATE, dbus_result, std::move(decoded_error),
               kDefaultError);
    return;
  }
  auto start_get_card_version = base::BindOnce(
      &Euicc::InitEuicc<T...>, weak_factory_.GetWeakPtr(),
      InitEuiccStep::START_GET_CARD_VERSION, std::move(passthrough_cb));
  context_->modem_control()->ProcessEuiccEvent(
      {physical_slot_, EuiccStep::END, EuiccOp::FW_UPDATE},
      base::BindOnce(&Euicc::RunOnSuccess<T...>, weak_factory_.GetWeakPtr(),
                     EuiccOp::FW_UPDATE, std::move(start_get_card_version),
                     std::move(dbus_result)));
}
#endif

template <typename... T>
void Euicc::InitEuicc(InitEuiccStep step,
                      base::OnceCallback<void(DbusResult<T...>)> cb,
                      DbusResult<T...> dbus_result) {
  LOG(INFO) << __func__ << ": step=" << to_underlying(step);
  switch (step) {
    case InitEuiccStep::CHECK_IF_INITIALIZED:
      if (euicc_initialized_) {
        context_->modem_control()->ProcessEuiccEvent(
            {physical_slot_, EuiccStep::START},
            base::BindOnce(&Euicc::RunOnSuccess<T...>,
                           weak_factory_.GetWeakPtr(), EuiccOp::UNKNOWN,
                           std::move(cb), std::move(dbus_result)));
        return;
      }

      // Check for eSIM fw updates. As of Feb 2022, no eSIM OS updates are
      // required.
      if (base::PathExists(context_->fw_path_)) {
#if USE_INTERNAL
        // Thales's FW updater is closed source. ifdef it out for chromiumos.
        auto update_fw =
            base::BindOnce(&Euicc::InitEuicc<T...>, weak_factory_.GetWeakPtr(),
                           InitEuiccStep::UPDATE_FW, std::move(cb));
        context_->modem_control()->ProcessEuiccEvent(
            {physical_slot_, EuiccStep::START, EuiccOp::FW_UPDATE},
            base::BindOnce(&Euicc::RunOnSuccess<T...>,
                           weak_factory_.GetWeakPtr(), EuiccOp::FW_UPDATE,
                           std::move(update_fw), std::move(dbus_result)));
        return;
#else
        LOG(ERROR) << "FW path specified but fw update library does not exist";
#endif
      }

      InitEuicc(InitEuiccStep::START_GET_CARD_VERSION, std::move(cb),
                std::move(dbus_result));
      break;
    case InitEuiccStep::UPDATE_FW: {
#if USE_INTERNAL
      // Thales's FW updater is closed source. ifdef it out for chromiumos.
      Thales::Device::COS::COSUpdateHermesManager cos_update_hermes_manager;
      auto on_fw_updated =
          base::BindOnce(&Euicc::OnFWUpdated<T...>, weak_factory_.GetWeakPtr(),
                         std::move(cb), std::move(dbus_result));
      // on_fw_updated will call
      // InitEuicc(InitEuiccStep::START_GET_CARD_VERSION)
      cos_update_hermes_manager.doUpdate(
          context_->executor(), context_->modem_control(),
          context_->fw_path_.value(), std::move(on_fw_updated));
#else
      CHECK(false) << "fw update library unavailable";
#endif
      return;
    }
    case InitEuiccStep::START_GET_CARD_VERSION: {
      auto get_card_version =
          base::BindOnce(&Euicc::InitEuicc<T...>, weak_factory_.GetWeakPtr(),
                         InitEuiccStep::GET_CARD_VERSION, std::move(cb));
      context_->modem_control()->ProcessEuiccEvent(
          {physical_slot_, EuiccStep::START, EuiccOp::GET_EUICC_INFO1},
          base::BindOnce(&Euicc::RunOnSuccess<T...>, weak_factory_.GetWeakPtr(),
                         EuiccOp::GET_EUICC_INFO1, std::move(get_card_version),
                         std::move(dbus_result)));
      return;
    }
    case InitEuiccStep::GET_CARD_VERSION: {
      // convert next_step into a copyable type (repeating callback), so that it
      // can be captured in a lambda.
      auto copyable_next_step = base::BindRepeating(
          [](base::OnceCallback<void(DbusResult<T...>)> next_step,
             DbusResult<T...> dbus_result) {
            std::move(next_step).Run(std::move(dbus_result));
          },
          base::Passed(std::move(cb)));
      context_->lpa()->GetEuiccInfo1(
          context_->executor(),
          [this, dbus_result{std::move(dbus_result)}, copyable_next_step](
              lpa::proto::EuiccInfo1& euicc_info_1, int error) {
            LOG(INFO) << "euicc_info_1:" << euicc_info_1.DebugString();
            auto decoded_error = LpaErrorToBrillo(FROM_HERE, error);
            if (decoded_error) {
              EndEuiccOp(EuiccOp::GET_EUICC_INFO1, dbus_result,
                         std::move(decoded_error), error);
              return;
            }
            euicc_initialized_ = true;
            context_->modem_control()->SetCardVersion(
                euicc_info_1.euicc_spec_version());
            copyable_next_step.Run(std::move(dbus_result));
          });
    }
  }
}

}  // namespace hermes
