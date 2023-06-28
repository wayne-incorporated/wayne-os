// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/device_policy_service.h"

#include <secmodt.h>
#include <stdint.h>

#include <utility>
#include <vector>

#include <base/bind.h>
#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/service_constants.h>
#include <chromeos/switches/chrome_switches.h>
#include <crypto/rsa_private_key.h>
#include <crypto/scoped_nss_types.h>
#include <install_attributes/libinstallattributes.h>

#include "bindings/chrome_device_policy.pb.h"
#include "bindings/device_management_backend.pb.h"
#include "login_manager/blob_util.h"
#include "login_manager/dbus_util.h"
#include "login_manager/feature_flags_util.h"
#include "login_manager/key_generator.h"
#include "login_manager/login_metrics.h"
#include "login_manager/owner_key_loss_mitigator.h"
#include "login_manager/policy_key.h"
#include "login_manager/policy_store.h"

namespace em = enterprise_management;

namespace login_manager {
using crypto::RSAPrivateKey;
using google::protobuf::RepeatedPtrField;

namespace {

// Returns true if |policy| was not pushed by an enterprise.
bool IsConsumerPolicy(const em::PolicyFetchResponse& policy) {
  em::PolicyData poldata;
  if (!policy.has_policy_data() ||
      !poldata.ParseFromString(policy.policy_data())) {
    return false;
  }

  // Look at management_mode first.  Refer to PolicyData::management_mode docs
  // for details.
  if (poldata.has_management_mode())
    return poldata.management_mode() == em::PolicyData::LOCAL_OWNER;
  return !poldata.has_request_token() && poldata.has_username();
}

void HandleVpdUpdateCompletion(bool ignore_error,
                               const PolicyService::Completion& completion,
                               bool success) {
  if (completion.is_null()) {
    return;
  }

  if (success || ignore_error) {
    completion.Run(brillo::ErrorPtr());
    return;
  }

  LOG(ERROR) << "Failed to update VPD";
  completion.Run(
      CreateError(dbus_error::kVpdUpdateFailed, "Failed to update VPD"));
}

}  // namespace

// Note: Rollback (go/rollback-data-restore) saves and restores device policy
// files. Any change in format or location of those files that is not backwards
// compatible might break rollback.
// static
const char DevicePolicyService::kPolicyDir[] = "/var/lib/whitelist";
// static
const char DevicePolicyService::kDevicePolicyType[] = "google/chromeos/device";
// static
const char DevicePolicyService::kExtensionPolicyType[] =
    "google/chrome/extension";
// static
const char DevicePolicyService::kRemoteCommandPolicyType[] =
    "google/chromeos/remotecommand";

DevicePolicyService::~DevicePolicyService() = default;

// static
std::unique_ptr<DevicePolicyService> DevicePolicyService::Create(
    PolicyKey* owner_key,
    LoginMetrics* metrics,
    OwnerKeyLossMitigator* mitigator,
    NssUtil* nss,
    Crossystem* crossystem,
    VpdProcess* vpd_process,
    InstallAttributesReader* install_attributes_reader) {
  return base::WrapUnique(new DevicePolicyService(
      base::FilePath(kPolicyDir), owner_key, metrics, mitigator, nss,
      crossystem, vpd_process, install_attributes_reader));
}

bool DevicePolicyService::CheckAndHandleOwnerLogin(
    const std::string& current_user,
    PK11SlotDescriptor* desc,
    bool* is_owner,
    brillo::ErrorPtr* error) {
  // Record metrics around consumer usage of user allowlisting.
  const em::PolicyFetchResponse& policy = GetChromeStore()->Get();
  if (IsConsumerPolicy(policy))
    metrics_->SendConsumerAllowsNewUsers(PolicyAllowsNewUsers(policy));

  // If the current user is the owner, and isn't allowlisted or set as the owner
  // in the settings blob, then do so.
  brillo::ErrorPtr key_error;
  std::unique_ptr<RSAPrivateKey> signing_key =
      GetOwnerKeyForGivenUser(key()->public_key_der(), desc, &key_error);

  // Now, the flip side... if we believe the current user to be the owner based
  // on the user field in policy, and they DON'T have the private half of the
  // public key, we must mitigate.
  *is_owner = GivenUserIsOwner(policy, current_user);
  if (*is_owner && !signing_key.get()) {
    if (!mitigator_->Mitigate(current_user, desc->ns_mnt_path)) {
      *error = std::move(key_error);
      DCHECK(*error);
      return false;
    }
  }
  return true;
}

bool DevicePolicyService::ValidateAndStoreOwnerKey(
    const std::string& current_user,
    const std::vector<uint8_t>& pub_key,
    PK11SlotDescriptor* desc) {
  std::unique_ptr<RSAPrivateKey> signing_key =
      GetOwnerKeyForGivenUser(pub_key, desc, nullptr);
  if (!signing_key.get())
    return false;

  if (mitigator_->Mitigating()) {
    // Mitigating: Depending on whether the public key is still present, either
    // clobber or populate regularly.
    if (!(key()->IsPopulated() ? key()->ClobberCompromisedKey(pub_key)
                               : key()->PopulateFromBuffer(pub_key))) {
      return false;
    }
  } else {
    // Not mitigating, so regular key population should work.
    if (!key()->PopulateFromBuffer(pub_key))
      return false;
    // Clear policy in case we're re-establishing ownership.
    GetChromeStore()->Set(em::PolicyFetchResponse());
  }

  // TODO(cmasone): Remove this as well once the browser can tolerate it:
  // http://crbug.com/472132
  if (StoreOwnerProperties(current_user, signing_key.get())) {
    PostPersistKeyTask();
    PostPersistPolicyTask(MakeChromePolicyNamespace(), Completion());
  } else {
    LOG(WARNING) << "Could not immediately store owner properties in policy";
  }
  return true;
}

DevicePolicyService::DevicePolicyService(
    const base::FilePath& policy_dir,
    PolicyKey* policy_key,
    LoginMetrics* metrics,
    OwnerKeyLossMitigator* mitigator,
    NssUtil* nss,
    Crossystem* crossystem,
    VpdProcess* vpd_process,
    InstallAttributesReader* install_attributes_reader)
    : PolicyService(policy_dir, policy_key, metrics, true),
      mitigator_(mitigator),
      nss_(nss),
      crossystem_(crossystem),
      vpd_process_(vpd_process),
      install_attributes_reader_(install_attributes_reader) {}

bool DevicePolicyService::KeyMissing() {
  return key()->HaveCheckedDisk() && !key()->IsPopulated();
}

bool DevicePolicyService::Mitigating() {
  return mitigator_->Mitigating();
}

bool DevicePolicyService::Initialize() {
  bool key_success = key()->PopulateFromDiskIfPossible();
  if (!key_success)
    LOG(ERROR) << "Failed to load device policy key from disk.";

  bool policy_success = GetChromeStore()->EnsureLoadedOrCreated();
  if (!policy_success)
    LOG(WARNING) << "Failed to load device policy data, continuing anyway.";

  if (!key_success && policy_success &&
      GetChromeStore()->Get().has_new_public_key()) {
    LOG(WARNING) << "Recovering missing owner key from policy blob!";
    key_success = key()->PopulateFromBuffer(
        StringToBlob(GetChromeStore()->Get().new_public_key()));
    if (key_success)
      PostPersistKeyTask();
  }

  ReportPolicyFileMetrics(key_success, policy_success);
  return key_success;
}

bool DevicePolicyService::Store(const PolicyNamespace& ns,
                                const std::vector<uint8_t>& policy_blob,
                                int key_flags,
                                SignatureCheck signature_check,
                                const Completion& completion) {
  bool result = PolicyService::Store(ns, policy_blob, key_flags,
                                     signature_check, completion);

  if (result && ns == MakeChromePolicyNamespace()) {
    // Flush the settings cache, the next read will decode the new settings.
    settings_.reset();
  }

  return result;
}

void DevicePolicyService::ReportPolicyFileMetrics(bool key_success,
                                                  bool policy_success) {
  LoginMetrics::PolicyFilesStatus status;
  if (!key_success) {  // Key load failed.
    status.owner_key_file_state = LoginMetrics::MALFORMED;
  } else {
    if (key()->IsPopulated()) {
      if (nss_->CheckPublicKeyBlob(key()->public_key_der()))
        status.owner_key_file_state = LoginMetrics::GOOD;
      else
        status.owner_key_file_state = LoginMetrics::MALFORMED;
    } else {
      status.owner_key_file_state = LoginMetrics::NOT_PRESENT;
    }
  }

  if (!policy_success) {
    status.policy_file_state = LoginMetrics::MALFORMED;
  } else {
    std::string serialized;
    if (!GetChromeStore()->Get().SerializeToString(&serialized))
      status.policy_file_state = LoginMetrics::MALFORMED;
    else if (serialized == "")
      status.policy_file_state = LoginMetrics::NOT_PRESENT;
    else
      status.policy_file_state = LoginMetrics::GOOD;
  }

  if (GetChromeStore()->DefunctPrefsFilePresent())
    status.defunct_prefs_file_state = LoginMetrics::GOOD;

  metrics_->SendPolicyFilesStatus(status);
}

std::vector<std::string> DevicePolicyService::GetFeatureFlags() {
  using Status = LoginMetrics::SwitchToFeatureFlagMappingStatus;
  auto status = Status::SWITCHES_ABSENT;
  std::vector<std::string> feature_flags;
  const em::ChromeDeviceSettingsProto& settings = GetSettings();

  if (settings.feature_flags().feature_flags_size() > 0) {
    for (const auto& feature_flag : settings.feature_flags().feature_flags()) {
      feature_flags.push_back(feature_flag);
    }
  } else {
    // Previous versions of this code allowed raw switches to be specified in
    // device settings, stored in the now deprecated |switches| proto message
    // field. In order to keep existing device settings data files working, map
    // these switches back to feature flags.
    // TODO(crbug/1104193): Remove compatibility code when no longer needed.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    if (settings.feature_flags().switches_size() > 0) {
      status = Status::SWITCHES_VALID;
      for (const auto& switch_string : settings.feature_flags().switches()) {
        if (!MapSwitchToFeatureFlags(switch_string, &feature_flags)) {
          LOG(WARNING) << "Invalid feature flag switch: " << switch_string;
          status = Status::SWITCHES_INVALID;
        }
      }
    }
#pragma GCC diagnostic pop
  }

  metrics_->SendSwitchToFeatureFlagMappingStatus(status);

  return feature_flags;
}

const em::ChromeDeviceSettingsProto& DevicePolicyService::GetSettings() {
  if (!settings_.get()) {
    settings_.reset(new em::ChromeDeviceSettingsProto());

    em::PolicyData policy_data;
    if (!policy_data.ParseFromString(GetChromeStore()->Get().policy_data()) ||
        !settings_->ParseFromString(policy_data.policy_value())) {
      LOG(ERROR) << "Failed to parse device settings, using empty defaults.";
    }
  }

  return *settings_;
}

// static
bool DevicePolicyService::PolicyAllowsNewUsers(
    const em::PolicyFetchResponse& policy) {
  em::PolicyData poldata;
  if (!policy.has_policy_data() ||
      !poldata.ParseFromString(policy.policy_data())) {
    return false;
  }
  em::ChromeDeviceSettingsProto polval;
  if (!poldata.has_policy_type() ||
      poldata.policy_type() != DevicePolicyService::kDevicePolicyType ||
      !poldata.has_policy_value() ||
      !polval.ParseFromString(poldata.policy_value())) {
    return false;
  }
  // TODO(crbug.com/1103816) - remove whitelist support when no longer supported
  // by DMServer.
  bool has_whitelist_only =
      polval.has_user_whitelist() && !polval.has_user_allowlist();
  bool has_allowlist = has_whitelist_only || polval.has_user_allowlist();
  // Use the allowlist proto by default, and only look at the whitelist proto
  // iff there are no values set for the allowlist proto.
  bool non_empty_allowlist =
      has_whitelist_only ? (polval.has_user_whitelist() &&
                            polval.user_whitelist().user_whitelist_size() > 0)
                         : (polval.has_user_allowlist() &&
                            polval.user_allowlist().user_allowlist_size() > 0);
  // Explicitly states that new users are allowed.
  bool explicitly_allowed = (polval.has_allow_new_users() &&
                             polval.allow_new_users().allow_new_users());
  // Doesn't state that new users are allowed, but also doesn't have a
  // non-empty whitelist or allowlist.
  bool not_disallowed = !polval.has_allow_new_users() && !non_empty_allowlist;
  // States that new users are not allowed, but doesn't specify a whitelist.
  // So, we fail open. Such policies are the result of a long-fixed bug, but
  // we're not certain all users ever got migrated.
  bool failed_open = polval.has_allow_new_users() &&
                     !polval.allow_new_users().allow_new_users() &&
                     !has_allowlist;

  return explicitly_allowed || not_disallowed || failed_open;
}

// static
bool DevicePolicyService::GivenUserIsOwner(
    const enterprise_management::PolicyFetchResponse& policy,
    const std::string& current_user) {
  em::PolicyData poldata;
  if (!policy.has_policy_data() ||
      !poldata.ParseFromString(policy.policy_data())) {
    return false;
  }

  if (!IsConsumerPolicy(policy))
    return false;

  return (poldata.has_username() && poldata.username() == current_user);
}

bool DevicePolicyService::StoreOwnerProperties(const std::string& current_user,
                                               RSAPrivateKey* signing_key) {
  CHECK(signing_key);
  const em::PolicyFetchResponse& policy = GetChromeStore()->Get();
  em::PolicyData poldata;
  if (policy.has_policy_data())
    poldata.ParseFromString(policy.policy_data());
  em::ChromeDeviceSettingsProto polval;
  if (poldata.has_policy_type() && poldata.policy_type() == kDevicePolicyType) {
    if (poldata.has_policy_value())
      polval.ParseFromString(poldata.policy_value());
  } else {
    poldata.set_policy_type(kDevicePolicyType);
  }

  // TODO(crbug.com/1103816) - remove whitelist support when no longer supported
  // by DMServer.
  bool has_whitelist_only =
      polval.has_user_whitelist() && !polval.has_user_allowlist();
  // If there existed some device policy, we've got it now!
  // Update the UserWhitelistProto inside the ChromeDeviceSettingsProto we made.
  bool on_list = false;
  RepeatedPtrField<std::string>* allowlist =
      has_whitelist_only
          ? polval.mutable_user_whitelist()->mutable_user_whitelist()
          : polval.mutable_user_allowlist()->mutable_user_allowlist();

  for (const auto& user : *allowlist) {
    if (current_user == user) {
      on_list = true;
      break;
    }
  }
  if (poldata.has_username() && poldata.username() == current_user && on_list &&
      key()->Equals(policy.new_public_key())) {
    return true;  // No changes are needed.
  }
  if (!on_list) {
    // Add owner to the allowlist and turn off allowlist enforcement if it is
    // currently not explicitly turned on or off.
    allowlist->Add(std::string(current_user));
    if (!polval.has_allow_new_users())
      polval.mutable_allow_new_users()->set_allow_new_users(true);
  }
  poldata.set_username(current_user);

  // We have now updated the allowlist and owner setting in |polval|.
  // We need to put it into |poldata|, serialize that, sign it, and
  // write it back.
  poldata.set_policy_value(polval.SerializeAsString());
  std::string new_data = poldata.SerializeAsString();
  std::vector<uint8_t> sig;
  if (!nss_->Sign(StringToBlob(new_data), signing_key, &sig)) {
    LOG(WARNING) << "Could not sign policy containing new owner data.";
    return false;
  }

  em::PolicyFetchResponse new_policy;
  new_policy.CheckTypeAndMergeFrom(policy);
  new_policy.set_policy_data(new_data);
  new_policy.set_policy_data_signature(BlobToString(sig));
  new_policy.set_new_public_key(BlobToString(key()->public_key_der()));
  GetChromeStore()->Set(new_policy);
  return true;
}

std::unique_ptr<RSAPrivateKey> DevicePolicyService::GetOwnerKeyForGivenUser(
    const std::vector<uint8_t>& key,
    PK11SlotDescriptor* desc,
    brillo::ErrorPtr* error) {
  std::unique_ptr<RSAPrivateKey> result(nss_->GetPrivateKeyForUser(key, desc));
  if (!result) {
    constexpr char kMessage[] =
        "Could not verify that owner key belongs to this user.";
    LOG(WARNING) << kMessage;
    if (error)
      *error = CreateError(dbus_error::kPubkeySetIllegal, kMessage);
    return nullptr;
  }
  return result;
}

void DevicePolicyService::PersistPolicy(const PolicyNamespace& ns,
                                        const Completion& completion) {
  // Run base method for everything other than Chrome device policy.
  if (ns != MakeChromePolicyNamespace()) {
    PolicyService::PersistPolicy(ns, completion);
    return;
  }

  if (!GetOrCreateStore(ns)->Persist()) {
    OnPolicyPersisted(completion, dbus_error::kSigEncodeFail);
    return;
  }

  if (!MayUpdateSystemSettings()) {
    OnPolicyPersisted(completion, dbus_error::kNone);
    return;
  }

  if (UpdateSystemSettings(completion)) {
    // |vpd_process_| will run |completion| when it's done, so pass a null
    // completion to OnPolicyPersisted().
    OnPolicyPersisted(Completion(), dbus_error::kNone);
  } else {
    OnPolicyPersisted(completion, dbus_error::kVpdUpdateFailed);
  }
}

bool DevicePolicyService::MayUpdateSystemSettings() {
  // Check if device ownership is established or if device is enrolled to Active
  // Directory (Chromad).
  if (!key()->IsPopulated() &&
      GetEnterpriseMode() != InstallAttributesReader::kDeviceModeEnterpriseAD) {
    return false;
  }

  // Check whether device is running on Chrome OS firmware.
  char buffer[Crossystem::kVbMaxStringProperty];
  if (!crossystem_->VbGetSystemPropertyString(Crossystem::kMainfwType, buffer,
                                              sizeof(buffer)) ||
      strcmp(Crossystem::kMainfwTypeNonchrome, buffer) == 0) {
    return false;
  }

  return true;
}

bool DevicePolicyService::UpdateSystemSettings(const Completion& completion) {
  const int block_devmode_setting =
      GetSettings().system_settings().block_devmode();
  int block_devmode_value =
      crossystem_->VbGetSystemPropertyInt(Crossystem::kBlockDevmode);
  if (block_devmode_value == -1) {
    LOG(ERROR) << "Failed to read block_devmode flag!";
  }

  // Set crossystem block_devmode flag.
  if (block_devmode_value != block_devmode_setting) {
    if (crossystem_->VbSetSystemPropertyInt(Crossystem::kBlockDevmode,
                                            block_devmode_setting) != 0) {
      LOG(ERROR) << "Failed to write block_devmode flag!";
    } else {
      block_devmode_value = block_devmode_setting;
    }
  }

  // Clear nvram_cleared if block_devmode has the correct state now.  (This is
  // OK as long as block_devmode is the only consumer of nvram_cleared.  Once
  // other use cases crop up, clearing has to be done in cooperation.)
  if (block_devmode_value == block_devmode_setting) {
    const int nvram_cleared_value =
        crossystem_->VbGetSystemPropertyInt(Crossystem::kNvramCleared);
    if (nvram_cleared_value == -1) {
      LOG(ERROR) << "Failed to read nvram_cleared flag!";
    }
    if (nvram_cleared_value != 0) {
      if (crossystem_->VbSetSystemPropertyInt(Crossystem::kNvramCleared, 0) !=
          0) {
        LOG(ERROR) << "Failed to clear nvram_cleared flag!";
      }
    }
  }

  // Used to keep the update key-value pairs for the VPD updater script.
  std::vector<std::pair<std::string, std::string>> updates;
  updates.push_back(std::make_pair(Crossystem::kBlockDevmode,
                                   std::to_string(block_devmode_setting)));

  // Check if device is enrolled. The flag for enrolled device is written to VPD
  // but will never get deleted. Existence of the flag is one of the triggers
  // for FRE check during OOBE.
  const std::string& mode = GetEnterpriseMode();
  if (mode != InstallAttributesReader::kDeviceModeEnterprise &&
      mode != InstallAttributesReader::kDeviceModeEnterpriseAD &&
      mode != InstallAttributesReader::kDeviceModeConsumer) {
    // Probably the first sign in, install attributes file is not created yet.
    if (!completion.is_null())
      completion.Run(brillo::ErrorPtr());

    return true;
  }
  bool is_enrolled = (mode == InstallAttributesReader::kDeviceModeEnterprise ||
                      mode == InstallAttributesReader::kDeviceModeEnterpriseAD);

  // It's impossible for block_devmode to be true and the device to not be
  // enrolled. If we end up in this situation, log the error and don't update
  // anything in VPD. The exception is if the device is in devmode, but we are
  // fine with this limitation, since user can update VPD in devmode manually.
  if (block_devmode_setting && !is_enrolled) {
    LOG(ERROR) << "Can't store contradictory values in VPD";
    // Return true to be on the safe side here since not allowing to continue
    // would make the device unusable.
    if (!completion.is_null())
      completion.Run(brillo::ErrorPtr());

    return true;
  }

  updates.push_back(std::make_pair(Crossystem::kCheckEnrollment,
                                   std::to_string(is_enrolled)));

  // Note that VPD update errors will be ignored if the device is not enrolled
  // or if device is enrolled to Active Directory (Chromad).
  // TODO(crbug.com/1060640): Revisit ignoring VPD update errors for Chromad
  // after better solution is found.
  bool ignore_errors =
      !is_enrolled || mode == InstallAttributesReader::kDeviceModeEnterpriseAD;
  return vpd_process_->RunInBackground(
      updates, false,
      base::Bind(&HandleVpdUpdateCompletion, ignore_errors, completion));
}

void DevicePolicyService::ClearForcedReEnrollmentFlags(
    const Completion& completion) {
  LOG(WARNING) << "Clear enrollment requested";
  // The block_devmode system property needs to be set to 0 as well to unblock
  // dev mode. It is stored independently from VPD and firmware management
  // parameters.
  if (crossystem_->VbSetSystemPropertyInt(Crossystem::kBlockDevmode, 0) != 0) {
    completion.Run(
        CreateError(dbus_error::kSystemPropertyUpdateFailed,
                    "Failed to set block_devmode system property to 0."));
    return;
  }
  if (!vpd_process_->RunInBackground(
          {{Crossystem::kBlockDevmode, "0"},
           {Crossystem::kCheckEnrollment, "0"}},
          false, base::Bind(&HandleVpdUpdateCompletion, false, completion))) {
    completion.Run(CreateError(dbus_error::kVpdUpdateFailed,
                               "Failed to run VPD update in the background."));
  }
}

bool DevicePolicyService::ValidateRemoteDeviceWipeCommand(
    const std::vector<uint8_t>& in_signed_command) {
  // Parse the SignedData that was sent over the DBus call.
  em::SignedData signed_data;
  if (!signed_data.ParseFromArray(in_signed_command.data(),
                                  in_signed_command.size()) ||
      !signed_data.has_data() || !signed_data.has_signature()) {
    LOG(ERROR) << "SignedData parsing failed.";
    return false;
  }

  // TODO(isandrk, 1000627): Move into a common Verify() function that everyone
  // uses (signature verification & policy_type checking).

  // Verify the command signature.
  if (!key()->Verify(StringToBlob(signed_data.data()),
                     StringToBlob(signed_data.signature()))) {
    LOG(ERROR) << "Invalid command signature.";
    return false;
  }

  // Parse the PolicyData from the raw data.
  em::PolicyData policy_data;
  if (!policy_data.ParseFromString(signed_data.data())) {
    LOG(ERROR) << "PolicyData parsing failed.";
    return false;
  }

  // Verify that this PolicyData really contains the RemoteCommand.
  if (policy_data.policy_type() != kRemoteCommandPolicyType) {
    LOG(ERROR) << "Received PolicyData doesn't contain the RemoteCommand.";
    return false;
  }

  // Parse the RemoteCommand from the PolicyData.
  em::RemoteCommand remote_command;
  if (!remote_command.ParseFromString(policy_data.policy_value())) {
    LOG(ERROR) << "RemoteCommand parsing failed.";
    return false;
  }

  // Also verify command type and target device id here.
  if (remote_command.type() != em::RemoteCommand_Type_DEVICE_REMOTE_POWERWASH) {
    LOG(ERROR) << "Invalid remote command type.";
    return false;
  }
  if (remote_command.target_device_id() != GetDeviceId()) {
    LOG(ERROR) << "Invalid remote command target_device_id.";
    return false;
  }

  // Note: the code here doesn't protect against replay attacks, but that is not
  // an issue for remote powerwash since after execution the device ID will no
  // longer match.  In case more commands are to be added in the future, replay
  // protection must be considered and added if deemed necessary.

  return true;
}

PolicyStore* DevicePolicyService::GetChromeStore() {
  return GetOrCreateStore(MakeChromePolicyNamespace());
}

std::string DevicePolicyService::GetDeviceId() {
  em::PolicyData policy_data;
  if (!policy_data.ParseFromString(GetChromeStore()->Get().policy_data()) ||
      !policy_data.has_device_id()) {
    LOG(ERROR) << "Failed to parse policy data, returning empty device id.";
    return std::string();
  }
  return policy_data.device_id();
}

const std::string& DevicePolicyService::GetEnterpriseMode() {
  return install_attributes_reader_->GetAttribute(
      InstallAttributesReader::kAttrMode);
}

bool DevicePolicyService::IsChromeStoreResilientForTesting() {
  return GetChromeStore()->resilient_for_testing();
}

}  // namespace login_manager
