// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "authpolicy/samba_interface.h"

#include <algorithm>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file.h>
#include <base/files/file_util.h>
#include <base/files/important_file_writer.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/notreached.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/threading/platform_thread.h>
#include <base/time/default_clock.h>
#include <base/time/time.h>
#include <policy/device_policy_impl.h>

#include "authpolicy/anonymizer.h"
#include "authpolicy/cryptohome_client.h"
#include "authpolicy/log_colors.h"
#include "authpolicy/platform_helper.h"
#include "authpolicy/process_executor.h"

namespace em = enterprise_management;

namespace authpolicy {
namespace {

// Samba configuration file data.
constexpr char kSmbConfData[] =
    "[global]\n"
    "\tnetbios name = %s\n"
    "\tsecurity = ADS\n"
    "\tworkgroup = %s\n"
    "\trealm = %s\n"
    "\tlock directory = %s\n"
    "\tinclude system krb5 conf = false\n"
    "\tcache directory = %s\n"
    "\tstate directory = %s\n"
    "\tprivate directory = %s\n"
    "\tkerberos encryption types = %s\n"
    "\tclient signing = mandatory\n"
    "\tclient min protocol = SMB2\n"
    // TODO(crbug.com/662440): Remove this line if it is no longer necessary.
    // (Make sure that Samba doesn't default to some older version)
    "\tclient max protocol = SMB3\n"
    "\tclient ipc min protocol = SMB2\n"
    "\tclient ldap sasl wrapping = sign\n";

// Fake domain SID to work around issue in Samba-4.8.6+, see
// `MaybeSetFakeDomainSid()`.
constexpr char kFakeDomainSid[] = "S-1-5-21-0000000000-0000000000-00000000";

constexpr int kFileMode_rwr = base::FILE_PERMISSION_READ_BY_USER |
                              base::FILE_PERMISSION_WRITE_BY_USER |
                              base::FILE_PERMISSION_READ_BY_GROUP;

constexpr int kFileMode_rwxrx = kFileMode_rwr |
                                base::FILE_PERMISSION_EXECUTE_BY_USER |
                                base::FILE_PERMISSION_EXECUTE_BY_GROUP;

constexpr int kFileMode_rwxrwx =
    kFileMode_rwxrx | base::FILE_PERMISSION_WRITE_BY_GROUP;

// Directories with permissions to be created. AUTHPOLICY_TMP_DIR needs group rx
// access to read smb.conf and krb5.conf and to access SAMBA_DIR, but no write
// access. The Samba directories need full group rwx access since Samba reads
// and writes files there.
constexpr struct CreateDirectories {
  Path path;
  int mode;
  bool owned_by_authpolicyd_exec;
} kDirsToCreate[] = {{Path::TEMP_DIR, kFileMode_rwxrx, false},
                     {Path::SAMBA_DIR, kFileMode_rwxrwx, false},
                     {Path::SAMBA_LOCK_DIR, kFileMode_rwxrwx, true},
                     {Path::SAMBA_CACHE_DIR, kFileMode_rwxrwx, true},
                     {Path::SAMBA_STATE_DIR, kFileMode_rwxrwx, true},
                     {Path::SAMBA_PRIVATE_DIR, kFileMode_rwxrwx, true}};

// Directory / filenames for user and device policy.
constexpr char kPRegUserDir[] = "User";
constexpr char kPRegDeviceDir[] = "Machine";
constexpr char kPRegFileName[] = "registry.pol";

// Size limit when loading the config file (256 kb).
constexpr size_t kConfigSizeLimit = 256 * 1024;

// SessionStateChanged signal payload we care about.
constexpr char kSessionStarted[] = "started";

// Maximum smbclient tries.
constexpr int kSmbClientMaxTries = 5;
// Wait interval between two smbclient tries.
constexpr base::TimeDelta kSmbClientRetryDelay = base::Seconds(1);

// Check every 120 minutes whether the machine password has to be changed.
constexpr base::TimeDelta kPasswordChangeCheckRate = base::Minutes(120);

// Default GPO version cache TTL. Can be overridden with the
// DeviceGpoCacheLifetime policy. Make sure the value matches the policy
// description in policy_templates.json!
constexpr base::TimeDelta kDefaultGpoVersionCacheTTL = base::Hours(25);

// Default auth data cache TTL. Can be overridden with the
// DeviceAuthDataCacheLifetime policy. Make sure the value matches the policy
// description in policy_templates.json!
constexpr base::TimeDelta kDefaultAuthDataCacheTTL = base::Hours(73);

constexpr base::TimeDelta kZeroDelta = base::Hours(0);

// Keys for interpreting net output.
constexpr char kKeyJoinAccessDenied[] = "NT_STATUS_ACCESS_DENIED";
constexpr char kKeyJoinAccessDenied2[] =
    "Failed to join domain: failed to set machine os attributes: Insufficient "
    "access";
constexpr char kKeyInvalidMachineName[] = "Improperly formed account name";
constexpr char kKeyInvalidMachineName2[] =
    "The name provided is not a properly formed account name";
constexpr char kKeyMachineNameTooLong[] = "Our netbios name can be at most";
constexpr char kKeyUserHitJoinQuota[] =
    "Insufficient quota exists to complete the operation";
constexpr char kKeyJoinFailedToFindDC[] = "failed to find DC";
constexpr char kKeyNoLogonServers[] = "No logon servers";
constexpr char kKeyJoinLogonFailure[] = "Logon failure";
constexpr char kKeyJoinLogonFailure2[] = "The attempted logon is invalid";
constexpr char kKeyJoinMustChangePassword[] = "Must change password";
constexpr char kKeyJoinMustChangePassword2[] = "password must be changed";
// Setting OU during domain join failed. More specific errors below.
constexpr char kKeyBadOuCommon[] = "failed to precreate account in ou";
// The domain join createcomputer argument specified a non-existent OU.
constexpr char kKeyBadOuNoSuchObject[] = "No such object";
// The domain join createcomputer argument syntax was invalid. Caused by some
// special characters in OU names, e.g. 'ou=123!' or 'a"b'. Seems like a Samba
// issue since OUs allow all characters and we do escape names properly.
constexpr char kKeyBadOuInvalidDnSyntax[] = "Invalid DN syntax";
// Domain join operation would have violated an attribute constraint.
constexpr char kKeyBadOuConstrainViolation[] = "Constraint violation";
// Domain join required access permissions that the user does not possess.
constexpr char kKeyBadOuInsufficientAccess[] = "Insufficient access";
// All other OU errors result in a generic ERROR_SETTING_OU_FAILED, e.g.
//  - "Referral": dc=... specification resulted in a referral to another server.
//  - "Operations error": Unspecific error.
// Keys for interpreting smbclient output.
constexpr char kKeyConnectionReset[] = "NT_STATUS_CONNECTION_RESET";
constexpr char kKeyNetworkTimeout[] = "NT_STATUS_IO_TIMEOUT";
constexpr char kKeyObjectNameNotFound[] =
    "NT_STATUS_OBJECT_NAME_NOT_FOUND opening remote file ";
constexpr char kKeyEncTypeNotSupported[] =
    "KDC has no support for encryption type";
constexpr char kKeyEncTypeNotSupported2[] =
    "The encryption type requested is not supported by the KDC";

// Replacement strings for anonymization.
constexpr char kMachineNamePlaceholder[] = "<MACHINE_NAME>";
constexpr char kLogonNamePlaceholder[] = "<USER_LOGON_NAME>";
constexpr char kGivenNamePlaceholder[] = "<USER_GIVEN_NAME>";
constexpr char kDisplayNamePlaceholder[] = "<USER_DISPLAY_NAME>";
constexpr char kSAMAccountNamePlaceholder[] = "<USER_SAM_ACCOUNT_NAME>";
constexpr char kCommonNamePlaceholder[] = "<USER_COMMON_NAME>";
constexpr char kAccountIdPlaceholder[] = "<USER_ACCOUNT_ID>";
constexpr char kWorkgroupPlaceholder[] = "<WORKGROUP>";
constexpr char kDeviceRealmPlaceholder[] = "<DEVICE_REALM>";
constexpr char kUserRealmPlaceholder[] = "<USER_REALM>";
constexpr char kForestPlaceholder[] = "<FOREST>";
constexpr char kDomainPlaceholder[] = "<DOMAIN>";
constexpr char kServerNamePlaceholder[] = "<SERVER_NAME>";
constexpr char kSiteNamePlaceholder[] = "<SITE_NAME>";
constexpr char kIpAddressPlaceholder[] = "<IP_ADDRESS>";
constexpr char kPasswordPlaceholder[] = "<PASSWORD>";

// Keys for net ads searches.
constexpr char kKeyWorkgroup[] = "Workgroup";
constexpr char kKeyAdsDnsParseRrSrv[] = "ads_dns_parse_rr_srv";
constexpr char kKeyPdcDnsName[] = "pdc_dns_name";
constexpr char kKeyAdsDcName[] = "ads_dc_name";
constexpr char kKeyPdcName[] = "pdc_name";
constexpr char kKeyServerSite[] = "server_site";
constexpr char kKeyClientSite[] = "client_site";
constexpr char kKeyForest[] = "Forest";
constexpr char kKeyDomain[] = "Domain";
constexpr char kKeyDomainController[] = "Domain Controller";
constexpr char kKeyPreWin2kDomain[] = "Pre-Win2k Domain";
constexpr char kKeyPreWin2kHostname[] = "Pre-Win2k Hostname";
constexpr char kKeyServerSiteName[] = "Server Site Name";
constexpr char kKeyClientSiteName[] = "Client Site Name";
constexpr char kKeyKdcServer[] = "KDC server";
constexpr char kKeyLdapServer[] = "LDAP server";
constexpr char kKeyLdapServerName[] = "LDAP server name";

// Kerberos encryption types strings for smb.conf.
constexpr char kEncTypesAll[] = "all";
constexpr char kEncTypesStrong[] = "strong";
constexpr char kEncTypesLegacy[] = "legacy";

// Maximum time that logging through SetDefaultLogLevel() should stay enabled.
// The method is called through the authpolicy_debug crosh command. The time is
// limited so users don't have to remember to turn logging off.
// Keep in sync with description in crosh!
constexpr int kMaxDefaultLogLevelUptimeMinutes = 30;

// Auth state backup filename in user daemon store.
constexpr char kBackupFileName[] = "user_backup_data";
constexpr int kMaxBackupSizeBytes = 4 * 1024 * 1024;

[[nodiscard]] ErrorType GetNetError(const ProcessExecutor& executor,
                                    const std::string& net_command) {
  const std::string& net_out = executor.GetStdout();
  const std::string& net_err = executor.GetStderr();
  const std::string error_msg("net ads " + net_command + " failed: ");

  if (Contains(net_out, kKeyJoinFailedToFindDC) ||
      Contains(net_err, kKeyNoLogonServers)) {
    LOG(ERROR) << error_msg << "network problem";
    return ERROR_NETWORK_PROBLEM;
  }
  if (Contains(net_out, kKeyJoinLogonFailure) ||
      Contains(net_out, kKeyJoinLogonFailure2)) {
    LOG(ERROR) << error_msg << "logon failure";
    return ERROR_BAD_PASSWORD;
  }
  if (Contains(net_out, kKeyJoinMustChangePassword) ||
      Contains(net_out, kKeyJoinMustChangePassword2)) {
    LOG(ERROR) << error_msg << "must change password";
    return ERROR_PASSWORD_EXPIRED;
  }
  if (Contains(net_out, kKeyJoinAccessDenied) ||
      Contains(net_out, kKeyJoinAccessDenied2)) {
    LOG(ERROR) << error_msg << "user is not permitted to join the domain";
    return ERROR_JOIN_ACCESS_DENIED;
  }
  if (Contains(net_out, kKeyInvalidMachineName) ||
      Contains(net_out, kKeyInvalidMachineName2)) {
    LOG(ERROR) << error_msg << "invalid machine name";
    return ERROR_INVALID_MACHINE_NAME;
  }
  if (Contains(net_out, kKeyMachineNameTooLong)) {
    LOG(ERROR) << error_msg << "machine name is too long";
    return ERROR_MACHINE_NAME_TOO_LONG;
  }
  if (Contains(net_out, kKeyUserHitJoinQuota)) {
    LOG(ERROR) << error_msg << "user joined max number of machines";
    return ERROR_USER_HIT_JOIN_QUOTA;
  }
  if (Contains(net_out, kKeyBadOuCommon)) {
    if (Contains(net_out, kKeyBadOuNoSuchObject)) {
      LOG(ERROR) << error_msg << "computer OU does not exist";
      return ERROR_OU_DOES_NOT_EXIST;
    }
    if (Contains(net_out, kKeyBadOuInvalidDnSyntax)) {
      LOG(ERROR) << error_msg << "computer OU invalid";
      return ERROR_INVALID_OU;
    }
    if (Contains(net_out, kKeyBadOuConstrainViolation)) {
      LOG(ERROR) << error_msg << "constraint violation setting computer OU";
      return ERROR_OU_CONSTRAINT_VIOLATION;
    }
    if (Contains(net_out, kKeyBadOuInsufficientAccess)) {
      LOG(ERROR) << error_msg << "access denied setting computer OU";
      return ERROR_OU_ACCESS_DENIED;
    }
    // Fall back to generic OU error.
    LOG(ERROR) << error_msg << "setting computer OU failed, unspecified error";
    return ERROR_SETTING_OU_FAILED;
  }
  if (Contains(net_out, kKeyEncTypeNotSupported) ||
      Contains(net_out, kKeyEncTypeNotSupported2)) {
    LOG(ERROR) << error_msg << "KDC does not support encryption type";
    return ERROR_KDC_DOES_NOT_SUPPORT_ENCRYPTION_TYPE;
  }
  LOG(ERROR) << error_msg << "exit code " << executor.GetExitCode();
  return ERROR_NET_FAILED;
}

[[nodiscard]] ErrorType GetSmbclientError(
    const ProcessExecutor& smb_client_cmd) {
  const std::string& smb_client_out = smb_client_cmd.GetStdout();
  if (Contains(smb_client_out, kKeyNetworkTimeout) ||
      Contains(smb_client_out, kKeyConnectionReset)) {
    LOG(ERROR) << "smbclient failed - network problem";
    return ERROR_NETWORK_PROBLEM;
  }
  LOG(ERROR) << "smbclient failed with exit code "
             << smb_client_cmd.GetExitCode();
  return ERROR_SMBCLIENT_FAILED;
}

// Creates the given directory recursively and sets error message on failure.
[[nodiscard]] ErrorType CreateDirectory(const base::FilePath& dir) {
  base::File::Error ferror;
  if (!base::CreateDirectoryAndGetError(dir, &ferror)) {
    LOG(ERROR) << "Failed to create directory '" << dir.value()
               << "': " << base::File::ErrorToString(ferror);
    return ERROR_LOCAL_IO;
  }
  return ERROR_NONE;
}

// Sets file permissions for a given filepath and sets error message on failure.
[[nodiscard]] ErrorType SetFilePermissions(const base::FilePath& fp, int mode) {
  if (!base::SetPosixFilePermissions(fp, mode)) {
    LOG(ERROR) << "Failed to set permissions on '" << fp.value() << "'";
    return ERROR_LOCAL_IO;
  }
  return ERROR_NONE;
}

// Similar to |SetFilePermissions|, but sets permissions recursively up the path
// to |base_fp| (not including |base_fp|). Returns false if |base_fp| is not a
// parent of |fp|.
[[nodiscard]] ErrorType SetFilePermissionsRecursive(
    const base::FilePath& fp, const base::FilePath& base_fp, int mode) {
  if (!base_fp.IsParent(fp)) {
    LOG(ERROR) << "Base path '" << base_fp.value() << "' is not a parent of '"
               << fp.value() << "'";
    return ERROR_LOCAL_IO;
  }
  ErrorType error = ERROR_NONE;
  for (base::FilePath curr_fp = fp; curr_fp != base_fp && error == ERROR_NONE;
       curr_fp = curr_fp.DirName()) {
    error = SetFilePermissions(curr_fp, mode);
  }
  return error;
}

// Checks whether the file at |default_level_path| exists and was last modified
// in a certain time range. If not, it is deleted to prevent that a user forgets
// to disable logging.
bool CheckFlagsDefaultLevelValid(const base::FilePath& default_level_path) {
  // Having no file is the out-of-box state with no level set, so exit quietly.
  if (!base::PathExists(default_level_path))
    return false;

  base::File::Info info;
  if (!GetFileInfo(default_level_path, &info)) {
    PLOG(ERROR) << "Failed to get file info from '"
                << default_level_path.value() << "'";
    return false;
  }

  // Check < -1 to prevent issues with clocks running backwards for a bit.
  int uptime_min = (base::Time::Now() - info.last_modified).InMinutes();
  if (uptime_min < -1 || uptime_min > kMaxDefaultLogLevelUptimeMinutes) {
    LOG(INFO) << "Removing flags default level file and resetting (uptime: "
              << uptime_min << " minutes).";
    PCHECK(base::DeleteFile(default_level_path))
        << "Failed to delete flags default level file '"
        << default_level_path.value() << "'";
    return false;
  }

  return true;
}

// Parses |gpo_policy_data| from |gpo_policy_data_blob|. Returns ERROR_NONE on
// success. Returns ERROR_PARSE_FAILED and prints an error on failure.
[[nodiscard]] ErrorType ParsePolicyData(
    const std::string& gpo_policy_data_blob,
    protos::GpoPolicyData* gpo_policy_data) {
  if (!gpo_policy_data->ParseFromString(gpo_policy_data_blob)) {
    LOG(ERROR) << "Failed to parse policy data from string";
    return ERROR_PARSE_FAILED;
  }
  return ERROR_NONE;
}

// Returns the string representation of |encryption_types| for smb.conf.
const char* GetEncryptionTypesString(KerberosEncryptionTypes encryption_types) {
  switch (encryption_types) {
    case ENC_TYPES_ALL:
      return kEncTypesAll;
    case ENC_TYPES_STRONG:
      return kEncTypesStrong;
    case ENC_TYPES_LEGACY:
      return kEncTypesLegacy;
    case ENC_TYPES_COUNT:
      NOTREACHED() << "Not a valid encryption type and will default to strong.";
      return kEncTypesStrong;
  }
  CHECK(false);
}

// Returns the value of the DeviceKerberosEncryptionTypes policy or
// ENC_TYPES_STRONG if the policy is not set or invalid.
KerberosEncryptionTypes GetEncryptionTypes(
    const em::ChromeDeviceSettingsProto& device_policy) {
  if (!device_policy.has_device_kerberos_encryption_types() ||
      !device_policy.device_kerberos_encryption_types().has_types()) {
    return ENC_TYPES_STRONG;
  }

  em::DeviceKerberosEncryptionTypesProto::Types policy_encryption_types =
      device_policy.device_kerberos_encryption_types().types();

  switch (policy_encryption_types) {
    case em::DeviceKerberosEncryptionTypesProto::ENC_TYPES_ALL:
      return ENC_TYPES_ALL;
    case em::DeviceKerberosEncryptionTypesProto::ENC_TYPES_STRONG:
      return ENC_TYPES_STRONG;
    case em::DeviceKerberosEncryptionTypesProto::ENC_TYPES_LEGACY:
      return ENC_TYPES_LEGACY;
  }

  CHECK(false);
}

// Returns the value of the DeviceUserPolicyLoopbackProcessingMode policy or
// |USER_POLICY_MODE_DEFAULT| if the policy is not.
em::DeviceUserPolicyLoopbackProcessingModeProto::Mode GetUserPolicyMode(
    const em::ChromeDeviceSettingsProto& device_policy) {
  if (!device_policy.has_device_user_policy_loopback_processing_mode() ||
      !device_policy.device_user_policy_loopback_processing_mode().has_mode()) {
    return em::DeviceUserPolicyLoopbackProcessingModeProto::
        USER_POLICY_MODE_DEFAULT;
  }
  return device_policy.device_user_policy_loopback_processing_mode().mode();
}

// Returns the value of the DeviceMachinePasswordChangeRate policy or
// |kDefaultMachinePasswordChange| if the policy is not set.
base::TimeDelta GetMachinePasswordChangeRate(
    const em::ChromeDeviceSettingsProto& device_policy) {
  if (!device_policy.has_device_machine_password_change_rate() ||
      !device_policy.device_machine_password_change_rate().has_rate_days()) {
    return kDefaultMachinePasswordChangeRate;
  }
  return base::Days(
      device_policy.device_machine_password_change_rate().rate_days());
}

// Returns the value of the DeviceGpoCacheLifetime policy or
// |kDefaultGpoVersionCacheTTL| if the policy is not set.
base::TimeDelta GetGpoVersionCacheTTL(
    const em::ChromeDeviceSettingsProto& device_policy) {
  if (!device_policy.has_device_gpo_cache_lifetime() ||
      !device_policy.device_gpo_cache_lifetime().has_lifetime_hours()) {
    return kDefaultGpoVersionCacheTTL;
  }
  return base::Hours(
      device_policy.device_gpo_cache_lifetime().lifetime_hours());
}

// Returns the value of the DeviceAuthDataCacheLifetime policy or
// |kDefaultAuthDataCacheTTL| if the policy is not set.
base::TimeDelta GetAuthDataCacheTTL(
    const em::ChromeDeviceSettingsProto& device_policy) {
  if (!device_policy.has_device_auth_data_cache_lifetime() ||
      !device_policy.device_auth_data_cache_lifetime().has_lifetime_hours()) {
    return kDefaultAuthDataCacheTTL;
  }
  return base::Hours(
      device_policy.device_auth_data_cache_lifetime().lifetime_hours());
}

std::ostream& operator<<(std::ostream& os,
                         const ActiveDirectoryUserStatus::TgtStatus& status) {
  switch (status) {
    case ActiveDirectoryUserStatus::TGT_VALID:
      return os << "valid";
    case ActiveDirectoryUserStatus::TGT_EXPIRED:
      return os << "expired";
    case ActiveDirectoryUserStatus::TGT_NOT_FOUND:
      return os << "not found";
  }
  NOTREACHED();
  return os << "unknown";
}

std::ostream& operator<<(
    std::ostream& os, const ActiveDirectoryUserStatus::PasswordStatus& status) {
  switch (status) {
    case ActiveDirectoryUserStatus::PASSWORD_VALID:
      return os << "valid";
    case ActiveDirectoryUserStatus::PASSWORD_EXPIRED:
      return os << "expired";
    case ActiveDirectoryUserStatus::PASSWORD_CHANGED:
      return os << "changed";
  }
  NOTREACHED();
  return os << "unknown";
}

// Helper to log |status| if the |log_status| debug flag is enabled.
void LogUserStatus(const ActiveDirectoryUserStatus& status,
                   const protos::DebugFlags& flags) {
  if (!flags.log_status())
    return;

  LOG(INFO) << kColorStatus << "User Status:" << kColorReset;
  LOG(INFO) << kColorStatus << "  TGT:                  " << status.tgt_status()
            << kColorReset;
  LOG(INFO) << kColorStatus
            << "  Password:             " << status.password_status()
            << kColorReset;
  LOG(INFO) << kColorStatus << "  Password Last Set:    "
            << status.account_info().pwd_last_set() << kColorReset;
  LOG(INFO) << kColorStatus << "  User Account Control: "
            << status.account_info().user_account_control() << kColorReset;
  // Note: Don't log the other account info data, it's all PII.
}

// Logs an error in case of failure. Returns true on success.
bool ReadMachinePasswordToString(const base::FilePath& password_path,
                                 std::string* password) {
  if (!base::ReadFileToString(password_path, password)) {
    PLOG(ERROR) << "Could not read machine password file '"
                << password_path.value() << "'";
    return false;
  }
  return true;
}

}  // namespace

SambaInterface::SambaInterface(
    AuthPolicyMetrics* metrics,
    const PathService* path_service,
    const base::RepeatingClosure& user_kerberos_files_changed)
    : user_account_(Path::USER_SMB_CONF),
      device_account_(Path::DEVICE_SMB_CONF),
      metrics_(metrics),
      paths_(path_service),
      anonymizer_(std::make_unique<Anonymizer>()),
      jail_helper_(paths_, &flags_, anonymizer_.get()),
      user_tgt_manager_(paths_,
                        metrics_,
                        &flags_,
                        &jail_helper_,
                        anonymizer_.get(),
                        this /* TgtManager::Delegate */,
                        Path::USER_KRB5_CONF,
                        Path::USER_CREDENTIAL_CACHE),
      device_tgt_manager_(paths_,
                          metrics_,
                          &flags_,
                          &jail_helper_,
                          anonymizer_.get(),
                          this /* TgtManager::Delegate */,
                          Path::DEVICE_KRB5_CONF,
                          Path::DEVICE_CREDENTIAL_CACHE),
      gpo_version_cache_(&flags_),
      gpo_version_cache_ttl_(kDefaultGpoVersionCacheTTL),
      auth_data_cache_(&flags_),
      auth_data_cache_ttl_(kDefaultAuthDataCacheTTL) {
  DCHECK(paths_);
  LoadFlagsDefaultLevel();
  user_tgt_manager_.SetKerberosFilesChangedCallback(
      user_kerberos_files_changed);
}

SambaInterface::~SambaInterface() = default;

ErrorType SambaInterface::Initialize(bool expect_config) {
  ReloadDebugFlags();

  ErrorType error = ERROR_NONE;
  {
    // Note: From 4.8.0 on Samba performs a strict ownership check on some
    // directories, so they have to be owned by authpolicyd-exec.
    for (const auto& dir : kDirsToCreate) {
      std::unique_ptr<ScopedSwitchToSavedUid> switch_scope;
      if (dir.owned_by_authpolicyd_exec)
        switch_scope = std::make_unique<ScopedSwitchToSavedUid>();
      const base::FilePath path(paths_->Get(dir.path));
      error = ::authpolicy::CreateDirectory(path);
      if (error != ERROR_NONE)
        return error;
      error = SetFilePermissions(path, dir.mode);
      if (error != ERROR_NONE)
        return error;
    }
  }

  if (expect_config) {
    error = ReadConfiguration();
    if (error != ERROR_NONE)
      return error;

    // Load cached auth data. It's OK if that fails, just start with an empty
    // cache.
    // NOTE: Load cache before UpdateDevicePolicyDependencies() as that may
    // modify the cache!
    base::FilePath cache_path(paths_->Get(Path::AUTH_DATA_CACHE));
    if (base::PathExists(cache_path))
      auth_data_cache_.Load(cache_path);

    // Load device policy and update stuff that depends on device policy. If
    // there's a config, it means the device is locked and there should also be
    // device policy at this point.
    std::unique_ptr<policy::DevicePolicyImpl> policy_impl =
        std::move(device_policy_impl_for_testing);
    if (!policy_impl)
      policy_impl = std::make_unique<policy::DevicePolicyImpl>();
    if (!policy_impl->LoadPolicy(/*delete_invalid_files=*/false)) {
      LOG(ERROR) << "Failed to load device policy. Authentication and policy "
                    "fetch might behave unexpectedly until the next device "
                    "policy fetch.";
    }

    // Call this even when loading failed to get the defaults right (e.g.
    // turn on machine password auto renewal).
    UpdateDevicePolicyDependencies(policy_impl->get_device_policy());
  }

  return ERROR_NONE;
}

void SambaInterface::SetCryptohomeClient(
    std::unique_ptr<CryptohomeClient> cryptohome_client) {
  cryptohome_client_ = std::move(cryptohome_client);
}

// static
bool SambaInterface::CleanState(const PathService* path_service) {
  // Note: We're not permitted to delete the folder and DeleteFile apparently
  // doesn't support wildcards, so DeleteFile returns false.
  DCHECK(path_service);
  const base::FilePath state_dir(path_service->Get(Path::STATE_DIR));
  base::DeletePathRecursively(state_dir);
  if (!base::IsDirectoryEmpty(state_dir)) {
    LOG(ERROR) << "Failed to clean state dir '" << state_dir.value() << "'";
    return false;
  }
  return true;
}

ErrorType SambaInterface::AuthenticateUser(
    const std::string& user_principal_name,
    const std::string& account_id,
    int password_fd,
    ActiveDirectoryAccountInfo* account_info) {
  ReloadDebugFlags();

  ErrorType error = AuthenticateUserInternal(user_principal_name, account_id,
                                             password_fd, account_info);

  last_auth_error_ = error;
  return error;
}

ErrorType SambaInterface::AuthenticateUserInternal(
    const std::string& user_principal_name,
    const std::string& account_id,
    int password_fd,
    ActiveDirectoryAccountInfo* account_info) {
  if (!account_id.empty())
    SetUserAccountId(account_id);

  // We technically don't have to be in joined state, but check it anyway,
  // because the device should always be joined during auth.
  if (!IsDeviceJoined())
    return ERROR_NOT_JOINED;

  // Split user_principal_name into parts and normalize.
  std::string user_name, user_realm, normalized_upn;
  if (!ParseUserPrincipalName(user_principal_name, &user_name, &user_realm,
                              &normalized_upn)) {
    return ERROR_PARSE_UPN_FAILED;
  }
  SetUserRealm(user_realm);
  user_tgt_manager_.SetPrincipal(normalized_upn);

  // Clean up auth data cache.
  auth_data_cache_.RemoveEntriesOlderThan(auth_data_cache_ttl_);

  // Acquire Kerberos ticket-granting-ticket for the user account.
  ErrorType error = AcquireUserTgt(password_fd);
  if (error != ERROR_NONE)
    return error;

  // Get account info for the user.
  error = GetAccountInfo(user_name, normalized_upn, account_id, account_info);
  if (error != ERROR_NONE)
    return error;

  // Renew TGT periodically. The usual validity lifetime is 1 day, so this won't
  // happen too often. There's a corner-case if pwdLastSet or userAccountControl
  // are missing, see crbug.com/795758. In that case, GetUserStatus cannot
  // determine the password validity and just *assumes* it's valid. However, the
  // AD admin might have requested the user to change their password. To limit
  // the impact, don't renew the TGT automatically, so that the user will be
  // prompted to relog after 1 day instead of the renewal lifetime of usually 1
  // week.
  bool should_auto_renew = account_info->has_pwd_last_set() &&
                           account_info->has_user_account_control();
  LOG_IF(WARNING, !should_auto_renew)
      << "pwdLastSet or userAccountControl fields missing. Will not "
         "be able to determine password validity. Turning off TGT "
         "renewal to limit lifetime.";
  user_tgt_manager_.EnableTgtAutoRenewal(should_auto_renew);

  if (account_id.empty())
    SetUserAccountId(account_info->account_id());

  // Store sAMAccountName for policy fetch. Note that net ads gpo list always
  // wants the sAMAccountName. Also note that pwd_last_set is zero and stale
  // at this point if AcquireTgtWithPassword() set a new password, but that's
  // fine, the timestamp is updated in the next GetUserStatus() call.
  user_account_.user_name = account_info->sam_account_name();
  if (account_info->has_pwd_last_set())
    user_pwd_last_set_ = account_info->pwd_last_set();
  user_logged_in_ = true;

  // Backup state on user's Cryptohome.
  MaybeBackupUserAuthState();

  // Collecting metrics with the encryption types used during this successful
  // login. This value has been set through the DeviceKerberosEncryptionTypes
  // policy.
  metrics_->ReportEncryptionType(ENC_TYPES_OF_AUTHENTICATE_USER,
                                 encryption_types_);

  return ERROR_NONE;
}

ErrorType SambaInterface::GetUserStatus(
    const std::string& user_principal_name,
    const std::string& account_id,
    ActiveDirectoryUserStatus* user_status) {
  ReloadDebugFlags();
  SetUserAccountId(account_id);
  user_status->Clear();

  // Try to restore TGT if it doesn't exist. The TGT is required for reading the
  // account info below.
  MaybeRestoreUserAuthState();

  // We technically don't have to be in joined state, but check it anyway,
  // because the device should always be joined during getting status.
  if (!IsDeviceJoined())
    return ERROR_NOT_JOINED;

  // Split user_principal_name into parts and normalize.
  std::string user_name, user_realm, normalized_upn;
  if (!ParseUserPrincipalName(user_principal_name, &user_name, &user_realm,
                              &normalized_upn)) {
    return ERROR_PARSE_UPN_FAILED;
  }
  SetUserRealm(user_realm);

  // Tell Chrome that the password expired in case the TGT is not valid and the
  // GetUserPasswordStatus() call below doesn't happen. See crbug.com/849318.
  if (last_auth_error_ == ERROR_PASSWORD_EXPIRED) {
    user_status->set_password_status(
        ActiveDirectoryUserStatus::PASSWORD_EXPIRED);
  }

  // If authentication failed with bad password, but the session was still
  // started and Cryptohome could be unmounted, it means that the logon password
  // must have been a valid, old password and the password must have changed on
  // the server.
  if (last_auth_error_ == ERROR_BAD_PASSWORD) {
    user_status->set_password_status(
        ActiveDirectoryUserStatus::PASSWORD_CHANGED);
  }

  // Determine the status of the TGT.
  ActiveDirectoryUserStatus::TgtStatus tgt_status =
      ActiveDirectoryUserStatus::TGT_VALID;
  ErrorType error = GetUserTgtStatus(&tgt_status);
  if (error != ERROR_NONE) {
    LogUserStatus(*user_status, flags_);
    return error;
  }
  user_status->set_tgt_status(tgt_status);

  // If we don't have a valid TGT, we can't GetAccountInfo() because that uses
  // the TGT to authenticate. Thus, just return the TGT status and the last auth
  // error.
  if (tgt_status != ActiveDirectoryUserStatus::TGT_VALID) {
    // Just try to ping the server here. Otherwise, Chrome shows a popup that
    // the user has to relog in order to get a new TGT, but AuthenticateUser()
    // fails if the server is unavailable and the popup is shown again.
    // See crbug.com/844662.
    LogUserStatus(*user_status, flags_);
    return PingServer(&user_account_);
  }

  // Update smb.conf, IPs, server names etc. for the user account.
  error = UpdateAccountData(&user_account_);
  if (error != ERROR_NONE) {
    LogUserStatus(*user_status, flags_);
    return error;
  }

  // Get account info for the user.
  ActiveDirectoryAccountInfo account_info;
  error =
      GetAccountInfo("" /* user_name unused */, "" /* normalized_upn unused */,
                     account_id, &account_info);
  if (error != ERROR_NONE) {
    LogUserStatus(*user_status, flags_);
    return error;
  }
  *user_status->mutable_account_info() = account_info;

  // Determine the status of the password.
  ActiveDirectoryUserStatus::PasswordStatus password_status =
      GetUserPasswordStatus(account_info);
  user_status->set_password_status(password_status);

  LogUserStatus(*user_status, flags_);
  return ERROR_NONE;
}

ErrorType SambaInterface::GetUserKerberosFiles(const std::string& account_id,
                                               KerberosFiles* files) {
  ReloadDebugFlags();
  SetUserAccountId(account_id);

  // Try to restore TGT, user_account_id_ etc. if it doesn't exist.
  MaybeRestoreUserAuthState();

  return user_tgt_manager_.GetKerberosFiles(files);
}

ErrorType SambaInterface::JoinMachine(
    const std::string& machine_name,
    const std::string& machine_domain,
    const std::vector<std::string>& machine_ou,
    const std::string& user_principal_name,
    KerberosEncryptionTypes encryption_types,
    int password_fd,
    std::string* joined_domain) {
  ReloadDebugFlags();

  // Prevent joining a second time for security reasons (a hacked Chrome might
  // call this).
  if (IsDeviceJoined())
    return ERROR_ALREADY_JOINED;

  // Split user_principal_name into parts and normalize.
  std::string user_name, user_realm, normalized_upn;
  if (!ParseUserPrincipalName(user_principal_name, &user_name, &user_realm,
                              &normalized_upn)) {
    return ERROR_PARSE_UPN_FAILED;
  }
  AnonymizeRealm(user_realm, kUserRealmPlaceholder);
  anonymizer_->SetReplacement(user_name, kSAMAccountNamePlaceholder);

  std::string join_realm;
  if (!machine_domain.empty()) {
    // Join machine to the given domain (note: realm and domain is the same).
    join_realm = base::ToUpperASCII(machine_domain);
    AnonymizeRealm(join_realm, kDeviceRealmPlaceholder);
  } else {
    // By default, join machine to the user's realm.
    join_realm = user_realm;
  }

  // The netbios name in smb.conf needs to be upper-case, but there is also
  // Samba code that logs the machine name lower-case, so add both here.
  anonymizer_->SetReplacementAllCases(machine_name, kMachineNamePlaceholder);

  // Wipe and (re-)create config. Note that all session data is wiped to make
  // testing easier.
  Reset();
  InitDeviceAccount(base::ToUpperASCII(machine_name), join_realm);

  // Note: Encryption types stay valid through the initial device policy fetch,
  // which, if it succeeds, resets or updates the value.
  SetKerberosEncryptionTypes(encryption_types);

  // Update smb.conf, IPs, server names etc. for the device account.
  ErrorType error = UpdateAccountData(&device_account_);
  if (error != ERROR_NONE) {
    Reset();
    return error;
  }

  // Call net ads join to join the machine to the Active Directory domain.
  ProcessExecutor net_cmd({paths_->Get(Path::NET), "ads", "join", kUserParam,
                           normalized_upn, kKerberosParam, kConfigParam,
                           paths_->Get(Path::DEVICE_SMB_CONF), kDebugParam,
                           flags_.net_log_level(), kMachinepassStdinParam});
  if (!machine_ou.empty()) {
    net_cmd.PushArg(kCreatecomputerParam +
                    BuildDistinguishedName(machine_ou, join_realm));
  }
  const std::string os_name = GetOsName();
  const std::string os_version = GetOsVersion();
  if (!os_name.empty() && !os_version.empty()) {
    // Both must be specified for the params to take effect.
    net_cmd.PushArg(kOsNameParam + os_name);
    net_cmd.PushArg(kOsVersionParam + os_version);
    // Prevent Samba from setting "Samba x.x.x" here.
    net_cmd.PushArg(kOsServicePackParam);
  }

  // The machine password and the user password are read from stdin.
  const std::string machine_pass = GenerateRandomMachinePassword();
  anonymizer_->SetReplacement(machine_pass, kPasswordPlaceholder);
  base::ScopedFD passwords_pipe =
      WriteStringAndPipeToPipe(machine_pass + "\n", password_fd);
  net_cmd.SetInputFile(passwords_pipe.get());
  if (!jail_helper_.SetupJailAndRun(&net_cmd, Path::NET_ADS_SECCOMP,
                                    TIMER_NET_ADS_JOIN)) {
    Reset();
    return GetNetError(net_cmd, "join");
  }

  // Store the machine password.
  error = WriteMachinePassword(Path::MACHINE_PASS, machine_pass);
  if (error != ERROR_NONE) {
    Reset();
    return error;
  }

  // Store configuration for subsequent runs of the daemon.
  error = WriteConfiguration();
  if (error != ERROR_NONE) {
    Reset();
    return error;
  }

  // Cache auth data. Note that users in the device realm are always affiliated.
  UpdateAuthDataCache(device_account_, true /* is_affiliated */);

  // Since we just created the account, set propagation retry to give the
  // password time to propagate through Active Directory.
  device_tgt_manager_.SetPropagationRetry(true);

  // Only if everything worked out, keep the config.
  if (joined_domain)
    *joined_domain = join_realm;

  // Collecting metrics with the encryption types used during this successful
  // enrollment. This value has been set through the advanced settings of the
  // domain join screen.
  metrics_->ReportEncryptionType(ENC_TYPES_OF_JOIN_AD_DOMAIN,
                                 encryption_types_);

  return ERROR_NONE;
}

ErrorType SambaInterface::FetchUserGpos(
    const std::string& account_id, protos::GpoPolicyData* gpo_policy_data) {
  ReloadDebugFlags();
  SetUserAccountId(account_id);

  // Try to restore TGT, user_account_id_ etc. if it doesn't exist.
  MaybeRestoreUserAuthState();

  if (!user_logged_in_) {
    LOG(ERROR) << "User not logged in. Did AuthenticateUser() fail?";
    return ERROR_NOT_LOGGED_IN;
  }
  DCHECK(!user_account_.user_name.empty());
  DCHECK(!user_account_.realm.empty());

  // We need user_policy_mode_ to properly fetch user policy, which is read from
  // device policy.
  if (!has_device_policy_) {
    LOG(ERROR) << "Unknown user policy mode. Did FetchDeviceGpos() fail?";
    return ERROR_NO_DEVICE_POLICY;
  }

  // Download GPOs for the given user, taking the loopback processing |mode|
  // into account:
  //   USER_POLICY_MODE_DEFAULT: Process user GPOs as usual.
  //   USER_POLICY_MODE_MERGE:   Apply user policy from device GPOs on top of
  //                             user policy from user GPOs.
  //   USER_POLICY_MODE_REPLACE: Only apply user policy from device GPOs.
  ErrorType error;
  std::vector<base::FilePath> gpo_file_paths;
  if (user_policy_mode_ != em::DeviceUserPolicyLoopbackProcessingModeProto::
                               USER_POLICY_MODE_REPLACE) {
    // Update smb.conf, IPs, server names etc for the user account.
    error = UpdateAccountData(&user_account_);
    if (error != ERROR_NONE)
      return error;

    // Download user GPOs with user policy data.
    error = GetGpos(GpoSource::USER, PolicyScope::USER, &gpo_file_paths);
    if (error != ERROR_NONE)
      return error;
  }
  if (user_policy_mode_ != em::DeviceUserPolicyLoopbackProcessingModeProto::
                               USER_POLICY_MODE_DEFAULT) {
    // Acquire Kerberos ticket-granting-ticket for the device account.
    error = AcquireDeviceTgt();
    if (error != ERROR_NONE)
      return error;

    // Download device GPOs with user policy data.
    // Note that device account data was updated by calling `AcquireDeviceTgt()`
    // above.
    error = GetGpos(GpoSource::MACHINE, PolicyScope::USER, &gpo_file_paths);
    if (error != ERROR_NONE)
      return error;
  }

  // Parse GPOs and store them in a user+extension policy protobuf.
  std::string gpo_policy_data_blob;
  error = ParseGposIntoProtobuf(gpo_file_paths, kCmdParseUserPreg,
                                &gpo_policy_data_blob);
  if (error != ERROR_NONE)
    return error;

  error = ParsePolicyData(gpo_policy_data_blob, gpo_policy_data);
  if (error != ERROR_NONE)
    return error;

  return ERROR_NONE;
}

ErrorType SambaInterface::FetchDeviceGpos(
    protos::GpoPolicyData* gpo_policy_data) {
  ReloadDebugFlags();

  // Check if the device is domain joined.
  if (!IsDeviceJoined())
    return ERROR_NOT_JOINED;

  // Acquire Kerberos ticket-granting-ticket for the device account.
  ErrorType error = AcquireDeviceTgt();
  if (error != ERROR_NONE)
    return error;

  // Download device GPOs with device policy data.
  // Note that account data was updated by calling `AcquireDeviceTgt()` above.
  std::vector<base::FilePath> gpo_file_paths;
  error = GetGpos(GpoSource::MACHINE, PolicyScope::MACHINE, &gpo_file_paths);
  if (error != ERROR_NONE)
    return error;

  // Parse GPOs and store them in a device+extension policy protobuf.
  std::string gpo_policy_data_blob;
  error = ParseGposIntoProtobuf(gpo_file_paths, kCmdParseDevicePreg,
                                &gpo_policy_data_blob);
  if (error != ERROR_NONE)
    return error;

  error = ParsePolicyData(gpo_policy_data_blob, gpo_policy_data);
  if (error != ERROR_NONE)
    return error;

  // Update stuff that depends on device policy.
  em::ChromeDeviceSettingsProto device_policy;
  if (!device_policy.ParseFromString(
          gpo_policy_data->user_or_device_policy())) {
    LOG(ERROR) << "Failed to parse device policy";
    return ERROR_PARSE_FAILED;
  }
  UpdateDevicePolicyDependencies(device_policy);

  return ERROR_NONE;
}

void SambaInterface::OnSessionStateChanged(const std::string& state) {
  LOG(INFO) << "Session state changed to '" << state << "'";
  in_user_session_ = state == kSessionStarted;
  MaybeBackupUserAuthState();
}

void SambaInterface::SetDefaultLogLevel(AuthPolicyFlags::DefaultLevel level) {
  flags_default_level_ = level;
  LOG(INFO) << "Flags default level = " << flags_default_level_;
  SaveFlagsDefaultLevel();
}

std::string SambaInterface::GetUserPrincipal() const {
  return user_account_.GetPrincipal();
}

void SambaInterface::OnTgtRenewed() {
  MaybeBackupUserAuthState();
}

void SambaInterface::DisableRetrySleepForTesting() {
  retry_sleep_disabled_for_testing_ = true;
  device_tgt_manager_.DisableRetrySleepForTesting();
}

ErrorType SambaInterface::RenewUserTgtForTesting() {
  return user_tgt_manager_.RenewTgt();
}

void SambaInterface::SetDevicePolicyImplForTesting(
    std::unique_ptr<policy::DevicePolicyImpl> policy_impl) {
  device_policy_impl_for_testing = std::move(policy_impl);
}

void SambaInterface::ResetForTesting() {
  Reset();
}

ErrorType SambaInterface::ChangeMachinePasswordForTesting() {
  const base::FilePath password_path(paths_->Get(Path::MACHINE_PASS));
  std::string old_password;
  if (!ReadMachinePasswordToString(password_path, &old_password))
    return ERROR_LOCAL_IO;

  auto stored_password_change_rate_ = password_change_rate_;
  password_change_rate_ = base::Milliseconds(1);
  ErrorType error = CheckMachinePasswordChange();
  password_change_rate_ = stored_password_change_rate_;
  if (error != ERROR_NONE)
    return error;

  std::string new_password;
  if (!ReadMachinePasswordToString(password_path, &new_password))
    return ERROR_LOCAL_IO;

  if (new_password == old_password)
    return ERROR_KPASSWD_FAILED;

  return ERROR_NONE;
}

ErrorType SambaInterface::UpdateKdcIpAndServerTime(AccountData* account) const {
  // Look up KDC IP from cache.
  if (account->kdc_ip.empty()) {
    std::optional<std::string> kdc_ip =
        auth_data_cache_.GetKdcIp(account->realm);
    if (kdc_ip) {
      account->kdc_ip = std::move(*kdc_ip);
      anonymizer_->SetReplacementAllCases(account->kdc_ip,
                                          kIpAddressPlaceholder);
    }
  }

  // Use cached KDC IP and server time. Caching server time seems weird since it
  // changes constantly, but most code doesn't need server time. If an
  // up-to-date server time is needed, just reset it to base::Time() before
  // calling UpdateAccountData();
  if (!account->kdc_ip.empty() && !account->server_time.is_null())
    return ERROR_NONE;

  // Call net ads info to get the KDC IP.
  const std::string& smb_conf_path = paths_->Get(account->smb_conf_path);
  authpolicy::ProcessExecutor net_cmd({paths_->Get(Path::NET), "ads", "info",
                                       kConfigParam, smb_conf_path, kDebugParam,
                                       flags_.net_log_level()});
  // Replace a few values immediately in the net_cmd output, see
  // SearchAccountInfo for an explanation.
  anonymizer_->ReplaceSearchArg(kKeyKdcServer, kIpAddressPlaceholder);
  anonymizer_->ReplaceSearchArg(kKeyLdapServer, kIpAddressPlaceholder);
  anonymizer_->ReplaceSearchArg(kKeyLdapServerName, kServerNamePlaceholder);
  const bool net_result = jail_helper_.SetupJailAndRun(
      &net_cmd, Path::NET_ADS_SECCOMP, TIMER_NET_ADS_INFO);
  anonymizer_->ResetSearchArgReplacements();
  if (!net_result)
    return GetNetError(net_cmd, "info");
  const std::string& net_out = net_cmd.GetStdout();

  // Parse the output to find the KDC IP. Enclose in a sandbox for security
  // considerations.
  ProcessExecutor parse_cmd(
      {paths_->Get(Path::PARSER), kCmdParseServerInfo, SerializeFlags(flags_)});
  parse_cmd.SetInputString(net_out);
  if (!jail_helper_.SetupJailAndRun(&parse_cmd, Path::PARSER_SECCOMP,
                                    TIMER_NONE)) {
    // Log net output if it hasn't been done yet.
    net_cmd.LogOutputOnce();
    LOG(ERROR) << "authpolicy_parser parse_server_info failed with exit code "
               << parse_cmd.GetExitCode();
    return ERROR_PARSE_FAILED;
  }

  protos::ServerInfo server_info;
  if (!server_info.ParseFromString(parse_cmd.GetStdout())) {
    // Log net output if it hasn't been done yet.
    net_cmd.LogOutputOnce();
    LOG(ERROR) << "Failed to parse server info protobuf";
    return ERROR_PARSE_FAILED;
  }

  account->kdc_ip = server_info.kdc_ip();
  account->server_time =
      base::Time::FromInternalValue(server_info.server_time());

  // Explicitly set replacements again, see SearchAccountInfo for an
  // explanation.
  anonymizer_->SetReplacementAllCases(account->kdc_ip, kIpAddressPlaceholder);

  return ERROR_NONE;
}

ErrorType SambaInterface::UpdateDcName(AccountData* account) const {
  // Look up DC name from cache.
  if (account->dc_name.empty()) {
    std::optional<std::string> dc_name =
        auth_data_cache_.GetDcName(account->realm);
    if (dc_name) {
      account->dc_name = std::move(*dc_name);
      anonymizer_->SetReplacementAllCases(account->dc_name,
                                          kServerNamePlaceholder);
    }
  }

  // Use cached DC name.
  if (!account->dc_name.empty())
    return ERROR_NONE;

  // Call net ads lookup to get the domain controller name.
  const std::string& smb_conf_path = paths_->Get(account->smb_conf_path);
  authpolicy::ProcessExecutor net_cmd({paths_->Get(Path::NET), "ads", "lookup",
                                       kConfigParam, smb_conf_path, kDebugParam,
                                       flags_.net_log_level()});
  // Replace a few values immediately in the net_cmd output, see
  // SearchAccountInfo for an explanation.
  anonymizer_->ReplaceSearchArg(kKeyForest, kForestPlaceholder);
  anonymizer_->ReplaceSearchArg(kKeyDomain, kDomainPlaceholder);
  anonymizer_->ReplaceSearchArg(kKeyDomainController, kServerNamePlaceholder);
  anonymizer_->ReplaceSearchArg(kKeyPreWin2kDomain, kDomainPlaceholder);
  anonymizer_->ReplaceSearchArg(kKeyPreWin2kHostname, kServerNamePlaceholder);
  anonymizer_->ReplaceSearchArg(kKeyServerSiteName, kSiteNamePlaceholder);
  anonymizer_->ReplaceSearchArg(kKeyClientSiteName, kSiteNamePlaceholder);
  const bool net_result = jail_helper_.SetupJailAndRun(
      &net_cmd, Path::NET_ADS_SECCOMP, TIMER_NET_ADS_INFO);
  anonymizer_->ResetSearchArgReplacements();
  if (!net_result)
    return GetNetError(net_cmd, "lookup");
  const std::string& net_out = net_cmd.GetStdout();

  // Parse the output to find the domain controller name. Enclose in a sandbox
  // for security considerations.
  ProcessExecutor parse_cmd(
      {paths_->Get(Path::PARSER), kCmdParseDcName, SerializeFlags(flags_)});
  parse_cmd.SetInputString(net_out);
  if (!jail_helper_.SetupJailAndRun(&parse_cmd, Path::PARSER_SECCOMP,
                                    TIMER_NONE)) {
    // Log net output if it hasn't been done yet.
    net_cmd.LogOutputOnce();
    LOG(ERROR) << "authpolicy_parser parse_dc_name failed with exit code "
               << parse_cmd.GetExitCode();
    return ERROR_PARSE_FAILED;
  }
  account->dc_name = parse_cmd.GetStdout();

  // Explicitly set replacements again, see SearchAccountInfo for an
  // explanation.
  anonymizer_->SetReplacementAllCases(account->dc_name, kServerNamePlaceholder);

  return ERROR_NONE;
}

ErrorType SambaInterface::GetUserTgtStatus(
    ActiveDirectoryUserStatus::TgtStatus* tgt_status) {
  protos::TgtLifetime lifetime;
  ErrorType error = user_tgt_manager_.GetTgtLifetime(&lifetime);
  switch (error) {
    case ERROR_NONE:
      *tgt_status = lifetime.validity_seconds() > 0
                        ? ActiveDirectoryUserStatus::TGT_VALID
                        : ActiveDirectoryUserStatus::TGT_EXPIRED;
      return ERROR_NONE;
    // Eat two errors and convert them to TgtStatus values instead.
    case ERROR_NO_CREDENTIALS_CACHE_FOUND:
      *tgt_status = ActiveDirectoryUserStatus::TGT_NOT_FOUND;
      return ERROR_NONE;
    case ERROR_KERBEROS_TICKET_EXPIRED:
      *tgt_status = ActiveDirectoryUserStatus::TGT_EXPIRED;
      return ERROR_NONE;
    default:
      return error;
  }
}

ActiveDirectoryUserStatus::PasswordStatus SambaInterface::GetUserPasswordStatus(
    const ActiveDirectoryAccountInfo& account_info) {
  // See https://msdn.microsoft.com/en-us/library/ms679430(v=vs.85).aspx.

  // Gracefully handle missing fields, see crbug.com/795758.
  if (!account_info.has_pwd_last_set() ||
      !account_info.has_user_account_control()) {
    return ActiveDirectoryUserStatus::PASSWORD_VALID;
  }

  // Password is always valid if it never expires.
  if ((account_info.user_account_control() & UF_DONT_EXPIRE_PASSWD) != 0)
    return ActiveDirectoryUserStatus::PASSWORD_VALID;

  // Password expired, user will have to enter a new password.
  if (account_info.pwd_last_set() == 0)
    return ActiveDirectoryUserStatus::PASSWORD_EXPIRED;

  // Memorize pwd_last_set if it wasn't set yet. This happens after the password
  // expired and was reset by AuthenticateUser().
  if (user_pwd_last_set_ == 0) {
    user_pwd_last_set_ = account_info.pwd_last_set();
    return ActiveDirectoryUserStatus::PASSWORD_VALID;
  }

  // Password changed on the server. Note: Don't update pwd_last_set_ here,
  // update it in AuthenticateUser() when we know that Chrome sent the right
  // password.
  if (user_pwd_last_set_ != account_info.pwd_last_set())
    return ActiveDirectoryUserStatus::PASSWORD_CHANGED;

  // pwd_last_set did not change, password is still valid.
  return ActiveDirectoryUserStatus::PASSWORD_VALID;
}

ErrorType SambaInterface::UpdateWorkgroup(AccountData* account) const {
  // Look up workgroup from cache.
  if (account->workgroup.empty()) {
    std::optional<std::string> workgroup =
        auth_data_cache_.GetWorkgroup(account->realm);
    if (workgroup) {
      account->workgroup = std::move(*workgroup);
      anonymizer_->SetReplacement(account->workgroup, kWorkgroupPlaceholder);
    }
  }

  // Use cached workgroup.
  if (!account->workgroup.empty())
    return ERROR_NONE;

  const std::string& smb_conf_path = paths_->Get(account->smb_conf_path);
  ProcessExecutor net_cmd({paths_->Get(Path::NET), "ads", "workgroup",
                           kConfigParam, smb_conf_path, kDebugParam,
                           flags_.net_log_level()});
  // Parse workgroup from the net_cmd output immediately, see SearchAccountInfo
  // for an explanation. Also replace a bunch of other server names.
  anonymizer_->ReplaceSearchArg(kKeyWorkgroup, kWorkgroupPlaceholder);
  anonymizer_->ReplaceSearchArg(kKeyAdsDnsParseRrSrv, kServerNamePlaceholder,
                                "Parsed (.+?)\\.");
  anonymizer_->ReplaceSearchArg(kKeyPdcDnsName, kServerNamePlaceholder,
                                "'(.+)'");
  anonymizer_->ReplaceSearchArg(kKeyAdsDcName, kServerNamePlaceholder,
                                "using server='(.+?)\\.");
  anonymizer_->ReplaceSearchArg(kKeyPdcName, kServerNamePlaceholder, "'(.+)'");
  anonymizer_->ReplaceSearchArg(kKeyServerSite, kSiteNamePlaceholder, "'(.+)'");
  anonymizer_->ReplaceSearchArg(kKeyClientSite, kSiteNamePlaceholder, "'(.+)'");
  const bool net_result = jail_helper_.SetupJailAndRun(
      &net_cmd, Path::NET_ADS_SECCOMP, TIMER_NET_ADS_WORKGROUP);
  anonymizer_->ResetSearchArgReplacements();
  if (!net_result)
    return GetNetError(net_cmd, "workgroup");
  const std::string& net_out = net_cmd.GetStdout();

  // Parse the output to find the workgroup. Enclose in a sandbox for security
  // considerations.
  ProcessExecutor parse_cmd(
      {paths_->Get(Path::PARSER), kCmdParseWorkgroup, SerializeFlags(flags_)});
  parse_cmd.SetInputString(net_out);
  if (!jail_helper_.SetupJailAndRun(&parse_cmd, Path::PARSER_SECCOMP,
                                    TIMER_NONE)) {
    LOG(ERROR) << "authpolicy_parser parse_workgroup failed with exit code "
               << parse_cmd.GetExitCode();
    return ERROR_PARSE_FAILED;
  }
  account->workgroup = parse_cmd.GetStdout();

  // Explicitly set replacements again, see SearchAccountInfo for an
  // explanation.
  anonymizer_->SetReplacement(account->workgroup, kWorkgroupPlaceholder);
  return ERROR_NONE;
}

ErrorType SambaInterface::WriteSmbConf(const AccountData& account) const {
  // account.netbios_name and account.workgroup may be empty at this point.
  DCHECK(!account.realm.empty());

  std::string data = base::StringPrintf(
      kSmbConfData, account.netbios_name.c_str(), account.workgroup.c_str(),
      account.realm.c_str(), paths_->Get(Path::SAMBA_LOCK_DIR).c_str(),
      paths_->Get(Path::SAMBA_CACHE_DIR).c_str(),
      paths_->Get(Path::SAMBA_STATE_DIR).c_str(),
      paths_->Get(Path::SAMBA_PRIVATE_DIR).c_str(),
      GetEncryptionTypesString(encryption_types_));

  const base::FilePath smbconf_path(paths_->Get(account.smb_conf_path));
  const int data_size = static_cast<int>(data.size());
  if (base::WriteFile(smbconf_path, data.data(), data_size) != data_size) {
    LOG(ERROR) << "Failed to write Samba conf file '" << smbconf_path.value()
               << "'";
    return ERROR_LOCAL_IO;
  }

  return ERROR_NONE;
}

ErrorType SambaInterface::UpdateAccountData(AccountData* account) {
  // Write smb.conf for UpdateWorkgroup().
  ErrorType error = WriteSmbConf(*account);
  if (error != ERROR_NONE)
    return error;

  // Update |account|->workgroup.
  const std::string prev_workgroup = account->workgroup;
  error = UpdateWorkgroup(account);
  if (error != ERROR_NONE)
    return error;

  // Write smb.conf again for the rest in case the workgroup changed.
  if (account->workgroup != prev_workgroup) {
    error = WriteSmbConf(*account);
    if (error != ERROR_NONE)
      return error;
  }

  // Set fake domain SID if it was not set for this account workgroup yet.
  // This is workaround for Samba 4.8.6+, see `MaybeSetFakeDomainSid()`
  // description.
  error = MaybeSetFakeDomainSid(*account);
  if (error != ERROR_NONE)
    return error;

  // Query the key distribution center IP and server time and store them in
  // |account|->kdc_ip and |account|->server_time, respectively.
  error = UpdateKdcIpAndServerTime(account);
  if (error != ERROR_NONE)
    return error;

  // Query the domain controller name and store it in |account|->dc_name.
  error = UpdateDcName(account);
  if (error != ERROR_NONE)
    return error;

  return ERROR_NONE;
}

ErrorType SambaInterface::PingServer(AccountData* account) {
  // Write smb.conf for UpdateWorkgroup().
  ErrorType error = WriteSmbConf(*account);
  if (error != ERROR_NONE)
    return error;

  // Update |account|->workgroup. Make sure to invalidate the workgroup and
  // disable the cache, so that the server is actually hit.
  std::string prev_workgroup;
  prev_workgroup.swap(account->workgroup);
  bool prev_enabled = auth_data_cache_.IsEnabled();
  auth_data_cache_.SetEnabled(false);

  error = UpdateWorkgroup(account);

  auth_data_cache_.SetEnabled(prev_enabled);
  prev_workgroup.swap(account->workgroup);
  return error;
}

bool SambaInterface::IsUserAffiliated() {
  // Check cache first.
  std::optional<bool> cached_is_affiliated =
      auth_data_cache_.GetIsAffiliated(user_account_.realm);
  if (cached_is_affiliated) {
    // Right now, only affiliated realms should be cached (but we'll keep it
    // generic, anyway, in case that changes in the future).
    CHECK(*cached_is_affiliated)
        << "Caching for unaffiliated realms not supported";
    return *cached_is_affiliated;
  }

  // Users on device realm are always affiliated.
  if (user_account_.realm == device_account_.realm)
    return true;

  // Call net ads search using
  //   - the device smb.conf, but
  //   - the user's credentials!
  // This enforces a trust check, which tells us about affiliation.
  const std::string& smb_conf_path = paths_->Get(device_account_.smb_conf_path);
  std::string search_string = base::StringPrintf(
      "(sAMAccountName=%s)", device_account_.user_name.c_str());
  ProcessExecutor net_cmd({paths_->Get(Path::NET), "ads", "search",
                           search_string, kSearchSAMAccountName, kConfigParam,
                           smb_conf_path, kDebugParam, flags_.net_log_level(),
                           kKerberosParam});
  net_cmd.SetEnv(kKrb5CCEnvKey,
                 paths_->Get(user_tgt_manager_.GetCredentialCachePath()));
  const bool net_result = jail_helper_.SetupJailAndRun(
      &net_cmd, Path::NET_ADS_SECCOMP, TIMER_NET_ADS_SEARCH);

  // net is expected to fail if the user is not affiliated. In my test setup
  // with different KDCs, net failed with exit code 255 and no error message,
  // resulting in ERROR_NET_FAILED (there was a "Cannot read password" error in
  // debug logs). It's unclear, though, if that's always the case, so just print
  // out the error otherwise and assume the user is not affiliated. By no means
  // bail on error here.
  if (!net_result) {
    ErrorType error = GetNetError(net_cmd, "search");
    if (error != ERROR_NET_FAILED)
      LOG(ERROR) << "Affiliation check failed with error " << error;
    return false;
  }

  // Expected output in case of success:
  // Got 1 replies
  //
  // sAMAccountName: <MACHINE_NAME>
  return Contains(net_cmd.GetStdout(), kSearchSAMAccountName);
}

ErrorType SambaInterface::AcquireUserTgt(int password_fd) {
  // Update smb.conf, IPs, server names etc. for the user account.
  ErrorType error = UpdateAccountData(&user_account_);
  if (error != ERROR_NONE)
    return error;
  user_tgt_manager_.SetKdcIp(user_account_.kdc_ip);

  // Call kinit to get the Kerberos ticket-granting-ticket.
  return user_tgt_manager_.AcquireTgtWithPassword(password_fd);
}

ErrorType SambaInterface::AcquireDeviceTgt() {
  // Update smb.conf, IPs, server names etc for the device account.
  ErrorType error = UpdateAccountData(&device_account_);
  if (error != ERROR_NONE)
    return error;
  device_tgt_manager_.SetKdcIp(device_account_.kdc_ip);

  // Acquire the Kerberos ticket-granting-ticket.
  const base::FilePath password_path(paths_->Get(Path::MACHINE_PASS));
  if (!base::PathExists(password_path)) {
    // This is expected to happen on devices that had been domain joined before
    // authpolicyd managed the machine password. They stored the machine keytab
    // instead of the password, so use that for authentication.
    return device_tgt_manager_.AcquireTgtWithKeytab(Path::MACHINE_KEYTAB);
  }

  // Authenticate using password. Note: There is no keytab file here.
  base::ScopedFD password_fd = ReadFileToPipe(password_path);
  if (!password_fd.is_valid()) {
    LOG(ERROR) << "Failed to open machine password file '"
               << password_path.value() << "'";
    return ERROR_LOCAL_IO;
  }
  const base::FilePath prev_password_path(paths_->Get(Path::PREV_MACHINE_PASS));
  error = device_tgt_manager_.AcquireTgtWithPassword(password_fd.get());
  if (error != ERROR_BAD_PASSWORD || !base::PathExists(prev_password_path))
    return error;

  // Try again with the previous password. After a password change the password
  // might not have propagated through a large AD deployment yet.
  password_fd = ReadFileToPipe(prev_password_path);
  if (!password_fd.is_valid()) {
    LOG(ERROR) << "Failed to open machine password file '"
               << prev_password_path.value() << "'";
    return ERROR_LOCAL_IO;
  }
  return device_tgt_manager_.AcquireTgtWithPassword(password_fd.get());
}

ErrorType SambaInterface::WriteMachinePassword(
    Path path, const std::string& machine_pass) const {
  const base::FilePath password_path(paths_->Get(path));
  if (!base::ImportantFileWriter::WriteFileAtomically(password_path,
                                                      machine_pass)) {
    LOG(ERROR) << "Failed to write machine password file '"
               << password_path.value() << "'";
    return ERROR_LOCAL_IO;
  }

  // This file is only authpolicyd's business.
  int mode =
      base::FILE_PERMISSION_READ_BY_USER | base::FILE_PERMISSION_WRITE_BY_USER;
  ErrorType error = SetFilePermissions(password_path, mode);
  if (error != ERROR_NONE)
    return error;

  // Set file time to match server time, so that we can determine the password
  // age and renew the machine password without relying on local time.
  if (!base::TouchFile(password_path, device_account_.server_time,
                       device_account_.server_time)) {
    LOG(ERROR) << "Failed to set file time on machine password file '"
               << password_path.value() << "'";
    return ERROR_LOCAL_IO;
  }

  LOG(INFO) << "Wrote machine password file '" << password_path.value() << "'";
  return ERROR_NONE;
}

ErrorType SambaInterface::RollMachinePassword() {
  const base::FilePath password_path(paths_->Get(Path::MACHINE_PASS));
  const base::FilePath prev_password_path(paths_->Get(Path::PREV_MACHINE_PASS));
  const base::FilePath new_password_path(paths_->Get(Path::NEW_MACHINE_PASS));

  base::File::Error file_error;
  if (!base::ReplaceFile(password_path, prev_password_path, &file_error) ||
      !base::ReplaceFile(new_password_path, password_path, &file_error)) {
    LOG(ERROR) << "Machine password roll failed: "
               << base::File::ErrorToString(file_error);
    return ERROR_LOCAL_IO;
  }

  return ERROR_NONE;
}

ErrorType SambaInterface::WriteConfiguration() const {
  DCHECK(!device_account_.realm.empty());
  DCHECK(!device_account_.netbios_name.empty());

  protos::ActiveDirectoryConfig config;
  config.set_realm(device_account_.realm);
  config.set_machine_name(device_account_.netbios_name);

  std::string config_blob;
  if (!config.SerializeToString(&config_blob)) {
    LOG(ERROR) << "Failed to serialize configuration to string";
    return ERROR_LOCAL_IO;
  }

  const base::FilePath config_path(paths_->Get(Path::CONFIG_DAT));
  if (!base::ImportantFileWriter::WriteFileAtomically(config_path,
                                                      config_blob)) {
    LOG(ERROR) << "Failed to write configuration file '" << config_path.value()
               << "'";
    return ERROR_LOCAL_IO;
  }

  // This file is only authpolicyd's business.
  ErrorType error =
      SetFilePermissions(config_path, base::FILE_PERMISSION_READ_BY_USER);
  if (error != ERROR_NONE)
    return error;

  LOG(INFO) << "Wrote configuration file '" << config_path.value() << "'";
  return ERROR_NONE;
}

ErrorType SambaInterface::ReadConfiguration() {
  const base::FilePath config_path(paths_->Get(Path::CONFIG_DAT));
  if (!base::PathExists(config_path)) {
    LOG(ERROR) << "Configuration file '" << config_path.value()
               << "' does not exist";
    return ERROR_LOCAL_IO;
  }

  std::string config_blob;
  if (!base::ReadFileToStringWithMaxSize(config_path, &config_blob,
                                         kConfigSizeLimit)) {
    PLOG(ERROR) << "Failed to read configuration file '" << config_path.value()
                << "'";
    return ERROR_LOCAL_IO;
  }

  auto config = std::make_unique<protos::ActiveDirectoryConfig>();
  if (!config->ParseFromString(config_blob)) {
    LOG(ERROR) << "Failed to parse configuration from string";
    return ERROR_LOCAL_IO;
  }

  // Check if the config is valid.
  if (config->machine_name().empty() || config->realm().empty()) {
    LOG(ERROR) << "Configuration is invalid";
    return ERROR_LOCAL_IO;
  }

  InitDeviceAccount(config->machine_name(), config->realm());

  LOG(INFO) << "Read configuration file '" << config_path.value() << "'";

  AnonymizeRealm(device_account_.realm, kDeviceRealmPlaceholder);
  anonymizer_->SetReplacementAllCases(device_account_.netbios_name,
                                      kMachineNamePlaceholder);
  return ERROR_NONE;
}

ErrorType SambaInterface::GetAccountInfo(
    const std::string& user_name,
    const std::string& normalized_upn,
    const std::string& account_id,
    ActiveDirectoryAccountInfo* account_info) {
  // If |account_id| is provided, search by objectGUID only.
  if (!account_id.empty()) {
    // Searching by objectGUID has to use the octet string representation!
    // Note: If |account_id| is malformed, the search yields no results.
    const std::string account_id_octet = GuidToOctetString(account_id);
    anonymizer_->SetReplacement(account_id_octet, kAccountIdPlaceholder);
    std::string search_string =
        base::StringPrintf("(objectGUID=%s)", account_id_octet.c_str());
    return SearchAccountInfo(search_string, account_info);
  }

  // Otherwise, search by sAMAccountName, then by userPrincipalName.
  anonymizer_->SetReplacement(user_name, kSAMAccountNamePlaceholder);
  std::string search_string =
      base::StringPrintf("(sAMAccountName=%s)", user_name.c_str());
  ErrorType error = SearchAccountInfo(search_string, account_info);
  if (error != ERROR_BAD_USER_NAME)  // ERROR_BAD_USER_NAME means there were
    return error;                    // no search results.

  LOG(WARNING) << "Account info not found by sAMAccountName. "
               << "Trying userPrincipalName.";
  anonymizer_->SetReplacement(user_name, kLogonNamePlaceholder);
  search_string =
      base::StringPrintf("(userPrincipalName=%s)", normalized_upn.c_str());
  return SearchAccountInfo(search_string, account_info);
}

ErrorType SambaInterface::SearchAccountInfo(
    const std::string& search_string,
    ActiveDirectoryAccountInfo* account_info) {
  // Set up net ads search to find the user's account info.
  const std::string& smb_conf_path = paths_->Get(user_account_.smb_conf_path);
  ProcessExecutor net_cmd(
      {paths_->Get(Path::NET), "ads", "search", search_string,
       kSearchObjectGUID, kSearchSAMAccountName, kSearchCommonName,
       kSearchDisplayName, kSearchGivenName, kSearchPwdLastSet,
       kSearchUserAccountControl, kConfigParam, smb_conf_path, kDebugParam,
       flags_.net_log_level(), kKerberosParam});

  // Parse the search args from the net_cmd output immediately. This resolves
  // the chicken-egg-problem that replacement strings cannot be set before the
  // strings-to-replace are known, so the output of net_cmd would still contain
  // sensitive strings.
  anonymizer_->ReplaceSearchArg(kSearchObjectGUID, kAccountIdPlaceholder);
  anonymizer_->ReplaceSearchArg(kSearchDisplayName, kDisplayNamePlaceholder);
  anonymizer_->ReplaceSearchArg(kSearchGivenName, kGivenNamePlaceholder);
  anonymizer_->ReplaceSearchArg(kSearchSAMAccountName,
                                kSAMAccountNamePlaceholder);
  anonymizer_->ReplaceSearchArg(kSearchCommonName, kCommonNamePlaceholder);

  // Use the user's TGT to query the account info.
  net_cmd.SetEnv(kKrb5CCEnvKey,
                 paths_->Get(user_tgt_manager_.GetCredentialCachePath()));
  const bool net_result = jail_helper_.SetupJailAndRun(
      &net_cmd, Path::NET_ADS_SECCOMP, TIMER_NET_ADS_SEARCH);
  anonymizer_->ResetSearchArgReplacements();
  if (!net_result) {
    return GetNetError(net_cmd, "search");
  }
  const std::string& net_out = net_cmd.GetStdout();

  // Parse the output to find the account info proto blob. Enclose in a sandbox
  // for security considerations.
  ProcessExecutor parse_cmd({paths_->Get(Path::PARSER), kCmdParseAccountInfo,
                             SerializeFlags(flags_)});
  parse_cmd.SetInputString(net_out);
  if (!jail_helper_.SetupJailAndRun(&parse_cmd, Path::PARSER_SECCOMP,
                                    TIMER_NONE)) {
    // Log net output if it hasn't been done yet.
    net_cmd.LogOutputOnce();
    LOG(ERROR) << "Failed to parse account info. Net response: " << net_out;
    return ERROR_PARSE_FAILED;
  }
  const std::string& account_info_blob = parse_cmd.GetStdout();

  // Parse account info protobuf.
  if (account_info_blob.empty()) {
    // No search results. Return ERROR_BAD_USER_NAME since it usually means that
    // the user mistyped their user name.
    LOG(WARNING) << "Search yielded no results";
    return ERROR_BAD_USER_NAME;
  } else if (!account_info->ParseFromString(account_info_blob)) {
    // Log net output if it hasn't been done yet.
    net_cmd.LogOutputOnce();
    LOG(ERROR) << "Failed to parse account info protobuf";
    return ERROR_PARSE_FAILED;
  }

  // Explicitly set replacements again in case logging is currently disabled
  // and the anonymizer has not parsed the search values above. If we didn't do
  // it here and logging would be enabled later, logs would contain sensitive
  // data.
  anonymizer_->SetReplacement(account_info->account_id(),
                              kAccountIdPlaceholder);
  anonymizer_->SetReplacement(account_info->display_name(),
                              kDisplayNamePlaceholder);
  anonymizer_->SetReplacement(account_info->given_name(),
                              kGivenNamePlaceholder);
  anonymizer_->SetReplacement(account_info->sam_account_name(),
                              kSAMAccountNamePlaceholder);
  anonymizer_->SetReplacement(account_info->common_name(),
                              kCommonNamePlaceholder);

  return ERROR_NONE;
}

ErrorType SambaInterface::GetGpos(GpoSource source,
                                  PolicyScope scope,
                                  std::vector<base::FilePath>* gpo_file_paths) {
  // There's no use case for machine policy from user GPOs right now.
  DCHECK(!(source == GpoSource::USER && scope == PolicyScope::MACHINE));

  // Query list of GPOs from Active Directory server.
  protos::GpoList gpo_list;
  ErrorType error = GetGpoList(source, scope, &gpo_list);
  if (error != ERROR_NONE)
    return error;

  // Download GPOs from Active Directory server.
  return DownloadGpos(gpo_list, source, scope, gpo_file_paths);
}

ErrorType SambaInterface::GetGpoList(GpoSource source,
                                     PolicyScope scope,
                                     protos::GpoList* gpo_list) {
  DCHECK(gpo_list);
  LOG(INFO) << "Getting " << (scope == PolicyScope::USER ? "user" : "device")
            << " GPO list for "
            << (source == GpoSource::USER ? "user" : "device") << " account";

  const AccountData& account = GetAccount(source);
  const TgtManager& tgt_manager = GetTgtManager(source);
  authpolicy::ProcessExecutor net_cmd(
      {paths_->Get(Path::NET), "ads", "gpo", "list", account.user_name,
       kConfigParam, paths_->Get(account.smb_conf_path), kDebugParam,
       flags_.net_log_level(), kKerberosParam});
  net_cmd.SetEnv(kKrb5CCEnvKey,
                 paths_->Get(tgt_manager.GetCredentialCachePath()));
  if (!jail_helper_.SetupJailAndRun(&net_cmd, Path::NET_ADS_SECCOMP,
                                    TIMER_NET_ADS_GPO_LIST)) {
    return GetNetError(net_cmd, "gpo list");
  }

  // GPO data is written to stderr, not stdin!
  const std::string& net_out = net_cmd.GetStderr();

  // Parse the GPO list. Enclose in a sandbox for security considerations. Note
  // that |cmd| depends on |scope| since the parse command is concerned with the
  // type of policy, not which account a GPO came from.
  const char* cmd = scope == PolicyScope::USER ? kCmdParseUserGpoList
                                               : kCmdParseDeviceGpoList;
  ProcessExecutor parse_cmd(
      {paths_->Get(Path::PARSER), cmd, SerializeFlags(flags_)});
  parse_cmd.SetInputString(net_out);
  if (!jail_helper_.SetupJailAndRun(&parse_cmd, Path::PARSER_SECCOMP,
                                    TIMER_NONE)) {
    // Log net output if it hasn't been done yet.
    net_cmd.LogOutputOnce();
    LOG(ERROR) << "Failed to parse GPO list";
    return ERROR_PARSE_FAILED;
  }
  std::string gpo_list_blob = parse_cmd.GetStdout();

  // Parse GPO list protobuf.
  if (!gpo_list->ParseFromString(gpo_list_blob)) {
    LOG(ERROR) << "Failed to read GPO list protobuf";
    return ERROR_PARSE_FAILED;
  }

  return ERROR_NONE;
}

struct GpoPaths {
  std::string server_;     // GPO file path on server (not a local file path!).
  base::FilePath local_;   // Local GPO file path.
  std::string cache_key_;  // Key into the gpo version cache; gpo giud + "-U/M".
  uint32_t version_;       // User or machine version of the GPO.
  bool use_cache_;  // Whether to use cached version. False to redownload.
  GpoPaths(const std::string& server,
           const base::FilePath& local,
           const std::string& cache_key,
           uint32_t version,
           bool use_cache)
      : server_(server),
        local_(local),
        cache_key_(cache_key),
        version_(version),
        use_cache_(use_cache) {}
};

ErrorType SambaInterface::DownloadGpos(
    const protos::GpoList& gpo_list,
    GpoSource source,
    PolicyScope scope,
    std::vector<base::FilePath>* gpo_file_paths) {
  metrics_->Report(METRIC_DOWNLOAD_GPO_COUNT, gpo_list.entries_size());
  if (gpo_list.entries_size() == 0) {
    LOG(INFO) << "No GPOs to download";
    return ERROR_NONE;
  }

  // Clean up GPO cache.
  gpo_version_cache_.RemoveEntriesOlderThan(gpo_version_cache_ttl_);

  // Generate all smb source and linux target directories and create targets.
  ErrorType error;
  std::string smb_command = "prompt OFF;lowercase ON;";
  std::string gpo_share;
  std::vector<GpoPaths> gpo_paths;
  bool anything_to_download = false;
  for (int entry_idx = 0; entry_idx < gpo_list.entries_size(); ++entry_idx) {
    const protos::GpoEntry& gpo = gpo_list.entries(entry_idx);

    // Security check, make sure nobody sneaks in smbclient commands.
    if (gpo.share().find(';') != std::string::npos ||
        gpo.directory().find(';') != std::string::npos) {
      LOG(ERROR) << "GPO paths may not contain a ';'";
      return ERROR_BAD_GPOS;
    }

    // All GPOs should have the same share, i.e. come from the same SysVol.
    if (gpo_share.empty()) {
      gpo_share = gpo.share();
    } else if (!base::EqualsCaseInsensitiveASCII(gpo_share, gpo.share())) {
      LOG(ERROR) << "Inconsistent share '" << gpo_share << "' != '"
                 << gpo.share() << "'";
      return ERROR_BAD_GPOS;
    }

    // Figure out local (Linux) and remote (smb) directories.
    const char* preg_dir =
        scope == PolicyScope::USER ? kPRegUserDir : kPRegDeviceDir;
    std::string smb_dir =
        base::StringPrintf("\\%s\\%s", gpo.directory().c_str(), preg_dir);
    std::string linux_dir = paths_->Get(Path::GPO_LOCAL_DIR) + smb_dir;
    std::replace(linux_dir.begin(), linux_dir.end(), '\\', '/');

    // Make local directory.
    const base::FilePath linux_dir_fp(linux_dir);
    error = ::authpolicy::CreateDirectory(linux_dir_fp);
    if (error != ERROR_NONE)
      return error;

    // Set group rwx permissions recursively, so that smbclient can write GPOs
    // there and the parser tool can read the GPOs later.
    error = SetFilePermissionsRecursive(
        linux_dir_fp, base::FilePath(paths_->Get(Path::SAMBA_CACHE_DIR)),
        kFileMode_rwxrwx);
    if (error != ERROR_NONE)
      return error;

    // Figure out whether we can use cached GPO to skip download. As cache key
    // use {GPO-GUID}-U for user policy and {GPO-GUID}-M for machine policy.
    // (User and machine policy are two separate files, even though it's the
    // same GPO). Note that the GPO file may not exist, but that's fine.
    const char* scope_extension = (scope == PolicyScope::USER ? "-U" : "-M");
    const std::string cache_key = gpo.name() + scope_extension;
    const bool use_cache =
        gpo_version_cache_.MayUseCachedGpo(cache_key, gpo.version());

    // Record output file paths.
    const std::string server_path = smb_dir + "\\" + kPRegFileName;
    const auto local_path = base::FilePath(linux_dir).Append(kPRegFileName);
    gpo_paths.push_back(
        GpoPaths(server_path, local_path, cache_key, gpo.version(), use_cache));

    if (!use_cache) {
      // Delete the stale GPO file if it exists.
      if (!base::DeleteFile(local_path)) {
        LOG(ERROR) << "Failed to delete old GPO file '"
                   << anonymizer_->Process(local_path.value()) << "'";
        return ERROR_LOCAL_IO;
      }

      // Build command to download the GPO file via smbclient.
      smb_command += base::StringPrintf("cd %s;lcd %s;get %s;", smb_dir.c_str(),
                                        linux_dir.c_str(), kPRegFileName);
      anything_to_download = true;
    }
  }

  // Skip smbclient call if there's nothing to download.
  if (anything_to_download) {
    const AccountData& account = GetAccount(source);
    DCHECK(!account.dc_name.empty());
    const std::string service = base::StringPrintf(
        "//%s/%s", account.dc_name.c_str(), gpo_share.c_str());

    // The exit code of smbclient corresponds to the LAST command issued. Some
    // files might be missing and fail to download, which is fine and handled
    // below. Appending 'exit' makes sure the exit code is not 1 if the last
    // file happens to be missing.
    smb_command += "exit;";

    // Download GPO into local directory. Retry a couple of times in case of
    // network errors, Kerberos authentication may be flaky in some deployments,
    // see crbug.com/684733.
    ProcessExecutor smb_client_cmd(
        {paths_->Get(Path::SMBCLIENT), service, kConfigParam,
         paths_->Get(account.smb_conf_path), kKerberosParam, kDebugParam,
         flags_.net_log_level(), kCommandParam, smb_command});
    const TgtManager& tgt_manager = GetTgtManager(source);
    smb_client_cmd.SetEnv(kKrb5CCEnvKey,
                          paths_->Get(tgt_manager.GetCredentialCachePath()));
    smb_client_cmd.SetEnv(
        kKrb5ConfEnvKey,  // Kerberos configuration file path.
        kFilePrefix + paths_->Get(tgt_manager.GetConfigPath()));
    int tries, failed_tries = 0;
    for (tries = 1; tries <= kSmbClientMaxTries; ++tries) {
      if (tries > 1 && !retry_sleep_disabled_for_testing_)
        base::PlatformThread::Sleep(kSmbClientRetryDelay);
      if (jail_helper_.SetupJailAndRun(&smb_client_cmd, Path::SMBCLIENT_SECCOMP,
                                       TIMER_SMBCLIENT)) {
        error = ERROR_NONE;
        break;
      }
      failed_tries++;
      error = GetSmbclientError(smb_client_cmd);
      if (error != ERROR_NETWORK_PROBLEM)
        break;
    }
    metrics_->Report(METRIC_SMBCLIENT_FAILED_TRY_COUNT, failed_tries);
    if (error != ERROR_NONE)
      return error;

    // Note that the errors are in stdout and the output is in stderr :-/
    const std::string& smbclient_out_lower =
        base::ToLowerASCII(smb_client_cmd.GetStdout());

    // Gracefully handle non-existing GPOs. Testing revealed these cases do
    // exist, see crbug.com/680921.
    for (const GpoPaths& gpo_path : gpo_paths) {
      if (gpo_path.use_cache_)
        continue;
      if (base::PathExists(gpo_path.local_))
        continue;

      const std::string no_file_error_key(
          base::ToLowerASCII(kKeyObjectNameNotFound + gpo_path.server_));
      if (Contains(smbclient_out_lower, no_file_error_key)) {
        LOG_IF(WARNING, flags_.log_gpo())
            << "Ignoring missing preg file '"
            << anonymizer_->Process(gpo_path.local_.value()) << "'";
      } else {
        // Log smbclient output if it hasn't been done yet.
        smb_client_cmd.LogOutputOnce();
        LOG(ERROR) << "Failed to download preg file '"
                   << anonymizer_->Process(gpo_path.local_.value()) << "'";
        gpo_version_cache_.Remove(gpo_path.cache_key_);
        return ERROR_SMBCLIENT_FAILED;
      }
    }
  }

  // Gather a list of existing GPO files and update cache.
  DCHECK(gpo_file_paths);
  for (const GpoPaths& gpo_path : gpo_paths) {
    if (base::PathExists(gpo_path.local_))
      gpo_file_paths->push_back(gpo_path.local_);

    // Add GPO to the cache even if the file didn't actually download.
    if (!gpo_path.use_cache_)
      gpo_version_cache_.Add(gpo_path.cache_key_, gpo_path.version_);
  }

  return ERROR_NONE;
}

ErrorType SambaInterface::ParseGposIntoProtobuf(
    const std::vector<base::FilePath>& gpo_file_paths,
    const char* parser_cmd_string,
    std::string* policy_blob) const {
  // Convert file paths to proto blob.
  std::string gpo_file_paths_blob;
  protos::FilePathList fp_proto;
  for (const auto& fp : gpo_file_paths)
    *fp_proto.add_entries() = fp.value();
  if (!fp_proto.SerializeToString(&gpo_file_paths_blob)) {
    LOG(ERROR) << "Failed to serialize policy file paths to protobuf";
    return ERROR_PARSE_PREG_FAILED;
  }

  // Load GPOs into protobuf. Enclose in a sandbox for security considerations.
  ProcessExecutor parse_cmd(
      {paths_->Get(Path::PARSER), parser_cmd_string, SerializeFlags(flags_)});
  parse_cmd.SetInputString(gpo_file_paths_blob);
  if (!jail_helper_.SetupJailAndRun(&parse_cmd, Path::PARSER_SECCOMP,
                                    TIMER_NONE)) {
    LOG(ERROR) << "Failed to parse preg files";
    return ERROR_PARSE_PREG_FAILED;
  }
  *policy_blob = parse_cmd.GetStdout();
  return ERROR_NONE;
}

void SambaInterface::UpdateDevicePolicyDependencies(
    const em::ChromeDeviceSettingsProto& device_policy) {
  has_device_policy_ = true;

  // Get Kerberos encryption types policy. Note that we fall back to strong
  // encryption if the policy is not set.
  KerberosEncryptionTypes enc_types = GetEncryptionTypes(device_policy);
  SetKerberosEncryptionTypes(enc_types);

  // Get loopback processing mode.
  user_policy_mode_ = GetUserPolicyMode(device_policy);

  // Update machine password change rate. Use the default 30 days for now until
  // the DeviceMachinePasswordChangeRate arrives in Chrome OS.
  base::TimeDelta password_change_rate =
      GetMachinePasswordChangeRate(device_policy);
  UpdateMachinePasswordAutoChange(password_change_rate);

  // Update GPO version cache. The cache is disabled if the TTL is 0.
  gpo_version_cache_ttl_ = GetGpoVersionCacheTTL(device_policy);
  gpo_version_cache_.SetEnabled(gpo_version_cache_ttl_ > kZeroDelta);
  if (!gpo_version_cache_.IsEnabled())
    gpo_version_cache_.Clear();

  // Update auth data cache. The cache is disabled if the TTL is 0.
  auth_data_cache_ttl_ = GetAuthDataCacheTTL(device_policy);
  auth_data_cache_.SetEnabled(auth_data_cache_ttl_ > kZeroDelta);
  if (!auth_data_cache_.IsEnabled()) {
    auth_data_cache_.Clear();
    const base::FilePath cache_path(paths_->Get(Path::AUTH_DATA_CACHE));
    if (!base::DeleteFile(cache_path)) {
      LOG(ERROR) << "Failed delete auth data cache file '" << cache_path.value()
                 << "'";
    }
  }
}

void SambaInterface::UpdateUserAffiliation() {
  // Must be called after successful login.
  DCHECK(user_logged_in_);

  // Figure out if the user is affiliated.
  is_user_affiliated_ = IsUserAffiliated();
  LOG(INFO) << "User is " << (is_user_affiliated_ ? "" : "not ")
            << "affiliated";

  // Cache auth data, but ONLY if the user is affiliated (for privacy reasons).
  if (is_user_affiliated_)
    UpdateAuthDataCache(user_account_, is_user_affiliated_);
}

void SambaInterface::UpdateAuthDataCache(const AccountData& account,
                                         bool is_affiliated) {
  // Update cache.
  auth_data_cache_.SetWorkgroup(account.realm, account.workgroup);
  auth_data_cache_.SetKdcIp(account.realm, account.kdc_ip);
  auth_data_cache_.SetDcName(account.realm, account.dc_name);
  auth_data_cache_.SetIsAffiliated(account.realm, is_affiliated);

  // Flush cache to file. Do a best effort, don't bother if it fails.
  const base::FilePath cache_path(paths_->Get(Path::AUTH_DATA_CACHE));
  auth_data_cache_.Save(cache_path);
}

void SambaInterface::UpdateMachinePasswordAutoChange(
    const base::TimeDelta& rate) {
  password_change_rate_ = rate;

  // Disable password auto change if the rate is non-positive.
  if (password_change_rate_ <= base::Days(0)) {
    password_change_timer_.Stop();
    return;
  }

  // Are we using a machine password at all? Devices joined before the switch
  // from keytab to password still use keytabs, so changing the machine password
  // isn't possible.
  if (!base::PathExists(base::FilePath(paths_->Get(Path::MACHINE_PASS)))) {
    LOG(WARNING)
        << "Cannot change the machine password since this devices still uses "
           "the keytab file. Re-enrolling the device will fix this.";
    return;
  }

  // Start timer for the password change checker.
  if (!password_change_timer_.IsRunning()) {
    password_change_timer_.Start(
        FROM_HERE, kPasswordChangeCheckRate, this,
        &SambaInterface::AutoCheckMachinePasswordChange);

    // Perform a check immediately. This usually happens on startup and makes
    // sure we do at least one check during a session.
    AutoCheckMachinePasswordChange();
  }
}

void SambaInterface::AutoCheckMachinePasswordChange() {
  LOG(INFO) << "Running scheduled machine password age check";
  ErrorType error = CheckMachinePasswordChange();
  if (error != ERROR_NONE)
    LOG(ERROR) << "Machine password check failed with error " << error;
  did_password_change_check_run_for_testing_ = true;
  metrics_->ReportError(ERROR_OF_AUTO_MACHINE_PASSWORD_CHANGE, error);
}

ErrorType SambaInterface::CheckMachinePasswordChange() {
  // Get the latest server time and KDC IP. Reset |server_time| to enforce an
  // update (otherwise, the cached values are kept).
  device_account_.server_time = base::Time();
  ErrorType error = UpdateAccountData(&device_account_);
  if (error != ERROR_NONE)
    return error;
  device_tgt_manager_.SetKdcIp(device_account_.kdc_ip);

  const base::FilePath password_path(paths_->Get(Path::MACHINE_PASS));
  base::File::Info file_info;
  if (!GetFileInfo(password_path, &file_info)) {
    LOG(ERROR)
        << "Machine password check failed. Could not get info for machine "
        << "password file '" << password_path.value() << "'";
    return ERROR_LOCAL_IO;
  }

  // Check if the password is older than the change rate (=max age).
  base::TimeDelta password_age =
      device_account_.server_time - file_info.last_modified;
  if (password_age < password_change_rate_) {
    int total_hours_left = (password_change_rate_ - password_age).InHours();
    int days_left = total_hours_left / base::Time::kHoursPerDay;
    int hours_left = total_hours_left % base::Time::kHoursPerDay;

    LOG(INFO) << "No need to change machine password (" << days_left << "d "
              << hours_left << "h left)";
    return ERROR_NONE;
  }

  LOG(INFO) << "Machine password is older than "
            << password_change_rate_.InDays() << " days. Changing.";

  // Read the old password.
  std::string old_password;
  if (!ReadMachinePasswordToString(password_path, &old_password))
    return ERROR_LOCAL_IO;

  // Generate and write a new password.
  const std::string new_password = GenerateRandomMachinePassword();
  error = WriteMachinePassword(Path::NEW_MACHINE_PASS, new_password);
  if (error != ERROR_NONE)
    return error;

  // Change the machine password on the server.
  error = device_tgt_manager_.ChangePassword(old_password, new_password);
  if (error != ERROR_NONE)
    return error;

  // Roll password files.
  error = RollMachinePassword();

  if (error != ERROR_NONE) {
    // Try writing the new password directly, ignoring the previous one.
    error = WriteMachinePassword(Path::MACHINE_PASS, new_password);
  }

  if (error != ERROR_NONE) {
    // Do a best effort recovering the old password. If that doesn't work, we
    // won't be able to access the machine account anymore!
    ErrorType change_back_error =
        device_tgt_manager_.ChangePassword(new_password, old_password);
    ErrorType write_error =
        WriteMachinePassword(Path::MACHINE_PASS, old_password);
    if (change_back_error != ERROR_NONE || write_error != ERROR_NONE) {
      LOG(ERROR) << "Recovering the old machine password failed. Your device "
                    "is in an invalid state and needs to be re-enrolled.";
    }
    return error;
  }

  LOG(INFO) << "Successfully changed machine password";
  return ERROR_NONE;
}

void SambaInterface::SetUserAccountId(const std::string& account_id) {
  // Don't allow authenticating multiple users. Chrome should prevent that.
  CHECK(!account_id.empty());
  if (user_account_id_ == account_id)
    return;
  CHECK(user_account_id_.empty()) << "Multi-user not supported";
  user_account_id_ = account_id;

  // Get the user daemon store path to back up auth data.
  DCHECK(cryptohome_client_);
  std::string sanitized_username =
      cryptohome_client_->GetSanitizedUsername(GetAccountIdKey(account_id));
  if (sanitized_username.empty()) {
    LOG(ERROR) << "Failed to get sanitized username. "
                  "Auth state backups won't work.";
    return;
  }
  user_daemon_store_path_ = base::FilePath(paths_->Get(Path::DAEMON_STORE_DIR))
                                .Append(sanitized_username);
}

void SambaInterface::SetUserRealm(const std::string& user_realm) {
  // Allow setting the realm only once. This makes sure that nobody calls
  // AuthenticateUser() with a different realm, the call fails and we're stuck
  // with a wrong realm.
  CHECK(!user_realm.empty());
  CHECK(user_account_.realm.empty() || user_account_.realm == user_realm)
      << "Multi-user not supported";
  user_account_.realm = user_realm;
  user_tgt_manager_.SetRealm(user_account_.realm);
  AnonymizeRealm(user_realm, kUserRealmPlaceholder);
}

ErrorType SambaInterface::MaybeSetFakeDomainSid(const AccountData& account) {
  // Don't set twice for the same workgroup.
  if (fake_domain_sid_was_set_for_workgroup_.find(account.workgroup) !=
      fake_domain_sid_was_set_for_workgroup_.end())
    return ERROR_NONE;

  // Reuse the NET_ADS_SECCOMP filter for simplicity, even though it's not a net
  // ads command.
  ProcessExecutor net_cmd({paths_->Get(Path::NET), "setdomainsid",
                           kFakeDomainSid, kConfigParam,
                           paths_->Get(account.smb_conf_path), kDebugParam,
                           flags_.net_log_level()});
  if (!jail_helper_.SetupJailAndRun(&net_cmd, Path::NET_ADS_SECCOMP,
                                    TIMER_NONE)) {
    // This is actually a local operation.
    LOG(ERROR) << "Failed to set fake domain SID";
    return ERROR_LOCAL_IO;
  }

  // Mark as set for this workgroup.
  fake_domain_sid_was_set_for_workgroup_.insert(account.workgroup);
  return ERROR_NONE;
}

void SambaInterface::InitDeviceAccount(const std::string& netbios_name,
                                       const std::string& realm) {
  device_account_.netbios_name = netbios_name;
  device_account_.user_name = device_account_.netbios_name + "$";
  device_account_.realm = realm;
  device_tgt_manager_.SetRealm(device_account_.realm);
  device_tgt_manager_.SetPrincipal(device_account_.GetPrincipal());
}

void SambaInterface::SetKerberosEncryptionTypes(
    KerberosEncryptionTypes encryption_types) {
  if (encryption_types_ != encryption_types) {
    LOG(INFO) << "Kerberos encryption types changed to "
              << GetEncryptionTypesString(encryption_types);
  }
  encryption_types_ = encryption_types;
  user_tgt_manager_.SetKerberosEncryptionTypes(encryption_types_);
  device_tgt_manager_.SetKerberosEncryptionTypes(encryption_types_);
}

void SambaInterface::MaybeBackupUserAuthState() {
  if (!user_logged_in_ || !in_user_session_ || user_daemon_store_path_.empty())
    return;
  DCHECK(!user_account_id_.empty());

  // Since we're in the session, Cryptohome should be mounted.
  DCHECK(base::PathExists(user_daemon_store_path_));

  // Back up TGT state.
  protos::UserBackupData data;
  if (!user_tgt_manager_.Backup(data.mutable_tgt_state()))
    return;

  // Put all other data we want to serialize into the proto.
  data.set_pwd_last_set(user_pwd_last_set_);
  data.set_user_name(user_account_.user_name);
  data.set_is_user_affiliated(is_user_affiliated_);
  data.set_user_realm(user_account_.realm);

  // Convert proto to string.
  std::string data_blob;
  if (!data.SerializeToString(&data_blob)) {
    LOG(WARNING) << "Backup failed to serialize backup data to string";
    return;
  }

  // Save string to disk.
  const int size = static_cast<int>(data_blob.size());
  const base::FilePath backup_path =
      user_daemon_store_path_.Append(kBackupFileName);
  if (base::WriteFile(backup_path, data_blob.data(), size) != size) {
    LOG(WARNING) << "Backup failed to write data to " << backup_path.value();
    return;
  }

  LOG(INFO) << "Backup successfully written to " << backup_path.value();
}

void SambaInterface::MaybeRestoreUserAuthState() {
  if (user_logged_in_ || !in_user_session_ || user_daemon_store_path_.empty())
    return;
  DCHECK(!user_account_id_.empty());

  // Exit quietly if the backup path doesn't exist (yet).
  const base::FilePath backup_path =
      user_daemon_store_path_.Append(kBackupFileName);
  if (!base::PathExists(backup_path))
    return;

  // Read string from disk.
  std::string data_blob;
  if (!base::ReadFileToStringWithMaxSize(backup_path, &data_blob,
                                         kMaxBackupSizeBytes)) {
    PLOG(ERROR) << "Backup failed to read data from " << backup_path.value();
    return;
  }

  // Convert string to proto.
  protos::UserBackupData data;
  if (!data.ParseFromString(data_blob)) {
    LOG(WARNING) << "Backup failed to parse backup data from string";
    return;
  }

  // Check proto.
  if (!data.has_tgt_state() || !data.has_pwd_last_set() ||
      !data.has_user_name() || data.user_name().empty() ||
      !data.has_is_user_affiliated()) {
    LOG(WARNING) << "Backup data is bad";
    return;
  }

  // Restore TGT state.
  if (!user_tgt_manager_.Restore(data.tgt_state()))
    return;

  // Restore all other data from the proto.
  user_pwd_last_set_ = data.pwd_last_set();
  user_account_.user_name = data.user_name();
  is_user_affiliated_ = data.is_user_affiliated();
  // User realm might be missing in old backup data. New data should have it.
  if (data.has_user_realm())
    SetUserRealm(data.user_realm());
  user_logged_in_ = true;

  LOG(INFO) << "Backup successfully restored from " << backup_path.value();
}

void SambaInterface::AnonymizeRealm(const std::string& realm,
                                    const char* placeholder) {
  anonymizer_->SetReplacementAllCases(realm, placeholder);

  std::vector<std::string> parts = base::SplitString(
      realm, ".", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  for (const auto& part : parts)
    anonymizer_->SetReplacementAllCases(part, placeholder);
}

bool SambaInterface::IsDeviceJoined() const {
  DCHECK(device_account_.realm.empty() ^ !device_account_.netbios_name.empty());
  return !device_account_.realm.empty() &&
         !device_account_.netbios_name.empty();
}

void SambaInterface::Reset() {
  user_account_id_.clear();
  user_pwd_last_set_ = 0;
  user_logged_in_ = false;
  is_user_affiliated_ = false;
  user_account_ = AccountData(Path::USER_SMB_CONF);
  device_account_ = AccountData(Path::DEVICE_SMB_CONF);
  user_tgt_manager_.Reset();
  device_tgt_manager_.Reset();
  gpo_version_cache_.Clear();
  gpo_version_cache_.SetEnabled(true);
  gpo_version_cache_ttl_ = kDefaultGpoVersionCacheTTL;
  auth_data_cache_.Clear();
  auth_data_cache_.SetEnabled(true);
  auth_data_cache_ttl_ = kDefaultAuthDataCacheTTL;
  SetKerberosEncryptionTypes(ENC_TYPES_STRONG);
  user_policy_mode_ =
      em::DeviceUserPolicyLoopbackProcessingModeProto::USER_POLICY_MODE_DEFAULT;
  password_change_timer_.Stop();
  password_change_rate_ = base::TimeDelta();
  has_device_policy_ = false;
  device_policy_impl_for_testing.reset();
  did_password_change_check_run_for_testing_ = false;
}

void SambaInterface::LoadFlagsDefaultLevel() {
  const base::FilePath default_level_path(
      paths_->Get(Path::FLAGS_DEFAULT_LEVEL));
  if (!CheckFlagsDefaultLevelValid(default_level_path))
    return;
  std::string level_str;
  if (!base::ReadFileToStringWithMaxSize(default_level_path, &level_str, 16)) {
    PLOG(ERROR) << "Failed to read flags default level from '"
                << default_level_path.value() << "'";
    return;
  }
  int level_int;
  if (!base::StringToInt(level_str, &level_int) ||
      level_int < AuthPolicyFlags::kMinLevel ||
      level_int > AuthPolicyFlags::kMaxLevel) {
    LOG(ERROR) << "Bad flags default level '" << level_str << "'";
    return;
  }
  flags_default_level_ = static_cast<AuthPolicyFlags::DefaultLevel>(level_int);
  LOG(INFO) << "Flags default level = " << flags_default_level_;
}

void SambaInterface::SaveFlagsDefaultLevel() {
  const base::FilePath default_level_path(
      paths_->Get(Path::FLAGS_DEFAULT_LEVEL));
  const std::string level_str = std::to_string(flags_default_level_);
  const int size = static_cast<int>(level_str.size());
  if (flags_default_level_ == AuthPolicyFlags::kQuiet) {
    // Remove the file, kQuiet is the default, anyway.
    if (!base::DeleteFile(default_level_path)) {
      PLOG(ERROR) << "Failed to delete flags default level file '"
                  << default_level_path.value() << "'";
    }
  } else {
    // Write the file.
    if (base::WriteFile(default_level_path, level_str.data(), size) != size) {
      PLOG(ERROR) << "Failed to write flags default level to '"
                  << default_level_path.value() << "'";
    }
  }
}

void SambaInterface::ReloadDebugFlags() {
  const base::FilePath default_level_path(
      paths_->Get(Path::FLAGS_DEFAULT_LEVEL));
  if (flags_default_level_ != AuthPolicyFlags::kQuiet &&
      !CheckFlagsDefaultLevelValid(default_level_path)) {
    // Default flags file expired, reset default level.
    flags_default_level_ = AuthPolicyFlags::kQuiet;
  }

  // First set defaults, then load file on top.
  AuthPolicyFlags flags_container;
  flags_container.SetDefaults(flags_default_level_);
  const base::FilePath path(paths_->Get(Path::DEBUG_FLAGS));
  if (flags_container.LoadFromJsonFile(path) ||
      flags_default_level_ != AuthPolicyFlags::kQuiet) {
    flags_container.Dump();
  }
  flags_ = flags_container.Get();
  if (disable_seccomp_for_testing_)
    flags_.set_disable_seccomp(true);

  // Toggle anonymizer.
  anonymizer_->set_disabled(flags_.disable_anonymizer());
}

}  // namespace authpolicy
