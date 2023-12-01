// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef AUTHPOLICY_SAMBA_INTERFACE_H_
#define AUTHPOLICY_SAMBA_INTERFACE_H_

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/memory/ref_counted.h>
#include <base/timer/timer.h>
#include <dbus/authpolicy/dbus-constants.h>

#include "authpolicy/auth_data_cache.h"
#include "authpolicy/authpolicy_flags.h"
#include "authpolicy/authpolicy_metrics.h"
#include "authpolicy/constants.h"
#include "authpolicy/gpo_version_cache.h"
#include "authpolicy/jail_helper.h"
#include "authpolicy/path_service.h"
#include "authpolicy/proto_bindings/active_directory_info.pb.h"
#include "authpolicy/samba_helper.h"
#include "authpolicy/tgt_manager.h"
#include "bindings/authpolicy_containers.pb.h"
#include "bindings/chrome_device_policy.pb.h"

// Helper methods for Samba Active Directory authentication, machine (device)
// joining and policy fetching. Note: "Device" and "machine" can be used
// interchangably here.

namespace enterprise_management {
class ChromeDeviceSettingsProto;
}

namespace policy {
class DevicePolicyImpl;
}

namespace authpolicy {

class Anonymizer;
class AuthPolicyMetrics;
class CryptohomeClient;
class PathService;
class ProcessExecutor;

class SambaInterface : public TgtManager::Delegate {
 public:
  SambaInterface(AuthPolicyMetrics* metrics,
                 const PathService* path_service,
                 const base::RepeatingClosure& user_kerberos_files_changed);
  SambaInterface(const SambaInterface&) = delete;
  SambaInterface& operator=(const SambaInterface&) = delete;

  ~SambaInterface();

  // Creates directories required by Samba code. If |expect_config| is true,
  // loads configuration and device policy and initializes dependent stuff like
  // |encryption_types_|.
  // Returns an error
  // - if a directory failed to create or
  // - if |expect_config| is true and the config file fails to load.
  [[nodiscard]] ErrorType Initialize(bool expect_config);

  // Sets the interface to Cryptohome.
  void SetCryptohomeClient(std::unique_ptr<CryptohomeClient> cryptohome_client);

  // Gets the cryptohome client for testing.
  CryptohomeClient* get_cryptohome_client_for_testing() {
    return cryptohome_client_.get();
  }

  // Cleans all persistent state files. Returns true if all files were cleared.
  static bool CleanState(const PathService* path_service);

  // Calls kinit to get a Kerberos ticket-granting-ticket (TGT) for the given
  // |user_principal_name| (format: user_name@workgroup.domain). If a TGT
  // already exists, it is renewed. The password must be readable from the pipe
  // referenced by the file descriptor |password_fd|. On success, the user's
  // account information is returned in |account_info|. If |account_id| is
  // non-empty, the |account_info| is queried by |account_id| instead of by
  // user name. This is safer since the account id is invariant, whereas the
  // user name can change. The updated user name (or rather the sAMAccountName)
  // is returned in the |account_info|. Thus, |account_id| should be set if
  // known and left empty if unknown.
  [[nodiscard]] ErrorType AuthenticateUser(
      const std::string& user_principal_name,
      const std::string& account_id,
      int password_fd,
      ActiveDirectoryAccountInfo* account_info);

  // Figures out whether the user is affiliated or not. If affiliated, caches
  // auth data and saves the auth data cache to disk. Must be called after a
  // successful AuthenticateUser() call. It is separate from that method in
  // order to allow asynchronous execution.
  void UpdateUserAffiliation();

  // Retrieves the status of the user account given by |account_id| (aka
  // objectGUID). |user_principal_name| is used to derive the user's realm.
  // The returned |user_status| contains general ActiveDirectoryAccountInfo as
  // well as the status of the user's ticket-granting-ticket (TGT). Does not
  // fill |user_status| on error.
  [[nodiscard]] ErrorType GetUserStatus(const std::string& user_principal_name,
                                        const std::string& account_id,
                                        ActiveDirectoryUserStatus* user_status);

  // Gets the user Kerberos credential cache (krb5cc) and configuration
  // (krb5.conf) files if they exist. Does not set |files| on error.
  [[nodiscard]] ErrorType GetUserKerberosFiles(const std::string& account_id,
                                               KerberosFiles* files);

  // Joins the local device with name |machine_name| to an Active Directory
  // domain. The credentials for joining (usually admin level) are given by
  // |user_principal_name| and |password_fd|, see AuthenticateUser() for
  // details. |machine_domain| is the domain where the machine is joined to. If
  // empty, it is derived from |user_principal_name|. |machine_ou| is a vector
  // of organizational units where the machine is placed into, ordered
  // leaf-to-root. If empty, the machine is placed in the default location (e.g.
  // Computers OU). |encryption_types| specifies the allowed encryption types
  // for Kerberos authentication. On success, |joined_domain| is set to the
  // domain that was joined (may be nullptr).
  [[nodiscard]] ErrorType JoinMachine(
      const std::string& machine_name,
      const std::string& machine_domain,
      const std::vector<std::string>& machine_ou,
      const std::string& user_principal_name,
      KerberosEncryptionTypes encryption_types,
      int password_fd,
      std::string* joined_domain);

  // Downloads user and extension policy from the Active Directory server and
  // stores it in |gpo_policy_data|. |account_id| is the unique user objectGUID
  // returned from |AuthenticateUser| in |account_info|. The user's Kerberos
  // authentication ticket must still be valid. If this operation fails, call
  // |AuthenticateUser| and try again.
  [[nodiscard]] ErrorType FetchUserGpos(const std::string& account_id,
                                        protos::GpoPolicyData* gpo_policy_data);

  // Downloads device and extension policy from the Active Directory server and
  // stores it in |gpo_policy_data|. The device must be joined to the Active
  // Directory domain already (see JoinMachine()) as policy fetch requires
  // authentication with the machine account generated during domain join.
  [[nodiscard]] ErrorType FetchDeviceGpos(
      protos::GpoPolicyData* gpo_policy_data);

  // Should be called when the user session state changed (e.g. "started",
  // "stopped"). User auth state can only be backed up when the session is in
  // "started" state.
  void OnSessionStateChanged(const std::string& state);

  // Sets the default log level, see AuthPolicyFlags::DefaultLevel for details.
  // The level persists between restarts of authpolicyd, but gets reset on
  // reboot.
  void SetDefaultLogLevel(AuthPolicyFlags::DefaultLevel level);

  // Returns the user's principal name (sAMAccountName @ realm).
  std::string GetUserPrincipal() const;

  const std::string& user_account_id() const { return user_account_id_; }

  // Returns true if the current user's domain is trusted by the machine domain.
  // Must be logged in.
  bool is_user_affiliated() const {
    DCHECK(user_logged_in_);
    return is_user_affiliated_;
  }

  const std::string& machine_name() const {
    return device_account_.netbios_name;
  }

  // TgtManager::Delegate:
  void OnTgtRenewed() override;

  // Disables sleep between kinit tries for unit tests.
  void DisableRetrySleepForTesting();

  // Disables seccomp filtering for unit tests as they might make different
  // syscalls than production code.
  void DisableSeccompForTesting(bool disabled) {
    disable_seccomp_for_testing_ = disabled;
  }

  // Returns the anonymizer.
  const Anonymizer* GetAnonymizerForTesting() const {
    return anonymizer_.get();
  }

  // Returns the cache for the GPO version.
  GpoVersionCache* GetGpoVersionCacheForTesting() {
    return &gpo_version_cache_;
  }

  // Returns the lifetime of cached GPos.
  base::TimeDelta GetGpoVersionCacheTTLForTesting() const {
    return gpo_version_cache_ttl_;
  }

  // Returns the cache for the GPO version.
  AuthDataCache* GetAuthDataCacheForTesting() { return &auth_data_cache_; }

  // Returns the lifetime of cached auth data.
  base::TimeDelta GetAuthDataCacheTTLForTesting() const {
    return auth_data_cache_ttl_;
  }

  // Renew the user ticket-granting-ticket.
  [[nodiscard]] ErrorType RenewUserTgtForTesting();

  // Returns the ticket-granting-ticket manager for the user account.
  TgtManager& GetUserTgtManagerForTesting() { return user_tgt_manager_; }

  // Sets the container used to load device policy during Initialize(). Can be
  // used to load device policy from a different location and without key check.
  void SetDevicePolicyImplForTesting(
      std::unique_ptr<policy::DevicePolicyImpl> policy_impl);

  // Sets the actual device policy. Only a few policies are taken into account,
  // see UpdateDevicePolicyDependencies().
  void SetUserPolicyModeForTesting(
      enterprise_management::DeviceUserPolicyLoopbackProcessingModeProto::Mode
          mode) {
    user_policy_mode_ = mode;
  }

  // Returns true if AutoCheckMachinePasswordChange() was called at least once.
  bool DidPasswordChangeCheckRunForTesting() const {
    return did_password_change_check_run_for_testing_;
  }

  // Resets internal state (useful for doing multiple domain joins).
  void ResetForTesting();

  // Runs kpasswd to change machine password.
  [[nodiscard]] ErrorType ChangeMachinePasswordForTesting();

 private:
  // User or device specific information. The user might be logging on to a
  // different realm than the machine was joined to.
  struct AccountData {
    std::string realm;         // Active Directory realm.
    std::string workgroup;     // Active Directory workgroup name.
    std::string netbios_name;  // Netbios name is empty for user.
    std::string kdc_ip;        // IPv4/IPv6 address of key distribution center.
    std::string dc_name;       // DNS name of the domain controller
    std::string user_name;     // User sAMAccountName or device netbios_name+$.
    base::Time server_time;    // The server time at last query.
    Path smb_conf_path;        // Path of the Samba configuration file.

    // Note: Initialize server_time to Now(). This prevents an unnecessary net
    // ads info call in UpdateKdcIpAndServerTime() during user auth when the KDC
    // IP is cached.
    explicit AccountData(Path _smb_conf_path)
        : server_time(base::Time::Now()), smb_conf_path(_smb_conf_path) {}

    // Returns user_name @ realm.
    std::string GetPrincipal() const { return user_name + "@" + realm; }
  };

  // Actual implementation of AuthenticateUser() (see above). The method is
  // wrapped in order to catch and memorize the returned error.
  [[nodiscard]] ErrorType AuthenticateUserInternal(
      const std::string& user_principal_name,
      const std::string& account_id,
      int password_fd,
      ActiveDirectoryAccountInfo* account_info);

  // Gets the status of the user's ticket-granting-ticket (TGT). Uses klist
  // internally to check whether the ticket is valid, expired or not present.
  // Does not perform any server-side checks.
  [[nodiscard]] ErrorType GetUserTgtStatus(
      ActiveDirectoryUserStatus::TgtStatus* tgt_status);

  // Determines the password status by comparing the old |user_pwd_last_set_|
  // timestamp to the new timestamp in |account_info|.
  ActiveDirectoryUserStatus::PasswordStatus GetUserPasswordStatus(
      const ActiveDirectoryAccountInfo& account_info);

  // Writes the Samba configuration file using the given |account|.
  [[nodiscard]] ErrorType WriteSmbConf(const AccountData& account) const;

  // Queries the name of the workgroup for the given |account| and stores it in
  // |account|->workgroup.
  [[nodiscard]] ErrorType UpdateWorkgroup(AccountData* account) const;

  // Queries the IP of the key distribution center (KDC) and server time for the
  // given |account| and stores them in |account|->kdc_ip and
  // |account|->server_time, respectively. The KDC address is required to speed
  // up network communication and to get rid of waiting for the machine account
  // propagation after Active Directory domain join. The server time is required
  // to keep track of the machine password age.
  [[nodiscard]] ErrorType UpdateKdcIpAndServerTime(AccountData* account) const;

  // Queries the DNS domain name of the domain controller (DC) for the given
  // |account| and stores it in |account|->dc_name. The DC name is required as
  // host name in smbclient. With an IP address only, Samba wouldn't be able to
  // use the Kerberos ticket.
  [[nodiscard]] ErrorType UpdateDcName(AccountData* account) const;

  // Writes the Samba configuration file for the given |account| and updates
  // the account's |kdc_ip|, |server_time|, |dc_name| and |workgroup|. Does not
  // refresh the values if they are already set.
  [[nodiscard]] ErrorType UpdateAccountData(AccountData* account);

  // Checks whether the ADS server for |account| is available. Currently
  // implemented by calling net ads workgroup.
  [[nodiscard]] ErrorType PingServer(AccountData* account);

  // Returns true if the current user is affiliated with the machine domain in
  // the sense that the machine domain trusts the user domain. Returns false
  // otherwise and on error. Currently implemented by calling net ads search for
  // the machine account using the user's Kerberos ticket. The search command is
  // sent to the device's server.
  [[nodiscard]] bool IsUserAffiliated();

  // Acquire a Kerberos ticket-granting-ticket for the user account.
  // |password_fd| is a file descriptor containing the user's password.
  [[nodiscard]] ErrorType AcquireUserTgt(int password_fd);

  // Acquire a Kerberos ticket-granting-ticket for the device account. Uses the
  // machine password file for authentication (or the keytab for backwards
  // compatibility). If the current machine password doesn't work, uses the
  // previous password (e.g. password change didn't propagate through AD yet).
  [[nodiscard]] ErrorType AcquireDeviceTgt();

  // Writes the machine password to the path specified by |path|.
  [[nodiscard]] ErrorType WriteMachinePassword(
      Path path, const std::string& machine_pass) const;

  // Rolls NEW_MACHINE_PASS -> MACHINE_PASS -> PREV_MACHINE_PASS. Used during
  // machine password change.
  [[nodiscard]] ErrorType RollMachinePassword();

  // Writes the file with configuration information.
  [[nodiscard]] ErrorType WriteConfiguration() const;

  // Reads the file with configuration information.
  [[nodiscard]] ErrorType ReadConfiguration();

  // Gets user account info. If |account_id| is not empty, searches by
  // objectGUID = |account_id| only. Otherwise, searches by sAMAccountName =
  // |user_name| and - if that fails - by userPrincipalName = |normalized_upn|.
  // Note that sAMAccountName can be different from the name-part of the
  // userPrincipalName and that kinit/Windows prefer sAMAccountName over
  // userPrincipalName. Assumes that the account is up-to-date and the user's
  // TGT is valid.
  [[nodiscard]] ErrorType GetAccountInfo(
      const std::string& user_name,
      const std::string& normalized_upn,
      const std::string& account_id,
      ActiveDirectoryAccountInfo* account_info);

  // Calls net ads search with given |search_string| to retrieve |account_info|.
  // Authenticates with the device TGT.
  [[nodiscard]] ErrorType SearchAccountInfo(
      const std::string& search_string,
      ActiveDirectoryAccountInfo* account_info);

  // Downloads GPOs and returns the |gpo_file_paths|. |source| determines
  // whether to get GPOs that apply to the user or the device. |scope|
  // determines whether user or device policy is to be loaded from the GPOs.
  // Note that some use cases like user policy loopback processing require
  // reading user policy from device GPOs. Calls GetGpoList() and DownloadGpos()
  // internally.
  [[nodiscard]] ErrorType GetGpos(GpoSource source,
                                  PolicyScope scope,
                                  std::vector<base::FilePath>* gpo_file_paths);

  // Calls net ads gpo list to retrieve a list of GPOs in |gpo_list|. See
  // GetGpos() for an explanation of |source| and |scope|.
  [[nodiscard]] ErrorType GetGpoList(GpoSource source,
                                     PolicyScope scope,
                                     protos::GpoList* gpo_list);

  // Downloads user or device GPOs in the given |gpo_list|. See GetGpos() for an
  // explanation of |source| and |scope|. Returns the downloaded GPO file paths
  // in |gpo_file_paths|.
  [[nodiscard]] ErrorType DownloadGpos(
      const protos::GpoList& gpo_list,
      GpoSource source,
      PolicyScope scope,
      std::vector<base::FilePath>* gpo_file_paths);

  // Parses GPOs and stores them in user/device policy protobufs.
  [[nodiscard]] ErrorType ParseGposIntoProtobuf(
      const std::vector<base::FilePath>& gpo_file_paths,
      const char* parser_cmd_string,
      std::string* policy_blob) const;

  // Update stuff that depends on device policy like |encryption_types_|. Should
  // be called whenever new device policy is available.
  void UpdateDevicePolicyDependencies(
      const enterprise_management::ChromeDeviceSettingsProto& device_policy);

  // Updates |auth_data_cache_| with data from |account| and |is_affiliated| and
  // saves to disk.
  void UpdateAuthDataCache(const AccountData& account, bool is_affiliated);

  // Sets the |rate| at which the machine password is changed. Turns off
  // automatic password change if |rate| is non-positive. Turned off by default.
  // Prints out a warning on devices that are still using the machine keytab.
  // Repeatedly schedules AutoCheckMachinePasswordChange() every few hours.
  void UpdateMachinePasswordAutoChange(const base::TimeDelta& rate);

  // Calls CheckMachinePasswordChange() and logs errors.
  void AutoCheckMachinePasswordChange();

  // Checks whether the age of the password exceeds |password_change_rate_| and
  // renews the password if it does.
  [[nodiscard]] ErrorType CheckMachinePasswordChange();

  // Get user or device AccountData. Depends on GpoSource, not on PolicyScope,
  // since that determines what account to download GPOs for.
  const AccountData& GetAccount(GpoSource source) const {
    return source == GpoSource::USER ? user_account_ : device_account_;
  }

  // Get user or device TGT manager. Depends on GpoSource, not on PolicyScope,
  // since that determines what account to download GPOs for and the TGT is tied
  // to the account.
  const TgtManager& GetTgtManager(GpoSource source) const {
    return source == GpoSource::USER ? user_tgt_manager_ : device_tgt_manager_;
  }

  // Sets and fixes the current user by account id. Only one account id is
  // allowed per user. Calling this multiple times with different account ids
  // crashes the daemon.
  void SetUserAccountId(const std::string& account_id);

  // Similar to SetUser, but sets user_account_.realm.
  void SetUserRealm(const std::string& user_realm);

  // Calls net setdomainsid S-1-5-21-0000000000-0000000000-00000000 if it was
  // not set for the account workgroup yet. This is a workaround for
  // Samba 4.8.6+, which expects a domain SID to exist in add_builtin_guests()
  // (Samba code). Without a SID 'net ads gpo list' fails with "Failed to check
  // for local Guests membership (NT_STATUS_INVALID_PARAMETER_MIX)". The SID is
  // stored in Samba's, secrets.tdb as a key/value store with key as a
  // workgroup, which authpolicyd places in /tmp/authpolicyd/samba/private, so
  // it is wiped whenever the daemon is restarted and the SID is lost. However,
  // the SID is not really needed for our purposes, so we set a fake SID here.
  [[nodiscard]] ErrorType MaybeSetFakeDomainSid(const AccountData& account);

  // Sets machine name and realm on the device account and the tgt manager.
  void InitDeviceAccount(const std::string& netbios_name,
                         const std::string& realm);

  // Sets encryption types used by Kerberos tickets.
  void SetKerberosEncryptionTypes(KerberosEncryptionTypes encryption_types);

  // Backs up user authentication state (including the credentials cache) on the
  // user's Cryptohome if the user is logged in (i.e. AuthenticateUser()
  // succeeded).
  void MaybeBackupUserAuthState();

  // Restores user authentication state (including the credentials cache) from
  // the user's Cryptohome if the backup data exists and the user isn't logged
  // in yet. The restored state is equivalent to the state if AuthenticateUser()
  // succeeds.
  void MaybeRestoreUserAuthState();

  // Anonymizes |realm| in different capitalizations as well as all parts. For
  // instance, if realm is SOME.EXAMPLE.COM, anonymizes SOME, EXAMPLE and COM.
  void AnonymizeRealm(const std::string& realm, const char* placeholder);

  // Returns true if the device is not in a 'joined' state.
  bool IsDeviceJoined() const;

  // Resets internal state to an 'unenrolled' state by wiping configuration and
  // user data.
  void Reset();

  // Loads |flags_default_level_| from Path::FLAGS_DEFAULT_LEVEL. Logs an
  // error if the file exists, but the level cannot be loaded. Fails silently if
  // the file does not exist.
  void LoadFlagsDefaultLevel();

  // Saves |flags_default_level_| to Path::FLAGS_DEFAULT_LEVEL. Logs on error.
  void SaveFlagsDefaultLevel();

  // Reloads debug flags. Should be done on every public method called from
  // D-Bus, so that authpolicyd doesn't have to be restarted if the flags
  // change. Note that this is cheap in a production environment where the flags
  // file does not exist, so this is no performance concern.
  void ReloadDebugFlags();

  // User account_id (aka objectGUID).
  std::string user_account_id_;
  // Timestamp of last password change on server.
  uint64_t user_pwd_last_set_ = 0;
  // Whether AuthenticateUser() succeeded or the equivalent auth state could be
  // restored from a backup.
  bool user_logged_in_ = false;
  // Is the user affiliated with the machine's domain?
  bool is_user_affiliated_ = false;
  // Last AuthenticateUser() error.
  ErrorType last_auth_error_ = ERROR_NONE;
  // Path for user data backup, e.g. /run/daemon-store/authpolicyd/<user_hash>.
  // Note that this is essentially bound to /home/root/<user_hash>/authpolicyd.
  base::FilePath user_daemon_store_path_;
  // Whether the user session has been started, so Cryptohome is available.
  bool in_user_session_ = false;

  AccountData user_account_;
  AccountData device_account_;

  // The order of members is carefully chosen to match initialization order, so
  // don't mess with it unless you have a reason.

  // UMA statistics, not owned.
  AuthPolicyMetrics* metrics_;

  // Lookup for file paths, not owned.
  const PathService* paths_;

  // D-Bus interface to Cryptohome.
  std::unique_ptr<CryptohomeClient> cryptohome_client_;

  // Removes sensitive data from logs.
  std::unique_ptr<Anonymizer> anonymizer_;

  // Debug flags, loaded from Path::DEBUG_FLAGS.
  protos::DebugFlags flags_;
  AuthPolicyFlags::DefaultLevel flags_default_level_ = AuthPolicyFlags::kQuiet;

  // Helper to setup and run minijailed processes.
  JailHelper jail_helper_;

  // User and device ticket-granting-ticket managers.
  TgtManager user_tgt_manager_;
  TgtManager device_tgt_manager_;

  // Cache for GPO version, used to prevent unnecessary downloads.
  GpoVersionCache gpo_version_cache_;
  base::TimeDelta gpo_version_cache_ttl_;

  // File-based cache for authentication data. The cache persists across
  // restarts of authpolicyd (but not reboots), so that it can speed up logins
  // for different users and ephemeral mode.
  AuthDataCache auth_data_cache_;
  base::TimeDelta auth_data_cache_ttl_;

  // Encryption types to use for kinit and Samba commands. Don't set directly,
  // always set through SetKerberosEncryptionTypes(). Updated by
  // UpdateDevicePolicyDependencies.
  KerberosEncryptionTypes encryption_types_ = ENC_TYPES_STRONG;

  // Loopback processing mode (how/if user policy from machine GPOs is used).
  // Updated by UpdateDevicePolicyDependencies.
  enterprise_management::DeviceUserPolicyLoopbackProcessingModeProto::Mode
      user_policy_mode_ = enterprise_management::
          DeviceUserPolicyLoopbackProcessingModeProto::USER_POLICY_MODE_DEFAULT;

  // Timer for automatic machine password change. Updated by
  // UpdateDevicePolicyDependencies.
  base::TimeDelta password_change_rate_;

  // Timer for repeated password age checks. Calls
  // AutoCheckMachinePasswordChange().
  base::RepeatingTimer password_change_timer_;

  // Whether device policy has been fetched or loaded from disk on startup.
  bool has_device_policy_ = false;

  // Whether a fake domain SID was set for a given workgroup to work around
  // Samba issue.
  std::set<std::string> fake_domain_sid_was_set_for_workgroup_;

  // For testing only. Used/consumed during Initialize().
  std::unique_ptr<policy::DevicePolicyImpl> device_policy_impl_for_testing;

  // Disables sleeping when retrying net or smbclient (to prevent slowdowns in
  // tests).
  bool retry_sleep_disabled_for_testing_ = false;

  // Keeps track of whether AutoCheckMachinePasswordChange() ran or not.
  bool did_password_change_check_run_for_testing_ = false;

  // Disables seccomp filtering for unit tests.
  bool disable_seccomp_for_testing_ = false;
};

}  // namespace authpolicy

#endif  // AUTHPOLICY_SAMBA_INTERFACE_H_
