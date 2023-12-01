// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef AUTHPOLICY_TGT_MANAGER_H_
#define AUTHPOLICY_TGT_MANAGER_H_

#include <string>

#include <base/cancelable_callback.h>

#include "authpolicy/path_service.h"
#include "authpolicy/proto_bindings/active_directory_info.pb.h"

namespace authpolicy {

namespace protos {
class DebugFlags;
class TgtLifetime;
class TgtState;
}  // namespace protos

class Anonymizer;
class AuthPolicyMetrics;
class JailHelper;
class PathService;
class ProcessExecutor;

// Responsible for acquiring a ticket-tranting-ticket (TGT) from an Active
// Directory key distribution center (KDC) and managing the TGT. The TGT is
// kept in a file, the credentials cache. Supports authentication via a password
// or a keytab file.
class TgtManager {
 public:
  class Delegate {
   public:
    virtual ~Delegate() = default;

    // Called when the Kerberos ticket has been auto-renewed.
    virtual void OnTgtRenewed() = 0;
  };

  TgtManager(const PathService* path_service,
             AuthPolicyMetrics* metrics,
             const protos::DebugFlags* flags,
             const JailHelper* jail_helper,
             Anonymizer* anonymizer,
             Delegate* delegate,
             Path config_path,
             Path credential_cache_path);
  TgtManager(const TgtManager&) = delete;
  TgtManager& operator=(const TgtManager&) = delete;

  ~TgtManager();

  // Sets the principal (user@REALM or machine$@REALM).
  void SetPrincipal(const std::string& principal);

  // Sets the Active Directory realm (e.g. ENG.EXAMPLE.COM).
  void SetRealm(const std::string& realm) { realm_ = realm; }

  // Sets the key distribution center IP.
  void SetKdcIp(const std::string& kdc_ip) { kdc_ip_ = kdc_ip; }

  // If an account has just been created, it might not have propagated through
  // Active Directory yet, so attempts to acquire a TGT might fail. Enabling
  // propagation retry causes kinit to be retried a few times if an error occurs
  // that indicates a propagation issue. Disables itself after kinit has run.
  void SetPropagationRetry(bool enabled) { kinit_retry_ = enabled; }

  // Sets the encryption types to use for kinit.
  void SetKerberosEncryptionTypes(KerberosEncryptionTypes encryption_types) {
    encryption_types_ = encryption_types;
  }

  // Resets the principal, the realm, the KDC IP, propagation retry and
  // encryption types.
  void Reset();

  // Acquires a TGT using the password given in the file descriptor
  // |password_fd|. See AcquireTgt() for details.
  [[nodiscard]] ErrorType AcquireTgtWithPassword(int password_fd);

  // Acquires a TGT using the keytab file at |keytab_path|. See AcquireTgt() for
  // details.
  [[nodiscard]] ErrorType AcquireTgtWithKeytab(Path keytab_path);

  // Returns the Kerberos credentials cache and the configuration file. Returns
  // ERROR_NONE if the credentials cache is missing and ERROR_LOCAL_IO if any of
  // the files failed to read.
  [[nodiscard]] ErrorType GetKerberosFiles(KerberosFiles* files);

  // Sets a callback that gets called when either the Kerberos credential cache
  // or the configuration file changes on disk. Use in combination with
  // GetKerberosFiles() to get the latest files.
  void SetKerberosFilesChangedCallback(const base::RepeatingClosure& callback);

  // If enabled, the TGT renews automatically by scheduling RenewTgt()
  // periodically on the |task_runner_| (usually the D-Bus thread). Renewal must
  // happen within the the TGT's validity lifetime. The scheduling delay is a
  // fraction of that lifetime.
  void EnableTgtAutoRenewal(bool enabled);

  // Renews a TGT. Must happen within its validity lifetime.
  [[nodiscard]] ErrorType RenewTgt();

  // Returns the lifetime of a TGT.
  [[nodiscard]] ErrorType GetTgtLifetime(protos::TgtLifetime* lifetime);

  // Use kpasswd to change the password for the current principal.
  [[nodiscard]] ErrorType ChangePassword(const std::string& old_password,
                                         const std::string& new_password);

  // Returns the file path of the Kerberos configuration file.
  Path GetConfigPath() const { return config_path_; }

  // Returns the file path of the Kerberos credential cache.
  Path GetCredentialCachePath() const { return credential_cache_path_; }

  // Saves internal state to the given |state| blob. Fails if the TGT does not
  // exist or cannot be read.
  bool Backup(protos::TgtState* state);

  // Restores internal state from the given |state| blob.
  bool Restore(const protos::TgtState& state);

  // Disable retry sleep for unit tests.
  void DisableRetrySleepForTesting() {
    kinit_retry_sleep_disabled_for_testing_ = true;
  }

  // Returns whether TGT auto renewal is active, see EnableTgtAutoRenewal().
  bool IsTgtAutoRenewalEnabledForTesting() { return tgt_autorenewal_enabled_; }

 private:
  // Acquires a TGT for the current principal. If |password_fd| is not -1, uses
  // the password in that file descriptor for authentication. If |keytab_path|
  // is not Path::INVALID, uses the keytab for authentication. Should always
  // pass one or the other. Must set principal, KDC IP and realm beforehand.
  [[nodiscard]] ErrorType AcquireTgt(int password_fd, Path keytab_path);

  // Writes the Kerberos configuration and runs |kinit_cmd|. If |password_fd| is
  // not -1, the file descriptor is duplicated and set as input pipe.
  [[nodiscard]] ErrorType RunKinit(ProcessExecutor* kinit_cmd,
                                   int password_fd) const;

  // Writes the krb5 configuration file.
  [[nodiscard]] ErrorType WriteKrb5Conf() const;

  // Turns on krb5 trace logging if |flags_->TraceKrb5()| is enabled.
  void SetupKrb5Trace(ProcessExecutor* krb5_cmd) const;

  // Logs the krb5 trace if |flags_->TraceKrb5()| is enabled.
  void OutputKrb5Trace() const;

  // Cancels |tgt_renewal_callback_|. If |tgt_autorenewal_enabled_| is true and
  // the TGT is valid, schedules RenewTgt() with a delay of a fraction of the
  // TGT's validity lifetime.
  void UpdateTgtAutoRenewal();

  // Callback scheduled to renew the TGT. Calls RenewTgt() internally and prints
  // appropriate error messages.
  void AutoRenewTgt();

  // Runs |kerberos_files_changed_| if |kerberos_files_dirty_| is set.
  void MaybeTriggerKerberosFilesChanged();

  const PathService* const paths_ = nullptr;    // File paths, not owned.
  AuthPolicyMetrics* const metrics_ = nullptr;  // UMA statistics, not owned.
  const protos::DebugFlags* const flags_ = nullptr;  // Debug flags, not owned.
  const JailHelper* const jail_helper_ = nullptr;    // Minijail, not owned.
  Anonymizer* const anonymizer_ = nullptr;  // Log anonymizer, not owned.
  Delegate* delegate_ = nullptr;  // Delegate to receive events, not owned.
  const Path config_path_ = Path::INVALID;
  const Path credential_cache_path_ = Path::INVALID;
  base::RepeatingClosure kerberos_files_changed_;

  // Principal for which TGTs are acquired (user@REALM or machine$@REALM).
  std::string principal_;

  // Realm written to the Kerberos config.
  std::string realm_;

  // Key distribution center (KDC) IP address written to the Kerberos config. If
  // fetching a TGT with prescribed KDC IP fails with an error code that
  // indicates that the KDC could not be reached, |kdc_ip_| gets wiped and kinit
  // is retried, which lets Samba query the KDC IP.
  std::string kdc_ip_;

  // Whether the TGT was acquired for a user or machine principal. Determines
  // what error code is returned if the principal was bad.
  bool is_machine_principal_ = false;

  // Callback for automatic TGT renewal.
  base::CancelableOnceClosure tgt_renewal_callback_;
  bool tgt_autorenewal_enabled_ = false;

  // Whether to retry kinit in case an error indicates that the credentials
  // haven't propagated yet.
  bool kinit_retry_ = false;

  // Disables sleeping when retrying kinit (to prevent slowdowns in tests).
  bool kinit_retry_sleep_disabled_for_testing_ = false;

  // Encryption types to use for kinit.
  KerberosEncryptionTypes encryption_types_ = ENC_TYPES_STRONG;

  // If true, the Kerberos files changed and |kerberos_files_changed_| needs to
  // be called if it exists. Prevents that signals are fired too often, e.g. if
  // both krb5cc and config change in the same call.
  mutable bool kerberos_files_dirty_ = false;
};

}  // namespace authpolicy

#endif  // AUTHPOLICY_TGT_MANAGER_H_
