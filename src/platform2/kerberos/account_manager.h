// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef KERBEROS_ACCOUNT_MANAGER_H_
#define KERBEROS_ACCOUNT_MANAGER_H_

#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

#include <base/files/file_path.h>
#include <base/functional/callback.h>

#include "bindings/kerberos_containers.pb.h"
#include "kerberos/config_parser.h"
#include "kerberos/krb5_interface.h"
#include "kerberos/proto_bindings/kerberos_service.pb.h"
#include "kerberos/tgt_renewal_scheduler.h"

namespace password_provider {
class PasswordProviderInterface;
}

namespace kerberos {

class KerberosMetrics;

// Manages Kerberos tickets for a set of accounts keyed by principal name
// (user@REALM.COM).
class AccountManager : public TgtRenewalScheduler::Delegate {
 public:
  using KerberosFilesChangedCallback =
      base::RepeatingCallback<void(const std::string& principal_name)>;
  using KerberosTicketExpiringCallback =
      base::RepeatingCallback<void(const std::string& principal_name)>;

  // |storage_dir| is the path where configs and credential caches are stored.
  // |kerberos_files_changed| is a callback that gets called when either the
  // Kerberos credential cache or the configuration file changes for a specific
  // account. Use in combination with GetKerberosFiles() to get the latest
  // files. |kerberos_ticket_expiring| is a callback that gets called when a
  // Kerberos TGT is about to expire. It should be used to notify the user.
  // |krb5| interacts with lower level Kerberos libraries. It can be overridden
  // for tests. |password_provider| is used to retrieve the login password. It
  // can be overridden for tests.
  AccountManager(base::FilePath storage_dir,
                 KerberosFilesChangedCallback kerberos_files_changed,
                 KerberosTicketExpiringCallback kerberos_ticket_expiring,
                 std::unique_ptr<Krb5Interface> krb5,
                 std::unique_ptr<password_provider::PasswordProviderInterface>
                     password_provider,
                 KerberosMetrics* metrics);
  AccountManager(const AccountManager&) = delete;
  AccountManager& operator=(const AccountManager&) = delete;

  ~AccountManager() override;

  // Saves all accounts to disk. Returns ERROR_LOCAL_IO and logs on error.
  ErrorType SaveAccounts() const;

  // Loads all accounts from disk. Returns ERROR_LOCAL_IO and logs on error.
  // Removes all old accounts before setting the new ones. Treats a non-existent
  // file on disk as if the file was empty, i.e. loading succeeds and the
  // account list is empty afterwards.
  ErrorType LoadAccounts();

  // Adds an account keyed by |principal_name| (user@REALM.COM) to the list of
  // accounts. |is_managed| indicates whether the account is managed by the
  // KerberosAccounts policy. Returns |ERROR_DUPLICATE_PRINCIPAL_NAME| if the
  // account is already present.
  [[nodiscard]] ErrorType AddAccount(const std::string& principal_name,
                                     bool is_managed);

  // The following methods return |ERROR_UNKNOWN_PRINCIPAL_NAME| if
  // |principal_name| (user@REALM.COM) is not known.

  // Removes the account keyed by |principal_name| from the list of accounts.
  [[nodiscard]] ErrorType RemoveAccount(const std::string& principal_name);

  // Removes account data or full accounts, depending on |mode|. Accounts in
  // |keep_list| are not touched.
  [[nodiscard]] ErrorType ClearAccounts(
      ClearMode mode, std::unordered_set<std::string> keep_list);

  // Returns a list of all existing accounts, including current status like
  // remaining Kerberos ticket lifetime. Does a best effort returning results.
  // See documentation of |Account| for more details.
  std::vector<Account> ListAccounts() const;

  // Sets the Kerberos configuration (krb5.conf) used for the given
  // |principal_name|. Validates the config before setting it.
  [[nodiscard]] ErrorType SetConfig(const std::string& principal_name,
                                    const std::string& krb5conf) const;

  // Validates the Kerberos configuration data |krb5conf|. If the config has
  // syntax errors or uses non-allowlisted options, returns ERROR_BAD_CONFIG
  // and fills |error_info| with error information.
  [[nodiscard]] ErrorType ValidateConfig(const std::string& krb5conf,
                                         ConfigErrorInfo* error_info) const;

  // Acquires a Kerberos ticket-granting-ticket for the account keyed by
  // |principal_name| using |password|. If |password| is empty, a stored
  // password is used if available. If |remember_password| is true and
  // |password| is not empty, the password is stored on disk. If
  // |use_login_password| is true, the primary user's login password is used to
  // authenticate. Both |password| and |remember_password| are ignored by the
  // daemon in this case.
  [[nodiscard]] ErrorType AcquireTgt(const std::string& principal_name,
                                     std::string password,
                                     bool remember_password,
                                     bool use_login_password);

  // Retrieves the Kerberos credential cache and the configuration file for the
  // account keyed by |principal_name|. Returns ERROR_NONE if both files could
  // be retrieved or if the credential cache is missing. Returns ERROR_LOCAL_IO
  // if any of the files failed to read.
  [[nodiscard]] ErrorType GetKerberosFiles(const std::string& principal_name,
                                           KerberosFiles* files) const;

  // Sends KerberosTicketExpiring signals for each expired Kerberos ticket and
  // starts scheduling renewal tasks for valid tickets.
  void StartObservingTickets();

  const base::FilePath& GetStorageDirForTesting() { return storage_dir_; }

  // Returns the base64-encoded |principal_name|.
  static std::string GetSafeFilenameForTesting(
      const std::string& principal_name);

  // Wraps |krb5_| in a Krb5JailWrapper.
  void WrapKrb5ForTesting();

  int last_renew_tgt_error_for_testing() const {
    return last_renew_tgt_error_for_testing_;
  }

 private:
  // File path helpers. All paths are relative to |storage_dir_|.

  // TgtRenewalScheduler::Delegate:
  ErrorType GetTgtStatus(const std::string& principal_name,
                         Krb5Interface::TgtStatus* tgt_status) override;
  ErrorType RenewTgt(const std::string& principal_name) override;
  void NotifyTgtExpiration(
      const std::string& principal_name,
      TgtRenewalScheduler::TgtExpiration expiration) override;

  // Acquires a TGT, sets |error| and returns true if the |principal_name|
  // account has access to the password (either the login password or a
  // remembered one). Returns false if no password is accessible.
  bool MaybeAutoAcquireTgt(const std::string& principal_name, ErrorType* error);

  // Directory where files specific to the |principal_name| account are stored.
  base::FilePath GetAccountDir(const std::string& principal_name) const;

  // File path of the Kerberos configuration for the given |principal_name|.
  base::FilePath GetKrb5ConfPath(const std::string& principal_name) const;

  // File path of the Kerberos credential cache for the given |principal_name|.
  base::FilePath GetKrb5CCPath(const std::string& principal_name) const;

  // File path of the Kerberos password for the given |principal_name|.
  base::FilePath GetPasswordPath(const std::string& principal_name) const;

  // Deletes all files (credential cache, password etc.) for the given
  // |principal_name|. Triggers KerberosFilesChanged if the credential cache was
  // deleted.
  void DeleteAllFilesFor(const std::string& principal_name);

  // Calls |kerberos_files_changed_|.
  void TriggerKerberosFilesChanged(const std::string& principal_name) const;

  // Calls |kerberos_ticket_expiring_|.
  void TriggerKerberosTicketExpiring(const std::string& principal_name) const;

  // Sets |password| to the login password. Removes a remembered password for
  // |principal_name| if there is any.
  ErrorType UpdatePasswordFromLogin(const std::string& principal_name,
                                    std::string* password);

  // If |password| is empty, loads it from the password file if that exists. If
  // |password| is not empty and |remember_password| is true, saves |password|
  // to the password file. If |remember_password| is false, deletes the password
  // file.
  ErrorType UpdatePasswordFromSaved(const std::string& principal_name,
                                    bool remember_password,
                                    std::string* password);

  // Sends UMA stats for daily usage counts. The stats are sent at most once a
  // day, even if this method is called more often.
  void MaybeReportDailyUsageStats() const;

  // Directory where all account data is stored.
  const base::FilePath storage_dir_;

  // File path where |accounts_| is stored.
  const base::FilePath accounts_path_;

  // Gets called when the Kerberos configuration or credential cache changes for
  // a specific account.
  const KerberosFilesChangedCallback kerberos_files_changed_;

  // Gets called when the a Kerberos ticket is about to expire in the next
  // couple of minutes or if it already expired.
  const KerberosTicketExpiringCallback kerberos_ticket_expiring_;

  // Interface for Kerberos methods (may be overridden for tests).
  std::unique_ptr<Krb5Interface> krb5_;

  // Returns the index of the account for |principal_name| or |kInvalidIndex| if
  // the account does not exist.
  int GetAccountIndex(const std::string& principal_name) const;

  struct InternalAccount {
    // Account state. Gets serialized to disk.
    AccountData data;

    // Scheduler for automatic TGT renewal.
    std::unique_ptr<TgtRenewalScheduler> tgt_renewal_scheduler_;

    InternalAccount(AccountData&& data,
                    TgtRenewalScheduler::Delegate* delegate);
  };

  // Returns the InternalAccount for |principal_name| if available or nullptr
  // otherwise. The returned pointer may lose validity if |accounts_| gets
  // modified.
  const InternalAccount* GetAccount(const std::string& principal_name) const;
  InternalAccount* GetMutableAccount(const std::string& principal_name);

  enum class WhatToRemove { kNothing, kPassword, kAccount };

  // Determines what data to remove, depending on |mode| and |account|.
  WhatToRemove DetermineWhatToRemove(ClearMode mode,
                                     const InternalAccount& account);

  // List of all accounts. Stored in a vector to keep order of addition.
  std::vector<InternalAccount> accounts_;

  // Interface to retrieve the login password.
  std::unique_ptr<password_provider::PasswordProviderInterface>
      password_provider_;

  // For collecting UMA stats. Not owned.
  KerberosMetrics* metrics_;

  // For retrieving encryption types from config and send to UMA stats.
  ConfigParser config_parser_;

  ErrorType last_renew_tgt_error_for_testing_ = ERROR_NONE;
};

}  // namespace kerberos

#endif  // KERBEROS_ACCOUNT_MANAGER_H_
