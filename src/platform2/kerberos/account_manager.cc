// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "kerberos/account_manager.h"

#include <limits>
#include <utility>

#include <base/base64.h>
#include <base/check.h>
#include <base/containers/contains.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <libpasswordprovider/password.h>
#include <libpasswordprovider/password_provider.h>

#include "kerberos/error_strings.h"
#include "kerberos/kerberos_metrics.h"
#include "kerberos/krb5_interface.h"
#include "kerberos/krb5_jail_wrapper.h"

namespace kerberos {

namespace {

constexpr int kInvalidIndex = -1;

constexpr int kFileMode_rw =
    base::FILE_PERMISSION_READ_BY_USER | base::FILE_PERMISSION_WRITE_BY_USER;

constexpr int kFileMode_rwxrwx =
    base::FILE_PERMISSION_USER_MASK | base::FILE_PERMISSION_GROUP_MASK;

// Kerberos config files are stored as storage_dir/account_dir/this.
constexpr char kKrb5ConfFilePart[] = "krb5.conf";
// Kerberos credential caches are stored as storage_dir/account_dir/this.
constexpr char kKrb5CCFilePart[] = "krb5cc";
// Passwords are stored as storage_dir/account_dir/this.
constexpr char kPasswordFilePart[] = "password";
// Account data is stored as storage_dir + this.
constexpr char kAccountsFile[] = "accounts";

// Size limit for file (1 MB).
constexpr size_t kFileSizeLimit = 1024 * 1024;

// Returns the base64 encoded |principal_name|. This is used to create safe
// filenames while at the same time allowing easy debugging.
std::string GetSafeFilename(const std::string& principal_name) {
  std::string encoded_principal;
  base::Base64Encode(principal_name, &encoded_principal);
  return encoded_principal;
}

// Reads the file at |path| into |data|. Returns |ERROR_LOCAL_IO| if the file
// could not be read.
[[nodiscard]] ErrorType LoadFile(const base::FilePath& path,
                                 std::string* data) {
  data->clear();
  if (!base::ReadFileToStringWithMaxSize(path, data, kFileSizeLimit)) {
    PLOG(ERROR) << "Failed to read " << path.value();
    data->clear();
    return ERROR_LOCAL_IO;
  }
  return ERROR_NONE;
}

// Writes |data| to the file at |path|. Returns |ERROR_LOCAL_IO| if the file
// could not be written.
[[nodiscard]] ErrorType SaveFile(const base::FilePath& path,
                                 const std::string& data) {
  const int data_size = static_cast<int>(data.size());
  if (base::WriteFile(path, data.data(), data_size) != data_size) {
    LOG(ERROR) << "Failed to write '" << path.value() << "'";
    return ERROR_LOCAL_IO;
  }
  return ERROR_NONE;
}

// Sets file permissions for a given |path|. Returns ERROR_LOCAL_IO on error.
[[nodiscard]] ErrorType SetFilePermissions(const base::FilePath& path,
                                           int mode) {
  if (!base::SetPosixFilePermissions(path, mode)) {
    LOG(ERROR) << "Failed to set permissions on '" << path.value() << "'";
    return ERROR_LOCAL_IO;
  }
  return ERROR_NONE;
}

}  // namespace

AccountManager::AccountManager(
    base::FilePath storage_dir,
    KerberosFilesChangedCallback kerberos_files_changed,
    KerberosTicketExpiringCallback kerberos_ticket_expiring,
    std::unique_ptr<Krb5Interface> krb5,
    std::unique_ptr<password_provider::PasswordProviderInterface>
        password_provider,
    KerberosMetrics* metrics)
    : storage_dir_(std::move(storage_dir)),
      accounts_path_(storage_dir_.Append(kAccountsFile)),
      kerberos_files_changed_(std::move(kerberos_files_changed)),
      kerberos_ticket_expiring_(std::move(kerberos_ticket_expiring)),
      krb5_(std::move(krb5)),
      password_provider_(std::move(password_provider)),
      metrics_(metrics) {
  DCHECK(kerberos_files_changed_);
  DCHECK(kerberos_ticket_expiring_);
}

AccountManager::~AccountManager() = default;

ErrorType AccountManager::SaveAccounts() const {
  // Copy |accounts_| into proto message.
  AccountDataList storage_accounts;
  for (const auto& account : accounts_)
    *storage_accounts.add_accounts() = account.data;

  // Store serialized proto message on disk.
  std::string accounts_blob;
  if (!storage_accounts.SerializeToString(&accounts_blob)) {
    LOG(ERROR) << "Failed to serialize accounts list to string";
    return ERROR_LOCAL_IO;
  }

  ErrorType error = SaveFile(accounts_path_, accounts_blob);
  if (error != ERROR_NONE)
    return error;

  // Remove group and other read access. This prevents kerberosd-exec from
  // reading it (it's none of its business).
  return SetFilePermissions(accounts_path_, kFileMode_rw);
}

ErrorType AccountManager::LoadAccounts() {
  accounts_.clear();

  // A missing file counts as a file with empty data.
  if (!base::PathExists(accounts_path_))
    return ERROR_NONE;

  // Load serialized proto blob.
  std::string accounts_blob;
  ErrorType error = LoadFile(accounts_path_, &accounts_blob);
  if (error != ERROR_NONE)
    return error;

  // Parse blob into proto message.
  AccountDataList storage_accounts;
  if (!storage_accounts.ParseFromString(accounts_blob)) {
    LOG(ERROR) << "Failed to parse accounts list from string";
    return ERROR_LOCAL_IO;
  }

  // Copy data into |accounts_|.
  accounts_.reserve(storage_accounts.accounts_size());
  for (int n = 0; n < storage_accounts.accounts_size(); ++n) {
    accounts_.emplace_back(std::move(*storage_accounts.mutable_accounts(n)),
                           this);
  }

  return ERROR_NONE;
}

ErrorType AccountManager::AddAccount(const std::string& principal_name,
                                     bool is_managed) {
  int index = GetAccountIndex(principal_name);
  if (index != kInvalidIndex) {
    // Policy should overwrite user-added accounts, but user-added accounts
    // should not overwrite policy accounts.
    if (!accounts_[index].data.is_managed() && is_managed) {
      DeleteAllFilesFor(principal_name);
      accounts_[index].data.set_is_managed(is_managed);
      SaveAccounts();
    }
    return ERROR_DUPLICATE_PRINCIPAL_NAME;
  }

  // Create the account directory.
  const base::FilePath account_dir = GetAccountDir(principal_name);
  base::File::Error ferror;
  if (!base::CreateDirectoryAndGetError(account_dir, &ferror)) {
    LOG(ERROR) << "Failed to create directory '" << account_dir.value()
               << "': " << base::File::ErrorToString(ferror);
    return ERROR_LOCAL_IO;
  }

  // The account directory needs to be group accessible since kinit runs as
  // kerberosd-exec user and wants to write krbcc into that directory.
  ErrorType error = SetFilePermissions(account_dir, kFileMode_rwxrwx);
  if (error != ERROR_NONE) {
    base::DeletePathRecursively(account_dir);
    return error;
  }

  // Create account record.
  AccountData data;
  data.set_principal_name(principal_name);
  data.set_is_managed(is_managed);
  accounts_.emplace_back(std::move(data), this);
  SaveAccounts();
  return ERROR_NONE;
}

ErrorType AccountManager::RemoveAccount(const std::string& principal_name) {
  int index = GetAccountIndex(principal_name);
  if (index == kInvalidIndex)
    return ERROR_UNKNOWN_PRINCIPAL_NAME;

  DeleteAllFilesFor(principal_name);
  accounts_.erase(accounts_.begin() + index);

  SaveAccounts();
  return ERROR_NONE;
}

void AccountManager::DeleteAllFilesFor(const std::string& principal_name) {
  const bool krb5cc_existed = base::PathExists(GetKrb5CCPath(principal_name));
  CHECK(base::DeletePathRecursively(GetAccountDir(principal_name)));
  if (krb5cc_existed)
    TriggerKerberosFilesChanged(principal_name);
}

ErrorType AccountManager::ClearAccounts(
    ClearMode mode, std::unordered_set<std::string> keep_list) {
  // Early out.
  if (accounts_.size() == 0)
    return ERROR_NONE;

  for (auto it = accounts_.begin(); it != accounts_.end(); /* empty */) {
    if (base::Contains(keep_list, it->data.principal_name())) {
      ++it;
      continue;
    }

    switch (DetermineWhatToRemove(mode, *it)) {
      case WhatToRemove::kNothing:
        ++it;
        continue;

      case WhatToRemove::kPassword:
        CHECK(base::DeleteFile(GetPasswordPath(it->data.principal_name())));
        ++it;
        continue;

      case WhatToRemove::kAccount:
        DeleteAllFilesFor(it->data.principal_name());
        it = accounts_.erase(it);
        continue;
    }
  }

  SaveAccounts();
  return ERROR_NONE;
}

std::vector<Account> AccountManager::ListAccounts() const {
  std::vector<Account> accounts;

  for (const auto& it : accounts_) {
    Account account;
    account.set_principal_name(it.data.principal_name());
    account.set_is_managed(it.data.is_managed());
    account.set_password_was_remembered(
        base::PathExists(GetPasswordPath(it.data.principal_name())));
    account.set_use_login_password(it.data.use_login_password());

    // Do a best effort reporting results, don't bail on the first error. If
    // there's a broken account, the user is able to recover the situation
    // this way (reauthenticate or remove account and add back).

    // Check PathExists, so that no error is printed if the file doesn't exist.
    std::string krb5conf;
    const base::FilePath krb5conf_path =
        GetKrb5ConfPath(it.data.principal_name());
    if (base::PathExists(krb5conf_path) &&
        LoadFile(krb5conf_path, &krb5conf) == ERROR_NONE) {
      account.set_krb5conf(krb5conf);
    }

    // A missing krb5cc file just translates to an invalid ticket (lifetime 0).
    Krb5Interface::TgtStatus tgt_status;
    const base::FilePath krb5cc_path = GetKrb5CCPath(it.data.principal_name());
    if (base::PathExists(krb5cc_path) &&
        krb5_->GetTgtStatus(krb5cc_path, &tgt_status) == ERROR_NONE) {
      account.set_tgt_validity_seconds(tgt_status.validity_seconds);
      account.set_tgt_renewal_seconds(tgt_status.renewal_seconds);
    }

    accounts.push_back(std::move(account));
  }

  return accounts;
}

ErrorType AccountManager::SetConfig(const std::string& principal_name,
                                    const std::string& krb5conf) const {
  const InternalAccount* account = GetAccount(principal_name);
  if (!account) {
    return ERROR_UNKNOWN_PRINCIPAL_NAME;
  }

  // Validate configuration before setting it to make sure it doesn't contain
  // invalid options.
  ConfigErrorInfo error_info;
  ErrorType error = krb5_->ValidateConfig(krb5conf, &error_info);
  if (error != ERROR_NONE) {
    return error;
  }

  error = SaveFile(GetKrb5ConfPath(principal_name), krb5conf);

  // Triggering the signal is only necessary if the file was saved successfully,
  // and the credential cache exists.
  if (error == ERROR_NONE && base::PathExists(GetKrb5CCPath(principal_name))) {
    TriggerKerberosFilesChanged(principal_name);
  }

  return error;
}

ErrorType AccountManager::ValidateConfig(const std::string& krb5conf,
                                         ConfigErrorInfo* error_info) const {
  return krb5_->ValidateConfig(krb5conf, error_info);
}

ErrorType AccountManager::AcquireTgt(const std::string& principal_name,
                                     std::string password,
                                     bool remember_password,
                                     bool use_login_password) {
  InternalAccount* account = GetMutableAccount(principal_name);
  if (!account)
    return ERROR_UNKNOWN_PRINCIPAL_NAME;

  // Remember whether to use the login password.
  if (account->data.use_login_password() != use_login_password) {
    account->data.set_use_login_password(use_login_password);
    SaveAccounts();
  }

  ErrorType error = use_login_password
                        ? UpdatePasswordFromLogin(principal_name, &password)
                        : UpdatePasswordFromSaved(principal_name,
                                                  remember_password, &password);
  if (error != ERROR_NONE)
    return error;

  // Acquire a Kerberos ticket-granting-ticket.
  error =
      krb5_->AcquireTgt(principal_name, password, GetKrb5CCPath(principal_name),
                        GetKrb5ConfPath(principal_name));

  if (error == ERROR_NONE) {
    // Schedule task to automatically renew the ticket. If the ticket is invalid
    // for whatever reason, don't notify expiration immediately. This might lead
    // to an infinite loop when a password is stored and MaybeAutoAcquireTgt
    // tries to acquire a new TGT immediately.
    account->tgt_renewal_scheduler_->ScheduleRenewal(
        false /* notify_expiration */);

    // Assume the ticket changed if AcquireTgt() was successful.
    TriggerKerberosFilesChanged(principal_name);

    std::string krb5conf;
    ErrorType load_config_error =
        LoadFile(GetKrb5ConfPath(principal_name), &krb5conf);

    if (load_config_error == ERROR_NONE) {
      KerberosEncryptionTypes encryption_types;
      bool success =
          config_parser_.GetEncryptionTypes(krb5conf, &encryption_types);
      if (success) {
        metrics_->ReportKerberosEncryptionTypes(encryption_types);
      }
    }
  }

  // Trying to acquire a ticket qualifies this user as an active user, so report
  // stats.
  MaybeReportDailyUsageStats();

  return error;
}

ErrorType AccountManager::GetKerberosFiles(const std::string& principal_name,
                                           KerberosFiles* files) const {
  // Trying to get Kerberos files qualifies this user as an active user, so
  // report stats.
  MaybeReportDailyUsageStats();

  files->clear_krb5cc();
  files->clear_krb5conf();

  const InternalAccount* account = GetAccount(principal_name);
  if (!account)
    return ERROR_UNKNOWN_PRINCIPAL_NAME;

  // By convention, no credential cache means no error.
  const base::FilePath krb5cc_path = GetKrb5CCPath(principal_name);
  if (!base::PathExists(krb5cc_path))
    return ERROR_NONE;

  std::string krb5cc;
  ErrorType error = LoadFile(krb5cc_path, &krb5cc);
  if (error != ERROR_NONE)
    return error;

  std::string krb5conf;
  error = LoadFile(GetKrb5ConfPath(principal_name), &krb5conf);
  if (error != ERROR_NONE)
    return error;

  files->mutable_krb5cc()->assign(krb5cc.begin(), krb5cc.end());
  files->mutable_krb5conf()->assign(krb5conf.begin(), krb5conf.end());
  return ERROR_NONE;
}

void AccountManager::StartObservingTickets() {
  for (const auto& account : accounts_) {
    const base::FilePath krb5cc_path =
        GetKrb5CCPath(account.data.principal_name());

    // Might happen for managed accounts (e.g. misconfigured password). Chrome
    // only allows adding unmanaged accounts if a ticket can be acquired.
    if (!base::PathExists(krb5cc_path))
      continue;

    // A ticket where GetTgtStatus fails is considered broken and hence invalid.
    Krb5Interface::TgtStatus tgt_status;
    if (krb5_->GetTgtStatus(krb5cc_path, &tgt_status) != ERROR_NONE ||
        tgt_status.validity_seconds <= 0) {
      NotifyTgtExpiration(account.data.principal_name(),
                          TgtRenewalScheduler::TgtExpiration::kExpired);
      continue;
    }

    // Ticket is valid. Schedule task to automatically renew it.
    account.tgt_renewal_scheduler_->ScheduleRenewal(
        true /* notify_expiration */);
  }
}

// static
std::string AccountManager::GetSafeFilenameForTesting(
    const std::string& principal_name) {
  return GetSafeFilename(principal_name);
}

void AccountManager::WrapKrb5ForTesting() {
  krb5_ = std::make_unique<Krb5JailWrapper>(std::move(krb5_));
}

void AccountManager::TriggerKerberosFilesChanged(
    const std::string& principal_name) const {
  kerberos_files_changed_.Run(principal_name);
}

void AccountManager::TriggerKerberosTicketExpiring(
    const std::string& principal_name) const {
  kerberos_ticket_expiring_.Run(principal_name);
}

ErrorType AccountManager::GetTgtStatus(const std::string& principal_name,
                                       Krb5Interface::TgtStatus* tgt_status) {
  return krb5_->GetTgtStatus(GetKrb5CCPath(principal_name), tgt_status);
}

ErrorType AccountManager::RenewTgt(const std::string& principal_name) {
  ErrorType error =
      krb5_->RenewTgt(principal_name, GetKrb5CCPath(principal_name),
                      GetKrb5ConfPath(principal_name));

  if (error != ERROR_NONE) {
    VLOG(1) << "RenewTgt failed with " << GetErrorString(error);

    // Renewal didn't work. See if we have a password stored and try to
    // auto-renew.
    MaybeAutoAcquireTgt(principal_name, &error);
  }

  last_renew_tgt_error_for_testing_ = error;
  return error;
}

void AccountManager::NotifyTgtExpiration(
    const std::string& principal_name,
    TgtRenewalScheduler::TgtExpiration expiration) {
  // First try to auto-acquire the TGT (usually works if password is stored).
  // Only if that isn't possible or doesn't work, trigger the signal.
  ErrorType error = ERROR_NONE;
  if (!MaybeAutoAcquireTgt(principal_name, &error) || error != ERROR_NONE) {
    TriggerKerberosTicketExpiring(principal_name);
  }
}

bool AccountManager::MaybeAutoAcquireTgt(const std::string& principal_name,
                                         ErrorType* error) {
  InternalAccount* account = GetMutableAccount(principal_name);
  DCHECK(account);

  // Check if |account| has access to the password.
  const bool use_login_password = account->data.use_login_password();
  const bool password_was_remembered =
      base::PathExists(GetPasswordPath(principal_name));
  if (!use_login_password && !password_was_remembered)
    return false;

  // Should not have remembered login password ourselves.
  DCHECK(!(use_login_password && password_was_remembered));

  VLOG(1) << "Auto-acquiring new TGT using "
          << (use_login_password ? "login" : "remembered") << " password";

  *error = AcquireTgt(principal_name, std::string() /* password */,
                      password_was_remembered /* keep remembering */,
                      use_login_password);

  if (*error != ERROR_NONE)
    VLOG(1) << "Auto-acquiring TGT failed with " << GetErrorString(*error);

  return true;
}

base::FilePath AccountManager::GetAccountDir(
    const std::string& principal_name) const {
  return storage_dir_.Append(GetSafeFilename(principal_name));
}

base::FilePath AccountManager::GetKrb5ConfPath(
    const std::string& principal_name) const {
  return GetAccountDir(principal_name).Append(kKrb5ConfFilePart);
}

base::FilePath AccountManager::GetKrb5CCPath(
    const std::string& principal_name) const {
  return GetAccountDir(principal_name).Append(kKrb5CCFilePart);
}

base::FilePath AccountManager::GetPasswordPath(
    const std::string& principal_name) const {
  return GetAccountDir(principal_name).Append(kPasswordFilePart);
}

ErrorType AccountManager::UpdatePasswordFromLogin(
    const std::string& principal_name, std::string* password) {
  // Erase a previously remembered password.
  base::DeleteFile(GetPasswordPath(principal_name));

  // Get login password from |password_provider_|.
  std::unique_ptr<password_provider::Password> login_password =
      password_provider_->GetPassword();
  if (!login_password || login_password->size() == 0) {
    password->clear();
    LOG(WARNING) << "Unable to retrieve login password";
  } else {
    *password = std::string(login_password->GetRaw(), login_password->size());
  }
  return ERROR_NONE;
}

ErrorType AccountManager::UpdatePasswordFromSaved(
    const std::string& principal_name,
    bool remember_password,
    std::string* password) {
  // Decision table what to do with the password:
  // pw empty / remember| false                      | true
  // -------------------+----------------------------+------------------------
  // false              | use given, erase file      | use given, save to file
  // true               | load from file, erase file | load from file

  // Remember password (even if authentication is going to fail below).
  const base::FilePath password_path = GetPasswordPath(principal_name);
  if (!password->empty() && remember_password) {
    ErrorType error = SaveFile(password_path, *password);
    if (error != ERROR_NONE)
      return error;

    // Remove group and other read access, just keep kerberosd rw. This prevents
    // kerberosd-exec from accessing the password.
    error = SetFilePermissions(password_path, kFileMode_rw);
    if (error != ERROR_NONE) {
      // Do a best effort removing the password.
      base::DeleteFile(password_path);
      return error;
    }
  }

  // Try to load a saved password if available and none is given.
  if (password->empty() && base::PathExists(password_path)) {
    ErrorType error = LoadFile(password_path, password);
    if (error != ERROR_NONE)
      return error;
  }

  // Erase a previously remembered password.
  if (!remember_password)
    base::DeleteFile(password_path);

  return ERROR_NONE;
}

void AccountManager::MaybeReportDailyUsageStats() const {
  // Did a day pass already?
  if (!metrics_->ShouldReportDailyUsageStats())
    return;

  // Count different kinds of accounts.
  int total_count = static_cast<int>(accounts_.size());
  int managed_count = 0;
  int unmanaged_count = 0;
  int remembered_password_count = 0;
  int use_login_password_count = 0;

  for (const auto& account : accounts_) {
    if (account.data.is_managed())
      managed_count++;
    else
      unmanaged_count++;
    if (base::PathExists(GetPasswordPath(account.data.principal_name())))
      remembered_password_count++;
    if (account.data.use_login_password())
      use_login_password_count++;
  }

  // Report UMA stats.
  metrics_->ReportDailyUsageStats(total_count, managed_count, unmanaged_count,
                                  remembered_password_count,
                                  use_login_password_count);
}

AccountManager::InternalAccount::InternalAccount(
    AccountData&& _data, TgtRenewalScheduler::Delegate* delegate)
    : data(std::move(_data)),
      tgt_renewal_scheduler_(std::make_unique<TgtRenewalScheduler>(
          data.principal_name(), delegate)) {}

int AccountManager::GetAccountIndex(const std::string& principal_name) const {
  for (size_t n = 0; n < accounts_.size(); ++n) {
    if (accounts_[n].data.principal_name() == principal_name) {
      CHECK(n <= std::numeric_limits<int>::max());
      return static_cast<int>(n);
    }
  }
  return kInvalidIndex;
}

const AccountManager::InternalAccount* AccountManager::GetAccount(
    const std::string& principal_name) const {
  int index = GetAccountIndex(principal_name);
  return index != kInvalidIndex ? &accounts_[index] : nullptr;
}

AccountManager::InternalAccount* AccountManager::GetMutableAccount(
    const std::string& principal_name) {
  int index = GetAccountIndex(principal_name);
  return index != kInvalidIndex ? &accounts_[index] : nullptr;
}

AccountManager::WhatToRemove AccountManager::DetermineWhatToRemove(
    ClearMode mode, const InternalAccount& account) {
  switch (mode) {
    case CLEAR_ALL:
      return WhatToRemove::kAccount;

    case CLEAR_ONLY_MANAGED_ACCOUNTS:
      return account.data.is_managed() ? WhatToRemove::kAccount
                                       : WhatToRemove::kNothing;

    case CLEAR_ONLY_UNMANAGED_ACCOUNTS:
      return !account.data.is_managed() ? WhatToRemove::kAccount
                                        : WhatToRemove::kNothing;

    case CLEAR_ONLY_UNMANAGED_REMEMBERED_PASSWORDS:
      return !account.data.is_managed() ? WhatToRemove::kPassword
                                        : WhatToRemove::kNothing;
  }
  return WhatToRemove::kNothing;
}

}  // namespace kerberos
