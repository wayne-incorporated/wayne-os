// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "kerberos/account_manager.h"

#include <map>
#include <memory>
#include <utility>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <base/memory/ref_counted.h>
#include <base/test/test_mock_time_task_runner.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libpasswordprovider/fake_password_provider.h>
#include <libpasswordprovider/password_provider_test_utils.h>

#include "kerberos/fake_krb5_interface.h"
#include "kerberos/kerberos_metrics.h"
#include "kerberos/krb5_jail_wrapper.h"

using testing::_;
using testing::Mock;
using testing::NiceMock;
using testing::Return;

namespace kerberos {
namespace {

constexpr char kUser[] = "user@REALM.COM";
constexpr char kUser2[] = "user2@REALM2.COM";
constexpr char kUser3[] = "user3@REALM3.COM";
constexpr char kPassword[] = "i<3k3R8e5Oz";
constexpr char kPassword2[] = "ih4zf00d";
constexpr char kKrb5Conf[] = R"(
  [libdefaults]
    forwardable = true)";
constexpr char kStrongKrb5Conf[] = R"(
  [libdefaults]
    forwardable = true
    default_tkt_enctypes = aes256-cts-hmac-sha1-96
    default_tgs_enctypes = aes256-cts-hmac-sha1-96
    permitted_enctypes = aes256-cts-hmac-sha1-96)";
constexpr char kLegacyKrb5Conf[] = R"(
  [libdefaults]
    forwardable = true
    default_tkt_enctypes = arcfour-hmac
    default_tgs_enctypes = arcfour-hmac
    permitted_enctypes = arcfour-hmac)";
constexpr char kInvalidKrb5Conf[] = R"(
  [libdefaults]
    stonkskew = 123)";

constexpr Krb5Interface::TgtStatus kValidTgt(3600, 3600);
constexpr Krb5Interface::TgtStatus kExpiredTgt(0, 0);

// Convenience defines to make code more readable
constexpr bool kManaged = true;
constexpr bool kUnmanaged = false;

constexpr bool kRememberPassword = true;
constexpr bool kDontRememberPassword = false;

constexpr bool kUseLoginPassword = true;
constexpr bool kDontUseLoginPassword = false;

constexpr char kEmptyPassword[] = "";

class MockMetrics : public KerberosMetrics {
 public:
  explicit MockMetrics(const base::FilePath& storage_dir)
      : KerberosMetrics(storage_dir) {}
  MockMetrics(const MockMetrics&) = delete;
  MockMetrics& operator=(const MockMetrics&) = delete;

  ~MockMetrics() override = default;

  MOCK_METHOD(bool, ShouldReportDailyUsageStats, (), (override));
  MOCK_METHOD(void,
              ReportDailyUsageStats,
              (int, int, int, int, int),
              (override));
  MOCK_METHOD(void,
              ReportKerberosEncryptionTypes,
              (KerberosEncryptionTypes),
              (override));
};

}  // namespace

class AccountManagerTest : public ::testing::Test {
 public:
  AccountManagerTest()
      : kerberos_files_changed_(
            base::BindRepeating(&AccountManagerTest::OnKerberosFilesChanged,
                                base::Unretained(this))),
        kerberos_ticket_expiring_(
            base::BindRepeating(&AccountManagerTest::OnKerberosTicketExpiring,
                                base::Unretained(this))) {}
  AccountManagerTest(const AccountManagerTest&) = delete;
  AccountManagerTest& operator=(const AccountManagerTest&) = delete;

  ~AccountManagerTest() override = default;

  void SetUp() override {
    ::testing::Test::SetUp();

    // Create temp directory for files written during tests.
    CHECK(storage_dir_.CreateUniqueTempDir());
    accounts_path_ = storage_dir_.GetPath().Append("accounts");
    account_dir_ = storage_dir_.GetPath().Append(
        AccountManager::GetSafeFilenameForTesting(kUser));
    krb5cc_path_ = account_dir_.Append("krb5cc");
    krb5conf_path_ = account_dir_.Append("krb5.conf");
    password_path_ = account_dir_.Append("password");

    // Create the manager with a fake krb5 interface.
    auto krb5 = std::make_unique<FakeKrb5Interface>();
    auto password_provider =
        std::make_unique<password_provider::FakePasswordProvider>();
    metrics_ = std::make_unique<NiceMock<MockMetrics>>(storage_dir_.GetPath());
    krb5_ = krb5.get();
    password_provider_ = password_provider.get();
    manager_ = std::make_unique<AccountManager>(
        storage_dir_.GetPath(), kerberos_files_changed_,
        kerberos_ticket_expiring_, std::move(krb5),
        std::move(password_provider), metrics_.get());
  }

  void TearDown() override {
    // Make sure the file stored on disk contains the same accounts as the
    // manager instance. This catches cases where AccountManager forgets to save
    // accounts on some change.
    if (base::PathExists(accounts_path_)) {
      std::vector<Account> accounts = manager_->ListAccounts();

      AccountManager other_manager(
          storage_dir_.GetPath(), kerberos_files_changed_,
          kerberos_ticket_expiring_, std::make_unique<FakeKrb5Interface>(),
          std::make_unique<password_provider::FakePasswordProvider>(),
          metrics_.get());
      other_manager.LoadAccounts();
      std::vector<Account> other_accounts = other_manager.ListAccounts();

      ASSERT_NO_FATAL_FAILURE(ExpectAccountsEqual(accounts, other_accounts));
    }

    ::testing::Test::TearDown();
  }

  // Add account with default settings.
  ErrorType AddAccount() { return manager_->AddAccount(kUser, kUnmanaged); }

  // Sets some default Kerberos configuration.
  ErrorType SetConfig() { return SetConfig(kKrb5Conf); }

  // Sets Kerberos configuration.
  ErrorType SetConfig(const std::string& config) {
    return manager_->SetConfig(kUser, config);
  }

  // Acquire Kerberos ticket with default credentials and settings.
  ErrorType AcquireTgt() {
    return manager_->AcquireTgt(kUser, kPassword, kDontRememberPassword,
                                kDontUseLoginPassword);
  }

  void SaveLoginPassword(const char* password) {
    auto password_ptr = password_provider::test::CreatePassword(password);
    password_provider_->SavePassword(*password_ptr);
  }

  // Fast forwards to the next scheduled task (assumed to be the renewal task)
  // and verifies expectation that |krb5_->RenewTgt() was called|.
  void RunScheduledRenewalTask() {
    int initial_count = krb5_->renew_tgt_call_count();
    EXPECT_EQ(1, task_runner_->GetPendingTaskCount());
    task_runner_->FastForwardBy(task_runner_->NextPendingTaskDelay());
    EXPECT_EQ(initial_count + 1, krb5_->renew_tgt_call_count());
  }

 protected:
  void OnKerberosFilesChanged(const std::string& principal_name) {
    kerberos_files_changed_count_[principal_name]++;
  }

  void OnKerberosTicketExpiring(const std::string& principal_name) {
    kerberos_ticket_expiring_count_[principal_name]++;
  }

  void ExpectAccountsEqual(const std::vector<Account>& account_list_1,
                           const std::vector<Account>& account_list_2) {
    ASSERT_EQ(account_list_1.size(), account_list_2.size());
    for (size_t n = 0; n < account_list_1.size(); ++n) {
      const Account& account1 = account_list_1[n];
      const Account& account2 = account_list_2[n];

      EXPECT_EQ(account1.principal_name(), account2.principal_name());
      EXPECT_EQ(account1.is_managed(), account2.is_managed());
      EXPECT_EQ(account1.use_login_password(), account2.use_login_password());
      EXPECT_EQ(account1.krb5conf(), account2.krb5conf());
      EXPECT_EQ(account1.password_was_remembered(),
                account2.password_was_remembered());
    }
  }

  std::unique_ptr<AccountManager> manager_;

  // Fake Kerberos interface used by |manager_|. Not owned.
  FakeKrb5Interface* krb5_;

  // Fake password provider to get the login password. Not owned.
  password_provider::FakePasswordProvider* password_provider_;

  // Mock metrics for testing UMA stat recording.
  std::unique_ptr<NiceMock<MockMetrics>> metrics_;

  // Paths of files stored by |manager_|.
  base::ScopedTempDir storage_dir_;
  base::FilePath accounts_path_;
  base::FilePath account_dir_;
  base::FilePath krb5conf_path_;
  base::FilePath krb5cc_path_;
  base::FilePath password_path_;

  AccountManager::KerberosFilesChangedCallback kerberos_files_changed_;
  AccountManager::KerberosTicketExpiringCallback kerberos_ticket_expiring_;

  std::map<std::string, int> kerberos_files_changed_count_;
  std::map<std::string, int> kerberos_ticket_expiring_count_;

  scoped_refptr<base::TestMockTimeTaskRunner> task_runner_{
      new base::TestMockTimeTaskRunner()};
  base::TestMockTimeTaskRunner::ScopedContext scoped_context_{task_runner_};
};

// Adding an account succeeds and serializes the file on disk.
TEST_F(AccountManagerTest, AddAccountSuccess) {
  EXPECT_FALSE(base::PathExists(accounts_path_));
  EXPECT_EQ(ERROR_NONE, AddAccount());
  EXPECT_TRUE(base::PathExists(accounts_path_));
}

// AddAccount() fails if the same account is added twice.
TEST_F(AccountManagerTest, AddDuplicateAccountFail) {
  EXPECT_EQ(ERROR_NONE, AddAccount());

  EXPECT_TRUE(base::DeleteFile(accounts_path_));
  EXPECT_EQ(ERROR_DUPLICATE_PRINCIPAL_NAME, AddAccount());
  EXPECT_FALSE(base::PathExists(accounts_path_));
}

// Adding a managed account overwrites an existing unmanaged account.
TEST_F(AccountManagerTest, ManagedOverridesUnmanaged) {
  EXPECT_EQ(ERROR_NONE, manager_->AddAccount(kUser, kUnmanaged));

  EXPECT_EQ(ERROR_NONE, AcquireTgt());
  EXPECT_TRUE(base::PathExists(krb5cc_path_));

  // Overwriting with a managed account should wipe existing files and make the
  // account managed.
  EXPECT_EQ(ERROR_DUPLICATE_PRINCIPAL_NAME,
            manager_->AddAccount(kUser, kManaged));
  EXPECT_FALSE(base::PathExists(krb5cc_path_));

  std::vector<Account> accounts = manager_->ListAccounts();
  ASSERT_EQ(1u, accounts.size());
  EXPECT_TRUE(accounts[0].is_managed());
}

// Adding an unmanaged account does not overwrite an existing managed account.
TEST_F(AccountManagerTest, UnmanagedDoesNotOverrideManaged) {
  EXPECT_EQ(ERROR_NONE, manager_->AddAccount(kUser, kManaged));

  EXPECT_EQ(ERROR_DUPLICATE_PRINCIPAL_NAME,
            manager_->AddAccount(kUser, kUnmanaged));
  std::vector<Account> accounts = manager_->ListAccounts();
  ASSERT_EQ(1u, accounts.size());
  EXPECT_TRUE(accounts[0].is_managed());
}

// RemoveAccount() succeeds if the account exists and serializes the file on
// disk.
TEST_F(AccountManagerTest, RemoveAccountSuccess) {
  EXPECT_EQ(ERROR_NONE, AddAccount());

  EXPECT_TRUE(base::DeleteFile(accounts_path_));
  EXPECT_EQ(ERROR_NONE, manager_->RemoveAccount(kUser));
  EXPECT_TRUE(base::PathExists(accounts_path_));
}

// RemoveAccount() fails if the account does not exist.
TEST_F(AccountManagerTest, RemoveUnknownAccountFail) {
  EXPECT_EQ(ERROR_UNKNOWN_PRINCIPAL_NAME, manager_->RemoveAccount(kUser));
  EXPECT_FALSE(base::PathExists(accounts_path_));
}

// RemoveAccount() does not trigger KerberosFilesChanged if the credential cache
// does not exists.
TEST_F(AccountManagerTest, RemoveAccountTriggersKFCIfCCExists) {
  EXPECT_EQ(ERROR_NONE, AddAccount());

  EXPECT_EQ(ERROR_NONE, manager_->RemoveAccount(kUser));
  EXPECT_EQ(0, kerberos_files_changed_count_[kUser]);
}

// RemoveAccount() triggers KerberosFilesChanged if the credential cache exists.
TEST_F(AccountManagerTest, RemoveAccountDoesNotTriggerKFCIfCCDoesNotExist) {
  EXPECT_EQ(ERROR_NONE, AddAccount());

  EXPECT_EQ(ERROR_NONE, AcquireTgt());
  EXPECT_EQ(1, kerberos_files_changed_count_[kUser]);
  EXPECT_EQ(ERROR_NONE, manager_->RemoveAccount(kUser));
  EXPECT_EQ(2, kerberos_files_changed_count_[kUser]);
}

// Repeatedly calling AddAccount() and RemoveAccount() succeeds.
TEST_F(AccountManagerTest, RepeatedAddRemoveSuccess) {
  EXPECT_EQ(ERROR_NONE, AddAccount());
  EXPECT_EQ(ERROR_NONE, manager_->RemoveAccount(kUser));

  EXPECT_EQ(ERROR_NONE, AddAccount());
  EXPECT_EQ(ERROR_NONE, manager_->RemoveAccount(kUser));
}

// ClearAccounts(CLEAR_ALL) clears all accounts.
TEST_F(AccountManagerTest, ClearAccountsSuccess) {
  EXPECT_EQ(ERROR_NONE, manager_->AddAccount(kUser, kUnmanaged));
  EXPECT_EQ(ERROR_NONE, manager_->AddAccount(kUser2, kManaged));

  EXPECT_EQ(ERROR_NONE, manager_->ClearAccounts(CLEAR_ALL, {}));
  std::vector<Account> accounts = manager_->ListAccounts();
  EXPECT_EQ(0u, accounts.size());
}

// ClearAccounts(CLEAR_ALL) wipes Kerberos configuration and credential cache.
TEST_F(AccountManagerTest, ClearAccountsRemovesKerberosFiles) {
  EXPECT_EQ(ERROR_NONE, AddAccount());

  EXPECT_EQ(ERROR_NONE, SetConfig());
  EXPECT_EQ(ERROR_NONE, AcquireTgt());
  EXPECT_TRUE(base::PathExists(krb5conf_path_));
  EXPECT_TRUE(base::PathExists(krb5cc_path_));
  EXPECT_EQ(ERROR_NONE, manager_->ClearAccounts(CLEAR_ALL, {}));
  EXPECT_FALSE(base::PathExists(krb5conf_path_));
  EXPECT_FALSE(base::PathExists(krb5cc_path_));
}

// ClearAccounts(CLEAR_ALL) triggers KerberosFilesChanged if the credential
// cache exists.
TEST_F(AccountManagerTest, ClearAccountsTriggersKFCIfCCExists) {
  EXPECT_EQ(ERROR_NONE, AddAccount());

  EXPECT_EQ(ERROR_NONE, AcquireTgt());
  EXPECT_EQ(1, kerberos_files_changed_count_[kUser]);
  EXPECT_EQ(ERROR_NONE, manager_->ClearAccounts(CLEAR_ALL, {}));
  EXPECT_EQ(2, kerberos_files_changed_count_[kUser]);
}

// ClearAccounts(CLEAR_ALL) does not trigger KerberosFilesChanged if the
// credential cache does not exist.
TEST_F(AccountManagerTest, ClearAccountsDoesNotTriggerKFCIfDoesNotCCExist) {
  EXPECT_EQ(ERROR_NONE, AddAccount());

  EXPECT_EQ(ERROR_NONE, manager_->ClearAccounts(CLEAR_ALL, {}));
  EXPECT_EQ(0, kerberos_files_changed_count_[kUser]);
}

// ClearAccounts(CLEAR_ONLY_UNMANAGED_ACCOUNTS) clears only unmanaged accounts.
TEST_F(AccountManagerTest, ClearUnmanagedAccountsSuccess) {
  EXPECT_EQ(ERROR_NONE, manager_->AddAccount(kUser, kUnmanaged));
  EXPECT_EQ(ERROR_NONE, manager_->AddAccount(kUser2, kManaged));

  EXPECT_EQ(ERROR_NONE,
            manager_->ClearAccounts(CLEAR_ONLY_UNMANAGED_ACCOUNTS, {}));
  std::vector<Account> accounts = manager_->ListAccounts();
  ASSERT_EQ(1u, accounts.size());
  EXPECT_EQ(kUser2, accounts[0].principal_name());
}

// ClearAccounts(CLEAR_ONLY_UNMANAGED_REMEMBERED_PASSWORDS) clears only
// passwords of unmanaged accounts.
TEST_F(AccountManagerTest, ClearUnmanagedPasswordsSuccess) {
  // kUser is unmanaged, kUser2 is managed.
  EXPECT_EQ(ERROR_NONE, manager_->AddAccount(kUser, kUnmanaged));
  EXPECT_EQ(ERROR_NONE, manager_->AddAccount(kUser2, kManaged));
  EXPECT_EQ(ERROR_NONE,
            manager_->AcquireTgt(kUser, kPassword, kRememberPassword,
                                 kDontUseLoginPassword));
  EXPECT_EQ(ERROR_NONE,
            manager_->AcquireTgt(kUser2, kPassword, kRememberPassword,
                                 kDontUseLoginPassword));

  base::FilePath password_path_2 =
      storage_dir_.GetPath()
          .Append(AccountManager::GetSafeFilenameForTesting(kUser2))
          .Append("password");
  EXPECT_TRUE(base::PathExists(password_path_));
  EXPECT_TRUE(base::PathExists(password_path_2));

  EXPECT_EQ(ERROR_NONE, manager_->ClearAccounts(
                            CLEAR_ONLY_UNMANAGED_REMEMBERED_PASSWORDS, {}));
  std::vector<Account> accounts = manager_->ListAccounts();
  ASSERT_EQ(2u, accounts.size());
  EXPECT_FALSE(base::PathExists(password_path_));
  EXPECT_TRUE(base::PathExists(password_path_2));
}

// ClearAccounts(CLEAR_ONLY_MANAGED_ACCOUNTS) clears only managed accounts that
// are not on the keep list.
TEST_F(AccountManagerTest, ClearManagedPasswordsWithKeepListSuccess) {
  EXPECT_EQ(ERROR_NONE, manager_->AddAccount(kUser, kManaged));
  EXPECT_EQ(ERROR_NONE, manager_->AddAccount(kUser2, kManaged));
  EXPECT_EQ(ERROR_NONE, manager_->AddAccount(kUser3, kUnmanaged));

  // Keep the managed kUser-account.
  EXPECT_EQ(ERROR_NONE,
            manager_->ClearAccounts(CLEAR_ONLY_MANAGED_ACCOUNTS, {kUser}));
  std::vector<Account> accounts = manager_->ListAccounts();
  ASSERT_EQ(2u, accounts.size());
  EXPECT_EQ(kUser, accounts[0].principal_name());
  EXPECT_EQ(kUser3, accounts[1].principal_name());
}

// SetConfig() succeeds and writes the config to |krb5conf_path_|.
TEST_F(AccountManagerTest, SetConfigSuccess) {
  EXPECT_EQ(ERROR_NONE, AddAccount());

  EXPECT_EQ(ERROR_NONE, SetConfig());
  std::string krb5_conf;
  EXPECT_TRUE(base::ReadFileToString(krb5conf_path_, &krb5_conf));
  EXPECT_EQ(krb5_conf, kKrb5Conf);
}

// SetConfig() calls ValidateConfig on the Kerberos interface.
TEST_F(AccountManagerTest, SetConfigValidatesConfig) {
  EXPECT_EQ(ERROR_NONE, AddAccount());

  krb5_->set_validate_config_error(ERROR_BAD_CONFIG);
  EXPECT_EQ(ERROR_BAD_CONFIG, SetConfig());

  // The config should not be saved if the validation returned error.
  EXPECT_FALSE(base::PathExists(krb5conf_path_));
}

// SetConfig() triggers KerberosFilesChanged if the credential cache exists.
TEST_F(AccountManagerTest, SetConfigTriggersKFCIfCCExists) {
  EXPECT_EQ(ERROR_NONE, AddAccount());

  EXPECT_EQ(ERROR_NONE, AcquireTgt());
  EXPECT_EQ(1, kerberos_files_changed_count_[kUser]);
  EXPECT_EQ(ERROR_NONE, SetConfig());
  EXPECT_EQ(2, kerberos_files_changed_count_[kUser]);
}

// SetConfig() does not trigger KerberosFilesChanged if the credential cache
// does not exist.
TEST_F(AccountManagerTest, SetConfigDoesNotTriggerKFCIfDoesNotCCExist) {
  EXPECT_EQ(ERROR_NONE, AddAccount());

  EXPECT_EQ(ERROR_NONE, SetConfig());
  EXPECT_EQ(0, kerberos_files_changed_count_[kUser]);
}

// RemoveAccount() removes the config file.
TEST_F(AccountManagerTest, RemoveAccountRemovesConfig) {
  EXPECT_EQ(ERROR_NONE, AddAccount());
  EXPECT_EQ(ERROR_NONE, SetConfig());

  EXPECT_TRUE(base::PathExists(krb5conf_path_));
  EXPECT_EQ(ERROR_NONE, manager_->RemoveAccount(kUser));
  EXPECT_FALSE(base::PathExists(krb5conf_path_));
}

// ValidateConfig() validates a good config successfully.
TEST_F(AccountManagerTest, ValidateConfigSuccess) {
  constexpr char kValidKrb5Conf[] = "";
  ConfigErrorInfo error_info;
  EXPECT_EQ(ERROR_NONE, manager_->ValidateConfig(kValidKrb5Conf, &error_info));
  EXPECT_EQ(CONFIG_ERROR_NONE, error_info.code());
}

// ValidateConfig() returns the correct error for a bad config.
TEST_F(AccountManagerTest, ValidateConfigFailure) {
  ConfigErrorInfo expected_error_info;
  expected_error_info.set_code(CONFIG_ERROR_SECTION_SYNTAX);
  krb5_->set_config_error_info(expected_error_info);
  krb5_->set_validate_config_error(ERROR_BAD_CONFIG);

  constexpr char kBadKrb5Conf[] =
      "[libdefaults]'); DROP TABLE KerberosTickets;--";
  ConfigErrorInfo error_info;
  EXPECT_EQ(ERROR_BAD_CONFIG,
            manager_->ValidateConfig(kBadKrb5Conf, &error_info));
  EXPECT_EQ(expected_error_info.SerializeAsString(),
            error_info.SerializeAsString());
}

// AcquireTgt() succeeds and writes a credential cache file.
TEST_F(AccountManagerTest, AcquireTgtSuccess) {
  EXPECT_EQ(ERROR_NONE, AddAccount());

  EXPECT_EQ(ERROR_NONE, AcquireTgt());
  EXPECT_TRUE(base::PathExists(krb5cc_path_));
}

// AcquireTgt() triggers KerberosFilesChanged on success.
TEST_F(AccountManagerTest, AcquireTgtTriggersKFCOnSuccess) {
  EXPECT_EQ(ERROR_NONE, AddAccount());

  EXPECT_EQ(0, kerberos_files_changed_count_[kUser]);
  EXPECT_EQ(ERROR_NONE, AcquireTgt());
  EXPECT_EQ(1, kerberos_files_changed_count_[kUser]);
}

// AcquireTgt() does not trigger KerberosFilesChanged on failure.
TEST_F(AccountManagerTest, AcquireTgtDoesNotTriggerKFCOnFailure) {
  EXPECT_EQ(ERROR_NONE, AddAccount());

  krb5_->set_acquire_tgt_error(ERROR_UNKNOWN);
  EXPECT_EQ(ERROR_UNKNOWN, AcquireTgt());
  EXPECT_EQ(0, kerberos_files_changed_count_[kUser]);
}

// AcquireTgt() saves password to disk if |remember_password| is true and
// removes the file again if |remember_password| is false.
TEST_F(AccountManagerTest, AcquireTgtRemembersPasswordsIfWanted) {
  EXPECT_EQ(ERROR_NONE, AddAccount());

  EXPECT_FALSE(base::PathExists(password_path_));
  EXPECT_EQ(ERROR_NONE,
            manager_->AcquireTgt(kUser, kPassword, kRememberPassword,
                                 kDontUseLoginPassword));
  EXPECT_TRUE(base::PathExists(password_path_));

  EXPECT_EQ(ERROR_NONE,
            manager_->AcquireTgt(kUser, kPassword, kDontRememberPassword,
                                 kDontUseLoginPassword));
  EXPECT_FALSE(base::PathExists(password_path_));
}

// AcquireTgt() uses saved password if none is given, no matter if it should be
// remembered again or not.
TEST_F(AccountManagerTest, AcquireTgtLoadsRememberedPassword) {
  EXPECT_EQ(ERROR_NONE, AddAccount());
  EXPECT_EQ(ERROR_NONE,
            manager_->AcquireTgt(kUser, kPassword, kRememberPassword,
                                 kDontUseLoginPassword));

  // This should load stored password and keep it.
  EXPECT_EQ(ERROR_NONE,
            manager_->AcquireTgt(kUser, kEmptyPassword, kRememberPassword,
                                 kDontUseLoginPassword));
  EXPECT_TRUE(base::PathExists(password_path_));

  // This should load stored password, but erase it afterwards.
  EXPECT_EQ(ERROR_NONE,
            manager_->AcquireTgt(kUser, kEmptyPassword, kDontRememberPassword,
                                 kDontUseLoginPassword));
  EXPECT_FALSE(base::PathExists(password_path_));

  // Check that the fake krb5 interface returns an error for a missing password.
  // This verifies that the above AcquireTgt() call actually loaded the
  // password from disk.
  EXPECT_EQ(ERROR_BAD_PASSWORD,
            manager_->AcquireTgt(kUser, kEmptyPassword, kDontRememberPassword,
                                 kDontUseLoginPassword));
}

// AcquireTgt() uses the login password if saved.
TEST_F(AccountManagerTest, AcquireTgtUsesLoginPassword) {
  EXPECT_EQ(ERROR_NONE, AddAccount());

  // Shouldn't explode if the login password not set yet.
  EXPECT_EQ(ERROR_BAD_PASSWORD,
            manager_->AcquireTgt(kUser, kEmptyPassword, kDontRememberPassword,
                                 kUseLoginPassword));

  SaveLoginPassword(kPassword);
  krb5_->set_expected_password(kPassword);

  // Uses the login password.
  EXPECT_EQ(ERROR_NONE,
            manager_->AcquireTgt(kUser, kEmptyPassword, kDontRememberPassword,
                                 kUseLoginPassword));

  // Check if auth fails without kUseLoginPassword.
  EXPECT_EQ(ERROR_BAD_PASSWORD,
            manager_->AcquireTgt(kUser, kEmptyPassword, kDontRememberPassword,
                                 kDontUseLoginPassword));
}

// AcquireTgt() wipes a saved password if the login password is used.
TEST_F(AccountManagerTest, AcquireTgtWipesStoredPasswordOnUsesLoginPassword) {
  EXPECT_EQ(ERROR_NONE, AddAccount());
  EXPECT_EQ(ERROR_NONE,
            manager_->AcquireTgt(kUser, kPassword, kRememberPassword,
                                 kDontUseLoginPassword));
  EXPECT_TRUE(base::PathExists(password_path_));

  SaveLoginPassword(kPassword);

  // Note: kRememberPassword gets ignored if kUseLoginPassword is passed.
  EXPECT_EQ(ERROR_NONE,
            manager_->AcquireTgt(kUser, kEmptyPassword, kRememberPassword,
                                 kUseLoginPassword));
  EXPECT_FALSE(base::PathExists(password_path_));
}

// AcquireTgt() ignores the passed password if the login password is used.
TEST_F(AccountManagerTest, AcquireTgtIgnoresPassedPasswordOnUsesLoginPassword) {
  EXPECT_EQ(ERROR_NONE, AddAccount());

  SaveLoginPassword(kPassword);
  krb5_->set_expected_password(kPassword);

  // Auth works despite passed kPassword2 != expected kPassword because the
  // login kPassword is used.
  EXPECT_EQ(ERROR_NONE,
            manager_->AcquireTgt(kUser, kPassword2, kDontRememberPassword,
                                 kUseLoginPassword));
}

// AcquireTgt() records all encryption types UMA stats on success.
TEST_F(AccountManagerTest, AcquireTgtEnctypesMetricsAll) {
  EXPECT_EQ(ERROR_NONE, AddAccount());
  EXPECT_EQ(ERROR_NONE, SetConfig());

  // The expected encryption type should be reported through |metric_|.
  EXPECT_CALL(*metrics_,
              ReportKerberosEncryptionTypes(KerberosEncryptionTypes::kAll));

  EXPECT_EQ(ERROR_NONE, AcquireTgt());
}

// AcquireTgt() records strong encryption types UMA stats on success.
TEST_F(AccountManagerTest, AcquireTgtEnctypesMetricsStrong) {
  EXPECT_EQ(ERROR_NONE, AddAccount());
  EXPECT_EQ(ERROR_NONE, SetConfig(kStrongKrb5Conf));

  // The expected encryption type should be reported through |metric_|.
  EXPECT_CALL(*metrics_,
              ReportKerberosEncryptionTypes(KerberosEncryptionTypes::kStrong));

  EXPECT_EQ(ERROR_NONE, AcquireTgt());
}

// AcquireTgt() records legacy encryption types UMA stats on success.
TEST_F(AccountManagerTest, AcquireTgtEnctypesMetricsLegacy) {
  EXPECT_EQ(ERROR_NONE, AddAccount());
  EXPECT_EQ(ERROR_NONE, SetConfig(kLegacyKrb5Conf));

  // The expected encryption type should be reported through |metric_|.
  EXPECT_CALL(*metrics_,
              ReportKerberosEncryptionTypes(KerberosEncryptionTypes::kLegacy));

  EXPECT_EQ(ERROR_NONE, AcquireTgt());
}

// AcquireTgt() doesn't record encryption types UMA stats on failure.
TEST_F(AccountManagerTest, AcquireTgtEnctypesMetricsFailure) {
  EXPECT_EQ(ERROR_NONE, AddAccount());
  EXPECT_EQ(ERROR_NONE, SetConfig());

  // No encryption type should be reported through |metric_|.
  EXPECT_CALL(*metrics_, ReportKerberosEncryptionTypes(_)).Times(0);

  krb5_->set_acquire_tgt_error(ERROR_UNKNOWN);
  EXPECT_EQ(ERROR_UNKNOWN, AcquireTgt());
}

// AcquireTgt() doesn't record encryption types UMA stats if no config is
// available.
TEST_F(AccountManagerTest, AcquireTgtEnctypesMetricsNoConfig) {
  EXPECT_EQ(ERROR_NONE, AddAccount());

  // No encryption type should be reported through |metric_|.
  EXPECT_CALL(*metrics_, ReportKerberosEncryptionTypes(_)).Times(0);

  EXPECT_EQ(ERROR_NONE, AcquireTgt());
}

// AcquireTgt() doesn't record encryption types UMA stats if config is invalid.
TEST_F(AccountManagerTest, AcquireTgtEnctypesMetricsInvalidConfig) {
  EXPECT_EQ(ERROR_NONE, AddAccount());
  EXPECT_EQ(ERROR_NONE, SetConfig(kInvalidKrb5Conf));

  // No encryption type should be reported through |metric_|.
  EXPECT_CALL(*metrics_, ReportKerberosEncryptionTypes(_)).Times(0);

  EXPECT_EQ(ERROR_NONE, AcquireTgt());
}

// RemoveAccount() removes the credential cache file.
TEST_F(AccountManagerTest, RemoveAccountRemovesCC) {
  EXPECT_EQ(ERROR_NONE, AddAccount());
  EXPECT_EQ(ERROR_NONE, AcquireTgt());

  EXPECT_TRUE(base::PathExists(krb5cc_path_));
  EXPECT_EQ(ERROR_NONE, manager_->RemoveAccount(kUser));
  EXPECT_FALSE(base::PathExists(krb5cc_path_));
}

// RemoveAccount() removes saved passwords.
TEST_F(AccountManagerTest, RemoveAccountRemovesPassword) {
  EXPECT_EQ(ERROR_NONE, AddAccount());
  EXPECT_EQ(ERROR_NONE,
            manager_->AcquireTgt(kUser, kPassword, kRememberPassword,
                                 kDontUseLoginPassword));

  EXPECT_TRUE(base::PathExists(password_path_));
  EXPECT_EQ(ERROR_NONE, manager_->RemoveAccount(kUser));
  EXPECT_FALSE(base::PathExists(password_path_));
}

// ListAccounts() succeeds and contains the expected data.
TEST_F(AccountManagerTest, ListAccountsSuccess) {
  EXPECT_EQ(ERROR_NONE, manager_->AddAccount(kUser, kManaged));
  EXPECT_EQ(ERROR_NONE, SetConfig());
  EXPECT_EQ(ERROR_NONE,
            manager_->AcquireTgt(kUser, kPassword, kRememberPassword,
                                 kDontUseLoginPassword));
  EXPECT_TRUE(base::PathExists(krb5cc_path_));

  SaveLoginPassword(kPassword);
  EXPECT_EQ(ERROR_NONE, manager_->AddAccount(kUser2, kUnmanaged));
  // Note: kRememberPassword should be ignored here, see below.
  EXPECT_EQ(ERROR_NONE,
            manager_->AcquireTgt(kUser2, kPassword, kRememberPassword,
                                 kUseLoginPassword));

  // Set a fake tgt status.
  constexpr int kRenewalSeconds = 10;
  constexpr int kValiditySeconds = 90;
  krb5_->set_tgt_status(
      Krb5Interface::TgtStatus(kValiditySeconds, kRenewalSeconds));

  // Verify that ListAccounts returns the expected accounts.
  std::vector<Account> accounts = manager_->ListAccounts();
  ASSERT_EQ(2u, accounts.size());

  EXPECT_EQ(kUser, accounts[0].principal_name());
  EXPECT_EQ(kKrb5Conf, accounts[0].krb5conf());
  EXPECT_EQ(kRenewalSeconds, accounts[0].tgt_renewal_seconds());
  EXPECT_EQ(kValiditySeconds, accounts[0].tgt_validity_seconds());
  EXPECT_TRUE(accounts[0].is_managed());
  EXPECT_TRUE(accounts[0].password_was_remembered());
  EXPECT_FALSE(accounts[0].use_login_password());

  EXPECT_EQ(kUser2, accounts[1].principal_name());
  EXPECT_FALSE(accounts[1].has_krb5conf());
  EXPECT_FALSE(accounts[1].is_managed());
  EXPECT_FALSE(accounts[1].password_was_remembered());
  EXPECT_TRUE(accounts[1].use_login_password());
}

// ListAccounts() ignores failures in GetTgtStatus() and loading the config.
TEST_F(AccountManagerTest, ListAccountsIgnoresFailures) {
  EXPECT_EQ(ERROR_NONE, AddAccount());
  EXPECT_EQ(ERROR_NONE, SetConfig());
  EXPECT_EQ(ERROR_NONE, AcquireTgt());
  EXPECT_TRUE(base::PathExists(krb5cc_path_));

  // Make reading the config fail.
  EXPECT_TRUE(base::SetPosixFilePermissions(krb5conf_path_, 0));

  // Make GetTgtStatus() fail.
  krb5_->set_get_tgt_status_error(ERROR_UNKNOWN);

  // ListAccounts() should still work, despite the errors.
  std::vector<Account> accounts = manager_->ListAccounts();
  ASSERT_EQ(1u, accounts.size());
  EXPECT_EQ(kUser, accounts[0].principal_name());

  // The config should not be set since we made reading the file fail.
  EXPECT_FALSE(accounts[0].has_krb5conf());

  // tgt_*_seconds should not be set since we made GetTgtStatus() fail.
  EXPECT_FALSE(accounts[0].has_tgt_renewal_seconds());
  EXPECT_FALSE(accounts[0].has_tgt_validity_seconds());
}

// GetKerberosFiles returns empty KerberosFiles if there is no credential cache,
// even if there is a config.
TEST_F(AccountManagerTest, GetKerberosFilesSucceedsWithoutCC) {
  EXPECT_EQ(ERROR_NONE, AddAccount());
  EXPECT_EQ(ERROR_NONE, SetConfig());

  KerberosFiles files;
  EXPECT_EQ(ERROR_NONE, manager_->GetKerberosFiles(kUser, &files));
  EXPECT_FALSE(files.has_krb5cc());
  EXPECT_FALSE(files.has_krb5conf());
}

// GetKerberosFiles returns the expected KerberosFiles if there is a credential
// cache.
TEST_F(AccountManagerTest, GetKerberosFilesSucceedsWithCC) {
  EXPECT_EQ(ERROR_NONE, AddAccount());
  EXPECT_EQ(ERROR_NONE, SetConfig());
  EXPECT_EQ(ERROR_NONE, AcquireTgt());

  KerberosFiles files;
  EXPECT_EQ(ERROR_NONE, manager_->GetKerberosFiles(kUser, &files));
  EXPECT_FALSE(files.krb5cc().empty());
  EXPECT_EQ(kKrb5Conf, files.krb5conf());
}

// Most methods return ERROR_UNKNOWN_PRINCIPAL if called with such a principal.
TEST_F(AccountManagerTest, MethodsReturnUnknownPrincipal) {
  KerberosFiles files;
  EXPECT_EQ(ERROR_UNKNOWN_PRINCIPAL_NAME, manager_->RemoveAccount(kUser));
  EXPECT_EQ(ERROR_UNKNOWN_PRINCIPAL_NAME, SetConfig());
  EXPECT_EQ(ERROR_UNKNOWN_PRINCIPAL_NAME, AcquireTgt());
  EXPECT_EQ(ERROR_UNKNOWN_PRINCIPAL_NAME,
            manager_->GetKerberosFiles(kUser, &files));
}

// Accounts can be saved to disk and loaded from disk.
TEST_F(AccountManagerTest, SerializationSuccess) {
  SaveLoginPassword(kPassword);
  EXPECT_EQ(ERROR_NONE, manager_->AddAccount(kUser, kManaged));
  EXPECT_EQ(ERROR_NONE, SetConfig(kKrb5Conf));
  EXPECT_EQ(ERROR_NONE,
            manager_->AcquireTgt(kUser, kPassword, kDontRememberPassword,
                                 kUseLoginPassword));

  EXPECT_EQ(ERROR_NONE, manager_->AddAccount(kUser2, kUnmanaged));
  EXPECT_EQ(ERROR_NONE, manager_->SetConfig(kUser2, kStrongKrb5Conf));
  EXPECT_EQ(ERROR_NONE,
            manager_->AcquireTgt(kUser2, kPassword, kRememberPassword,
                                 kDontUseLoginPassword));

  EXPECT_EQ(ERROR_NONE, manager_->SaveAccounts());
  AccountManager other_manager(
      storage_dir_.GetPath(), kerberos_files_changed_,
      kerberos_ticket_expiring_, std::make_unique<FakeKrb5Interface>(),
      std::make_unique<password_provider::FakePasswordProvider>(),
      metrics_.get());
  other_manager.LoadAccounts();
  std::vector<Account> accounts = other_manager.ListAccounts();
  ASSERT_EQ(2u, accounts.size());

  EXPECT_EQ(kUser, accounts[0].principal_name());
  EXPECT_EQ(kUser2, accounts[1].principal_name());

  EXPECT_TRUE(accounts[0].is_managed());
  EXPECT_FALSE(accounts[1].is_managed());

  EXPECT_TRUE(accounts[0].use_login_password());
  EXPECT_FALSE(accounts[1].use_login_password());

  EXPECT_EQ(kKrb5Conf, accounts[0].krb5conf());
  EXPECT_EQ(kStrongKrb5Conf, accounts[1].krb5conf());

  EXPECT_FALSE(accounts[0].password_was_remembered());
  EXPECT_TRUE(accounts[1].password_was_remembered());
}

// The StartObservingTickets() method triggers KerberosTicketExpiring for
// expired signals and starts observing valid tickets.
TEST_F(AccountManagerTest, StartObservingTickets) {
  krb5_->set_tgt_status(kValidTgt);
  EXPECT_EQ(ERROR_NONE, AddAccount());
  EXPECT_EQ(ERROR_NONE, SetConfig());
  EXPECT_EQ(ERROR_NONE, AcquireTgt());
  EXPECT_EQ(0, kerberos_ticket_expiring_count_[kUser]);
  task_runner_->ClearPendingTasks();

  // Fake an expired ticket. Check that KerberosTicketExpiring is triggered, but
  // no renewal task is scheduled.
  krb5_->set_tgt_status(kExpiredTgt);
  manager_->StartObservingTickets();
  EXPECT_EQ(1, kerberos_ticket_expiring_count_[kUser]);
  EXPECT_EQ(0, task_runner_->GetPendingTaskCount());

  // Fake a valid ticket. Check that KerberosTicketExpiring is NOT triggered,
  // but a renewal task is scheduled.
  krb5_->set_tgt_status(kValidTgt);
  EXPECT_EQ(0, task_runner_->GetPendingTaskCount());
  manager_->StartObservingTickets();
  EXPECT_EQ(1, task_runner_->GetPendingTaskCount());
  EXPECT_EQ(1, kerberos_ticket_expiring_count_[kUser]);
  EXPECT_EQ(0, krb5_->renew_tgt_call_count());
  task_runner_->FastForwardBy(task_runner_->NextPendingTaskDelay());
  EXPECT_EQ(1, krb5_->renew_tgt_call_count());
}

// When a TGT is acquired successfully, automatic renewal is scheduled.
TEST_F(AccountManagerTest, AcquireTgtSchedulesRenewalOnSuccess) {
  EXPECT_EQ(ERROR_NONE, AddAccount());

  krb5_->set_tgt_status(kValidTgt);
  EXPECT_EQ(0, task_runner_->GetPendingTaskCount());
  EXPECT_EQ(ERROR_NONE, AcquireTgt());
  EXPECT_EQ(1, task_runner_->GetPendingTaskCount());
}

// When a TGT fails to be acquired, no automatic renewal is scheduled.
TEST_F(AccountManagerTest, AcquireTgtDoesNotScheduleRenewalOnFailure) {
  EXPECT_EQ(ERROR_NONE, AddAccount());

  krb5_->set_tgt_status(kValidTgt);
  krb5_->set_acquire_tgt_error(ERROR_UNKNOWN);
  EXPECT_EQ(0, task_runner_->GetPendingTaskCount());
  EXPECT_EQ(ERROR_UNKNOWN, AcquireTgt());
  EXPECT_EQ(0, task_runner_->GetPendingTaskCount());
}

// A scheduled TGT renewal task calls |krb5_->RenewTgt()|.
TEST_F(AccountManagerTest, AutoRenewalCallsRenewTgt) {
  krb5_->set_tgt_status(kValidTgt);
  EXPECT_EQ(ERROR_NONE, AddAccount());
  EXPECT_EQ(ERROR_NONE, AcquireTgt());
  int initial_acquire_tgt_call_count = krb5_->acquire_tgt_call_count();

  // Set some return value for the RenewTgt() call and fast forward to scheduled
  // renewal task.
  const ErrorType expected_error = ERROR_UNKNOWN;
  krb5_->set_renew_tgt_error(expected_error);
  RunScheduledRenewalTask();

  EXPECT_EQ(initial_acquire_tgt_call_count, krb5_->acquire_tgt_call_count());
  EXPECT_EQ(expected_error, manager_->last_renew_tgt_error_for_testing());
}

// A scheduled TGT renewal task calls |krb5_->AcquireTgt()| using the login
// password if the call to |krb5_->RenewTgt()| fails and the login password was
// used for the initial AcquireTgt() call.
TEST_F(AccountManagerTest, AutoRenewalUsesLoginPasswordIfRenewalFails) {
  krb5_->set_tgt_status(kValidTgt);
  EXPECT_EQ(ERROR_NONE, AddAccount());

  // Acquire TGT with login password.
  SaveLoginPassword(kPassword);
  krb5_->set_expected_password(kPassword);
  EXPECT_EQ(ERROR_NONE,
            manager_->AcquireTgt(kUser, std::string(), kDontRememberPassword,
                                 kUseLoginPassword));
  int initial_acquire_tgt_call_count = krb5_->acquire_tgt_call_count();

  krb5_->set_renew_tgt_error(ERROR_UNKNOWN);
  RunScheduledRenewalTask();

  // The scheduled renewal task should have called AcquireTgt() with the login
  // password and succeeded.
  EXPECT_EQ(initial_acquire_tgt_call_count + 1,
            krb5_->acquire_tgt_call_count());
  EXPECT_EQ(ERROR_NONE, manager_->last_renew_tgt_error_for_testing());
}

// A scheduled TGT renewal task calls |krb5_->AcquireTgt()| using the remembered
// password if the call to |krb5_->RenewTgt()| fails and the password was
// remembered for the initial AcquireTgt() call.
TEST_F(AccountManagerTest, AutoRenewalUsesRememberedPasswordIfRenewalFails) {
  krb5_->set_tgt_status(kValidTgt);
  EXPECT_EQ(ERROR_NONE, AddAccount());

  // Acquire TGT and remember password.
  krb5_->set_expected_password(kPassword);
  EXPECT_EQ(ERROR_NONE,
            manager_->AcquireTgt(kUser, kPassword, kRememberPassword,
                                 kDontUseLoginPassword));
  int initial_acquire_tgt_call_count = krb5_->acquire_tgt_call_count();

  krb5_->set_renew_tgt_error(ERROR_UNKNOWN);
  RunScheduledRenewalTask();

  // The scheduled renewal task should have called AcquireTgt() with the
  // remembered password and succeeded.
  EXPECT_EQ(initial_acquire_tgt_call_count + 1,
            krb5_->acquire_tgt_call_count());
  EXPECT_EQ(ERROR_NONE, manager_->last_renew_tgt_error_for_testing());
}

// A scheduled TGT renewal task does not call |krb5_->AcquireTgt()| using the
// remembered password if the call to |krb5_->RenewTgt()| succeeds and the
// password was remembered for the initial AcquireTgt() call (similar for login
// password, but we don't test that).
TEST_F(AccountManagerTest, AutoRenewalDoesNotCallAcquireTgtIfRenewalSucceeds) {
  krb5_->set_tgt_status(kValidTgt);
  EXPECT_EQ(ERROR_NONE, AddAccount());

  // Acquire TGT and remember password.
  krb5_->set_expected_password(kPassword);
  EXPECT_EQ(ERROR_NONE,
            manager_->AcquireTgt(kUser, kPassword, kRememberPassword,
                                 kDontUseLoginPassword));
  int initial_acquire_tgt_call_count = krb5_->acquire_tgt_call_count();

  krb5_->set_renew_tgt_error(ERROR_NONE);
  RunScheduledRenewalTask();

  // The scheduled renewal task should NOT have called AcquireTgt() again since
  // |krb5_->RenewTgt()|.
  EXPECT_EQ(initial_acquire_tgt_call_count, krb5_->acquire_tgt_call_count());
  EXPECT_EQ(ERROR_NONE, manager_->last_renew_tgt_error_for_testing());
}

// Verifies that all files written have the expected access permissions.
// Unfortunately, file ownership can't be tested as the test won't run as
// kerberosd user nor can it switch to it.
TEST_F(AccountManagerTest, FilePermissions) {
  constexpr int kFileMode_rw =
      base::FILE_PERMISSION_READ_BY_USER | base::FILE_PERMISSION_WRITE_BY_USER;
  constexpr int kFileMode_rw_r =
      kFileMode_rw | base::FILE_PERMISSION_READ_BY_GROUP;
  constexpr int kFileMode_rw_r__r =
      kFileMode_rw_r | base::FILE_PERMISSION_READ_BY_OTHERS;
  constexpr int kFileMode_rwxrwx =
      base::FILE_PERMISSION_USER_MASK | base::FILE_PERMISSION_GROUP_MASK;

  // Wrap the fake krb5 in a jail wrapper to get the file permissions of krb5cc
  // right. Note that we can't use a Krb5JailWrapper for the whole test since
  // that would break the counters in FakeKrb5Interface (they would be inc'ed in
  // another process!).
  manager_->WrapKrb5ForTesting();

  // Can't set user in this test.
  Krb5JailWrapper::DisableChangeUserForTesting(true);

  EXPECT_EQ(ERROR_NONE, AddAccount());
  EXPECT_EQ(ERROR_NONE, SetConfig());
  EXPECT_EQ(ERROR_NONE,
            manager_->AcquireTgt(kUser, kPassword, kRememberPassword,
                                 kDontUseLoginPassword));

  int mode;

  EXPECT_TRUE(GetPosixFilePermissions(accounts_path_, &mode));
  EXPECT_EQ(kFileMode_rw, mode);

  EXPECT_TRUE(GetPosixFilePermissions(account_dir_, &mode));
  EXPECT_EQ(kFileMode_rwxrwx, mode);

  EXPECT_TRUE(GetPosixFilePermissions(krb5cc_path_, &mode));
  EXPECT_EQ(kFileMode_rw_r, mode);

  EXPECT_TRUE(GetPosixFilePermissions(krb5conf_path_, &mode));
  EXPECT_EQ(kFileMode_rw_r__r, mode);

  EXPECT_TRUE(GetPosixFilePermissions(password_path_, &mode));
  EXPECT_EQ(kFileMode_rw, mode);
}

// Tests that [Should]ReportDailyUsageStats is called as advertised.
TEST_F(AccountManagerTest, ReportDailyUsageStats) {
  // ShouldReportDailyUsageStats() should be called by GetKerberosFiles() even
  // if there is no account, and if that returns true, ReportDailyUsageStats()
  // should be called as well.
  EXPECT_CALL(*metrics_, ShouldReportDailyUsageStats()).WillOnce(Return(true));
  EXPECT_CALL(*metrics_, ReportDailyUsageStats(0, 0, 0, 0, 0));
  KerberosFiles files;
  EXPECT_EQ(ERROR_UNKNOWN_PRINCIPAL_NAME,
            manager_->GetKerberosFiles(kUser, &files));
  Mock::VerifyAndClearExpectations(metrics_.get());

  AddAccount();

  // ShouldReportDailyUsageStats() should be called by AcquireTgt(), but if that
  // returns false, ReportDailyUsageStats() should NOT be called.
  EXPECT_CALL(*metrics_, ShouldReportDailyUsageStats()).WillOnce(Return(false));
  EXPECT_CALL(*metrics_, ReportDailyUsageStats(_, _, _, _, _)).Times(0);
  AcquireTgt();
  Mock::VerifyAndClearExpectations(metrics_.get());

  // ShouldReportDailyUsageStats() should be called by AcquireTgt(), and if that
  // returns true, ReportDailyUsageStats() should be called as well.
  EXPECT_CALL(*metrics_, ShouldReportDailyUsageStats()).WillOnce(Return(true));
  EXPECT_CALL(*metrics_, ReportDailyUsageStats(_, _, _, _, _));
  AcquireTgt();
  Mock::VerifyAndClearExpectations(metrics_.get());
}

TEST_F(AccountManagerTest, AccountStats) {
  SaveLoginPassword(kPassword);

  EXPECT_EQ(ERROR_NONE, manager_->AddAccount(kUser, kManaged));
  EXPECT_EQ(ERROR_NONE, manager_->AddAccount(kUser2, kManaged));
  EXPECT_EQ(ERROR_NONE, manager_->AddAccount(kUser3, kUnmanaged));

  // Set metrics up so that the stats are reported on the last call.
  EXPECT_CALL(*metrics_, ShouldReportDailyUsageStats())
      .WillOnce(Return(false))
      .WillOnce(Return(false))
      .WillOnce(Return(true));

  // 3 accounts total, 2 managed, 1 unmanaged, 1 remembering the password, 1
  // using the login password.
  EXPECT_CALL(*metrics_, ReportDailyUsageStats(3, 2, 1, 1, 1));

  EXPECT_EQ(ERROR_NONE,
            manager_->AcquireTgt(kUser, kPassword, kDontRememberPassword,
                                 kDontUseLoginPassword));
  EXPECT_EQ(ERROR_NONE,
            manager_->AcquireTgt(kUser2, kPassword, kRememberPassword,
                                 kDontUseLoginPassword));
  EXPECT_EQ(ERROR_NONE,
            manager_->AcquireTgt(kUser3, kEmptyPassword, kDontRememberPassword,
                                 kUseLoginPassword));
}

}  // namespace kerberos
