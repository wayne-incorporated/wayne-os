// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "kerberos/kerberos_adaptor.h"

#include <memory>
#include <utility>

#include <base/check.h>
#include <base/files/scoped_temp_dir.h>
#include <base/memory/ref_counted.h>
#include <base/memory/scoped_refptr.h>
#include <base/test/task_environment.h>
#include <base/run_loop.h>
#include <brillo/asan.h>
#include <dbus/login_manager/dbus-constants.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_exported_object.h>
#include <dbus/mock_object_proxy.h>
#include <dbus/object_path.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "kerberos/account_manager.h"
#include "kerberos/fake_krb5_interface.h"
#include "kerberos/kerberos_metrics.h"
#include "kerberos/krb5_jail_wrapper.h"
#include "kerberos/platform_helper.h"
#include "kerberos/proto_bindings/kerberos_service.pb.h"

using brillo::dbus_utils::DBusObject;
using dbus::MockBus;
using dbus::MockExportedObject;
using dbus::MockObjectProxy;
using dbus::ObjectPath;
using testing::_;
using testing::AnyNumber;
using testing::Invoke;
using testing::Mock;
using testing::NiceMock;
using testing::Return;
using ByteArray = kerberos::KerberosAdaptor::ByteArray;

namespace kerberos {
namespace {

// Some arbitrary D-Bus message serial number. Required for mocking D-Bus calls.
const int kDBusSerial = 123;

// Stub user data.
constexpr char kUser[] = "user";
constexpr char kUserHash[] = "user-hash";
constexpr char kPrincipalName[] = "user@REALM.COM";
constexpr char kOtherPrincipalName[] = "other_user@REALM.COM";
constexpr bool kManaged = true;
constexpr bool kUnmanaged = false;
constexpr char kPassword[] = "hello123";

// Stub D-Bus object path for the mock daemon.
constexpr char kObjectPath[] = "/object/path";

// Real storage base dir.
constexpr char KDaemonStore[] = "/run/daemon-store/kerberosd";

// Empty Kerberos configuration.
constexpr char kEmptyConfig[] = "";

class MockMetrics : public KerberosMetrics {
 public:
  explicit MockMetrics(const base::FilePath& storage_dir)
      : KerberosMetrics(storage_dir) {}
  MockMetrics(const MockMetrics&) = delete;
  MockMetrics& operator=(const MockMetrics&) = delete;

  ~MockMetrics() override = default;

  MOCK_METHOD(void, StartAcquireTgtTimer, (), (override));
  MOCK_METHOD(void, StopAcquireTgtTimerAndReport, (), (override));
  MOCK_METHOD(void,
              ReportValidateConfigErrorCode,
              (ConfigErrorCode),
              (override));
  MOCK_METHOD(void,
              ReportDBusCallResult,
              (const std::string&, ErrorType),
              (override));
  MOCK_METHOD(bool, ShouldReportDailyUsageStats, (), (override));
};

// Stub completion callback for RegisterAsync().
void DoNothing(bool /* unused */) {}

// Serializes |message| as byte array.
ByteArray SerializeAsBlob(const google::protobuf::MessageLite& message) {
  ByteArray result;
  result.resize(message.ByteSizeLong());
  CHECK(message.SerializeToArray(result.data(), result.size()));
  return result;
}

// Parses a response message from a byte array.
template <typename TResponse>
TResponse ParseResponse(const ByteArray& response_blob) {
  TResponse response;
  EXPECT_TRUE(
      response.ParseFromArray(response_blob.data(), response_blob.size()));
  return response;
}

// Stub RetrievePrimarySession Session Manager method.
std::unique_ptr<dbus::Response> StubRetrievePrimarySession(
    dbus::MethodCall* method_call,
    int /* timeout_ms */,
    dbus::ScopedDBusError* /* error */) {
  // Respond with username = kUser and sanitized_username = kUserHash.
  method_call->SetSerial(kDBusSerial);
  auto response = dbus::Response::FromMethodCall(method_call);
  dbus::MessageWriter writer(response.get());
  writer.AppendString(kUser);
  writer.AppendString(kUserHash);

  // Note: The mock wraps this back into a std::unique_ptr.
  return response;
}

}  // namespace

class KerberosAdaptorTest : public ::testing::Test {
 public:
  KerberosAdaptorTest() = default;
  KerberosAdaptorTest(const KerberosAdaptorTest&) = delete;
  KerberosAdaptorTest& operator=(const KerberosAdaptorTest&) = delete;

  ~KerberosAdaptorTest() override = default;

  void SetUp() override {
    ::testing::Test::SetUp();

    mock_bus_ = base::MakeRefCounted<MockBus>(dbus::Bus::Options());

    // Mock out D-Bus initialization.
    const ObjectPath object_path(kObjectPath);
    mock_exported_object_ =
        base::MakeRefCounted<MockExportedObject>(mock_bus_.get(), object_path);
    EXPECT_CALL(*mock_bus_, GetExportedObject(object_path))
        .WillRepeatedly(Return(mock_exported_object_.get()));
    EXPECT_CALL(*mock_exported_object_, Unregister()).Times(AnyNumber());
    EXPECT_CALL(*mock_exported_object_, ExportMethod(_, _, _, _))
        .Times(AnyNumber());
    EXPECT_CALL(*mock_exported_object_, SendSignal(_))
        .WillRepeatedly(
            Invoke(this, &KerberosAdaptorTest::OnKerberosFilesChanged));

    // Create temp directory for files written during tests.
    CHECK(storage_dir_.CreateUniqueTempDir());

    // Create mock metrics.
    auto metrics =
        std::make_unique<NiceMock<MockMetrics>>(storage_dir_.GetPath());
    metrics_ = metrics.get();
    ON_CALL(*metrics_, ShouldReportDailyUsageStats)
        .WillByDefault(Return(false));

    // Create KerberosAdaptor instance. Do this AFTER creating the proxy mocks
    // since they might be accessed during initialization.
    auto dbus_object =
        std::make_unique<DBusObject>(nullptr, mock_bus_, object_path);
    adaptor_ = std::make_unique<KerberosAdaptor>(std::move(dbus_object));
    adaptor_->set_storage_dir_for_testing(storage_dir_.GetPath());
    adaptor_->set_metrics_for_testing(std::move(metrics));
    adaptor_->set_krb5_for_testing(std::make_unique<FakeKrb5Interface>());
    adaptor_->RegisterAsync(base::BindRepeating(&DoNothing));
  }

  void TearDown() override { adaptor_.reset(); }

 protected:
  void OnKerberosFilesChanged(dbus::Signal* signal) {
    EXPECT_EQ(signal->GetInterface(), "org.chromium.Kerberos");
    EXPECT_EQ(signal->GetMember(), "KerberosFilesChanged");
    dbus::MessageReader reader(signal);
    std::string principal_name;
    EXPECT_TRUE(reader.PopString(&principal_name));
    EXPECT_EQ(kPrincipalName, principal_name);
  }

  // Adds an account with given |principal_name| and |is_managed| parameters.
  ErrorType AddAccount(const std::string& principal_name, bool is_managed) {
    AddAccountRequest request;
    request.set_principal_name(principal_name);
    request.set_is_managed(is_managed);
    ByteArray response_blob = adaptor_->AddAccount(SerializeAsBlob(request));
    return ParseResponse<AddAccountResponse>(response_blob).error();
  }

  // Removes the account with |principal_name|.
  RemoveAccountResponse RemoveAccount(const std::string& principal_name) {
    RemoveAccountRequest request;
    request.set_principal_name(principal_name);
    ByteArray response_blob = adaptor_->RemoveAccount(SerializeAsBlob(request));
    return ParseResponse<RemoveAccountResponse>(response_blob);
  }

  // Removes all accounts.
  ClearAccountsResponse ClearAccounts(ClearMode mode) {
    ClearAccountsRequest request;
    request.set_mode(mode);
    ByteArray response_blob = adaptor_->ClearAccounts(SerializeAsBlob(request));
    return ParseResponse<ClearAccountsResponse>(response_blob);
  }

  // Lists accounts.
  ErrorType ListAccounts() {
    ListAccountsRequest request;
    ByteArray response_blob = adaptor_->ListAccounts(SerializeAsBlob(request));
    return ParseResponse<ListAccountsResponse>(response_blob).error();
  }

  // Sets a default config for |principal_name|.
  ErrorType SetConfig(const std::string& principal_name) {
    SetConfigRequest request;
    request.set_principal_name(principal_name);
    request.set_krb5conf(kEmptyConfig);
    ByteArray response_blob = adaptor_->SetConfig(SerializeAsBlob(request));
    return ParseResponse<SetConfigResponse>(response_blob).error();
  }

  // Validates a default config.
  ErrorType ValidateConfig() {
    ValidateConfigRequest request;
    request.set_krb5conf(kEmptyConfig);
    ByteArray response_blob =
        adaptor_->ValidateConfig(SerializeAsBlob(request));
    return ParseResponse<ValidateConfigResponse>(response_blob).error();
  }

  // Acquires a default Kerberos ticket for |principal_name| with default
  // password.
  ErrorType AcquireKerberosTgt(const std::string& principal_name) {
    AcquireKerberosTgtRequest request;
    request.set_principal_name(principal_name);
    ByteArray response_blob = adaptor_->AcquireKerberosTgt(
        SerializeAsBlob(request), WriteStringToPipe(kPassword));
    return ParseResponse<AcquireKerberosTgtResponse>(response_blob).error();
  }

  // Acquires a default Kerberos ticket for |principal_name|.
  ErrorType GetKerberosFiles(const std::string& principal_name) {
    GetKerberosFilesRequest request;
    request.set_principal_name(principal_name);
    ByteArray response_blob =
        adaptor_->GetKerberosFiles(SerializeAsBlob(request));
    return ParseResponse<GetKerberosFilesResponse>(response_blob).error();
  }

  // KEEP ORDER between these. It's important for destruction.
  scoped_refptr<MockBus> mock_bus_;
  scoped_refptr<MockExportedObject> mock_exported_object_;
  std::unique_ptr<KerberosAdaptor> adaptor_;
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY};

  base::ScopedTempDir storage_dir_;

  NiceMock<MockMetrics>* metrics_ = nullptr;
};

// RetrievePrimarySession is called to figure out the proper storage dir if the
// dir is NOT overwritten by KerberosAdaptor::set_storage_dir_for_testing().
TEST_F(KerberosAdaptorTest, RetrievesPrimarySession) {
  // Stub out Session Manager's RetrievePrimarySession D-Bus method.
  auto mock_session_manager_proxy = base::MakeRefCounted<MockObjectProxy>(
      mock_bus_.get(), login_manager::kSessionManagerServiceName,
      dbus::ObjectPath(login_manager::kSessionManagerServicePath));
  EXPECT_CALL(*mock_bus_,
              GetObjectProxy(login_manager::kSessionManagerServiceName, _))
      .WillOnce(Return(mock_session_manager_proxy.get()));
  EXPECT_CALL(*mock_session_manager_proxy,
              CallMethodAndBlockWithErrorDetails(_, _, _))
      .WillOnce(Invoke(&StubRetrievePrimarySession));

  // Recreate an adaptor, but don't call set_storage_dir_for_testing().
  auto dbus_object =
      std::make_unique<DBusObject>(nullptr, mock_bus_, ObjectPath(kObjectPath));
  auto adaptor = std::make_unique<KerberosAdaptor>(std::move(dbus_object));
  adaptor->RegisterAsync(base::BindRepeating(&DoNothing));

  // Check if the right storage dir is set.
  EXPECT_EQ(base::FilePath(KDaemonStore).Append(kUserHash),
            adaptor->GetAccountManagerForTesting()->GetStorageDirForTesting());
}

// AddAccount and RemoveAccount succeed when a new account is added and removed.
TEST_F(KerberosAdaptorTest, AddRemoveAccountSuccess) {
  EXPECT_EQ(ERROR_NONE, AddAccount(kPrincipalName, kUnmanaged));
  EXPECT_EQ(ERROR_NONE, RemoveAccount(kPrincipalName).error());
}

// RemoveAccount succeeds and returns the list of remaining accounts.
TEST_F(KerberosAdaptorTest, RemoveAccountSuccess) {
  EXPECT_EQ(ERROR_NONE, AddAccount(kPrincipalName, kUnmanaged));
  EXPECT_EQ(ERROR_NONE, AddAccount(kOtherPrincipalName, kUnmanaged));

  RemoveAccountResponse response = RemoveAccount(kPrincipalName);
  EXPECT_EQ(ERROR_NONE, response.error());
  ASSERT_EQ(1, response.accounts_size());
  EXPECT_EQ(kOtherPrincipalName, response.accounts(0).principal_name());
  response = RemoveAccount(kOtherPrincipalName);
  EXPECT_EQ(ERROR_NONE, response.error());
  EXPECT_EQ(0, response.accounts_size());
}

// RemoveAccount fails if the account doesn't exist, and returns the list of
// remaining accounts.
TEST_F(KerberosAdaptorTest, RemoveAccountFails) {
  EXPECT_EQ(ERROR_NONE, AddAccount(kPrincipalName, kUnmanaged));

  RemoveAccountResponse response = RemoveAccount(kOtherPrincipalName);
  EXPECT_EQ(ERROR_UNKNOWN_PRINCIPAL_NAME, response.error());
  ASSERT_EQ(1, response.accounts_size());
  EXPECT_EQ(kPrincipalName, response.accounts(0).principal_name());
}

// AddAccount and ClearAccounts succeed when a new account is added and cleared.
TEST_F(KerberosAdaptorTest, AddClearAccountsSuccess) {
  EXPECT_EQ(ERROR_NONE, AddAccount(kPrincipalName, kUnmanaged));
  EXPECT_EQ(ERROR_NONE, ClearAccounts(CLEAR_ALL).error());
}

// ClearAccounts succeeds to clear all accounts and returns the list of
// remaining accounts.
TEST_F(KerberosAdaptorTest, ClearAccountsSuccessClearAll) {
  EXPECT_EQ(ERROR_NONE, AddAccount(kPrincipalName, kUnmanaged));
  EXPECT_EQ(ERROR_NONE, AddAccount(kOtherPrincipalName, kUnmanaged));

  ClearAccountsResponse response = ClearAccounts(CLEAR_ALL);
  EXPECT_EQ(ERROR_NONE, response.error());
  EXPECT_EQ(0, response.accounts_size());
}

// ClearAccounts succeeds to clear managed accounts and returns the list of
// remaining accounts.
TEST_F(KerberosAdaptorTest, ClearAccountsSuccessClearManaged) {
  EXPECT_EQ(ERROR_NONE, AddAccount(kPrincipalName, kUnmanaged));
  EXPECT_EQ(ERROR_NONE, AddAccount(kOtherPrincipalName, kManaged));

  ClearAccountsResponse response = ClearAccounts(CLEAR_ONLY_MANAGED_ACCOUNTS);
  EXPECT_EQ(ERROR_NONE, response.error());
  ASSERT_EQ(1, response.accounts_size());
  EXPECT_EQ(kPrincipalName, response.accounts(0).principal_name());
}

// ClearAccounts succeeds to clear unmanaged accounts and returns the list of
// remaining accounts.
TEST_F(KerberosAdaptorTest, ClearAccountsSuccessClearUnmanaged) {
  EXPECT_EQ(ERROR_NONE, AddAccount(kPrincipalName, kUnmanaged));
  EXPECT_EQ(ERROR_NONE, AddAccount(kOtherPrincipalName, kManaged));

  ClearAccountsResponse response = ClearAccounts(CLEAR_ONLY_UNMANAGED_ACCOUNTS);
  EXPECT_EQ(ERROR_NONE, response.error());
  ASSERT_EQ(1, response.accounts_size());
  EXPECT_EQ(kOtherPrincipalName, response.accounts(0).principal_name());
}

// ClearAccounts succeeds to clear unmanaged remembered passwords and returns
// the list of remaining accounts.
TEST_F(KerberosAdaptorTest, ClearAccountsSuccessClearUnmanagedPasswords) {
  EXPECT_EQ(ERROR_NONE, AddAccount(kPrincipalName, kUnmanaged));
  EXPECT_EQ(ERROR_NONE, AddAccount(kOtherPrincipalName, kManaged));

  ClearAccountsResponse response =
      ClearAccounts(CLEAR_ONLY_UNMANAGED_REMEMBERED_PASSWORDS);
  EXPECT_EQ(ERROR_NONE, response.error());
  ASSERT_EQ(2, response.accounts_size());
  EXPECT_EQ(kPrincipalName, response.accounts(0).principal_name());
  EXPECT_EQ(kOtherPrincipalName, response.accounts(1).principal_name());
}

// Checks that metrics are reported for all D-Bus calls.
TEST_F(KerberosAdaptorTest, Metrics_ReportDBusCallResult) {
  EXPECT_CALL(*metrics_, ReportDBusCallResult("AddAccount", ERROR_NONE));
  EXPECT_CALL(*metrics_, ReportDBusCallResult("ListAccounts", ERROR_NONE));
  EXPECT_CALL(*metrics_, ReportDBusCallResult("SetConfig", ERROR_NONE));
  EXPECT_CALL(*metrics_, ReportDBusCallResult("ValidateConfig", ERROR_NONE));
  EXPECT_CALL(*metrics_,
              ReportDBusCallResult("AcquireKerberosTgt", ERROR_NONE));
  EXPECT_CALL(*metrics_, ReportDBusCallResult("GetKerberosFiles", ERROR_NONE));
  EXPECT_CALL(*metrics_, ReportDBusCallResult("RemoveAccount", ERROR_NONE));
  EXPECT_CALL(*metrics_, ReportDBusCallResult("ClearAccounts", ERROR_NONE));

  EXPECT_EQ(ERROR_NONE, AddAccount(kPrincipalName, kUnmanaged));
  EXPECT_EQ(ERROR_NONE, ListAccounts());
  EXPECT_EQ(ERROR_NONE, SetConfig(kPrincipalName));
  EXPECT_EQ(ERROR_NONE, ValidateConfig());
  EXPECT_EQ(ERROR_NONE, AcquireKerberosTgt(kPrincipalName));
  EXPECT_EQ(ERROR_NONE, GetKerberosFiles(kPrincipalName));
  EXPECT_EQ(ERROR_NONE, RemoveAccount(kPrincipalName).error());
  EXPECT_EQ(ERROR_NONE, ClearAccounts(CLEAR_ALL).error());
}

// AcquireKerberosTgt should trigger timing events.
TEST_F(KerberosAdaptorTest, Metrics_AcquireTgtTimer) {
  EXPECT_CALL(*metrics_, StartAcquireTgtTimer());
  EXPECT_CALL(*metrics_, StopAcquireTgtTimerAndReport());
  EXPECT_EQ(ERROR_UNKNOWN_PRINCIPAL_NAME, AcquireKerberosTgt(kPrincipalName));
}

// ValidateConfig should trigger timing events.
TEST_F(KerberosAdaptorTest, Metrics_ValidateConfigErrorCode) {
  EXPECT_CALL(*metrics_, ReportValidateConfigErrorCode(CONFIG_ERROR_NONE));
  EXPECT_EQ(ERROR_NONE, AddAccount(kPrincipalName, kUnmanaged));
  EXPECT_EQ(ERROR_NONE, ValidateConfig());
}

// TODO(b/259178130): Add more tests.

}  // namespace kerberos
