// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/dev_mode_unblock_broker.h"

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <chromeos/switches/chrome_switches.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/mock_exported_object.h>
#include <dbus/mock_object_proxy.h>
#include <gmock/gmock.h>
#include <utility>

#include "login_manager/fake_crossystem.h"
#include "login_manager/mock_system_utils.h"
#include "login_manager/mock_vpd_process.h"
#include "login_manager/session_manager_impl.h"
#include "login_manager/system_utils_impl.h"

using testing::_;
using testing::Invoke;
using testing::Return;

ACTION_TEMPLATE(MovePointee,
                HAS_1_TEMPLATE_PARAMS(int, k),
                AND_1_VALUE_PARAMS(pointer)) {
  *pointer = std::move(*(::std::get<k>(args)));
}

namespace {
void UnblockAtInit(brillo::ErrorPtr error) {
  if (!error)
    return;
  const std::string name = error->GetCode();
  const std::string msg = error->GetMessage();
  DVLOG(1) << "DBus Error: " << name;
  DVLOG(1) << "DBus Error Message: " << msg;
}
}  // namespace

namespace login_manager {

class DevModeUnblockBrokerTest : public ::testing::Test {
 public:
  DevModeUnblockBrokerTest()
      : fwmp_proxy_(new dbus::MockObjectProxy(
            nullptr, "", dbus::ObjectPath("/fake/fwmp"))) {
    SetupFs();
  }

  void SetupFs() {
    // Forward file operation calls to |real_utils_| so that the tests can
    // actually create/modify/delete files in |tmpdir_|.
    ON_CALL(utils_, EnsureAndReturnSafeFileSize(_, _))
        .WillByDefault(Invoke(&real_utils_,
                              &SystemUtilsImpl::EnsureAndReturnSafeFileSize));
    ON_CALL(utils_, Exists(_))
        .WillByDefault(Invoke(&real_utils_, &SystemUtilsImpl::Exists));
    ON_CALL(utils_, DirectoryExists(_))
        .WillByDefault(Invoke(&real_utils_, &SystemUtilsImpl::DirectoryExists));
    ON_CALL(utils_, CreateDir(_))
        .WillByDefault(Invoke(&real_utils_, &SystemUtilsImpl::CreateDir));
    ON_CALL(utils_, GetUniqueFilenameInWriteOnlyTempDir(_))
        .WillByDefault(
            Invoke(&real_utils_,
                   &SystemUtilsImpl::GetUniqueFilenameInWriteOnlyTempDir));
    ON_CALL(utils_, RemoveFile(_))
        .WillByDefault(Invoke(&real_utils_, &SystemUtilsImpl::RemoveFile));
    ON_CALL(utils_, AtomicFileWrite(_, _))
        .WillByDefault(Invoke(&real_utils_, &SystemUtilsImpl::AtomicFileWrite));

    ASSERT_TRUE(tmpdir_.CreateUniqueTempDir());
    real_utils_.set_base_dir_for_testing(tmpdir_.GetPath());
  }

  void InitBroker() {
    broker_ = DevModeUnblockBroker::Create(&utils_, &crossystem_, &vpd_process_,
                                           fwmp_proxy_.get());
  }

  // Returns a response for the given method call. Used to implement
  // CallMethodAndBlock() for |mock_proxy_|.
  std::unique_ptr<dbus::Response> CreateMockProxyResponse(
      dbus::MethodCall* method_call, int timeout_ms) {
    return dbus::Response::CreateEmpty();
  }

  void StoreDoWaitForServiceToBeAvailable(
      dbus::ObjectProxy::WaitForServiceToBeAvailableCallback* cb) {
    available_callback_ = std::move(*cb);
  }

  void InvokeServiceAvailableFromStored(bool available = true) {
    std::move(available_callback_).Run(available);
  }

  SystemUtilsImpl real_utils_;
  testing::NiceMock<MockSystemUtils> utils_;
  base::ScopedTempDir tmpdir_;
  FakeCrossystem crossystem_;
  MockVpdProcess vpd_process_;
  scoped_refptr<dbus::MockObjectProxy> fwmp_proxy_;
  dbus::ObjectProxy::WaitForServiceToBeAvailableCallback available_callback_;
  std::unique_ptr<DevModeUnblockBroker> broker_;
};

// Verify that broker does not wait for unblock from carrier lock module in case
// of non cellular devices.
TEST_F(DevModeUnblockBrokerTest, CheckNoWaitForCarrierLockNonCellularAtInit) {
  InitBroker();
  EXPECT_FALSE(broker_->IsDevModeBlockedForCarrierLock());
}

// Verify that broker wait for unblock from carrier lock module in case
// of cellular devices.
TEST_F(DevModeUnblockBrokerTest, CheckWaitForCarrierLockCellularAtInit) {
  utils_.AtomicFileWrite(
      base::FilePath(DevModeUnblockBroker::kFirmwareVariantPath), "Test_Modem");
  InitBroker();
  EXPECT_TRUE(broker_->IsDevModeBlockedForCarrierLock());
}

// Verify that broker checks persistent configuration at init to determine
// which modules already unblocked the dev mode.
TEST_F(DevModeUnblockBrokerTest, VerifyPersistConfigCheckAtInit) {
  utils_.AtomicFileWrite(
      base::FilePath(DevModeUnblockBroker::kCarrierLockUnblockedFlag), "1");
  utils_.AtomicFileWrite(
      base::FilePath(
          DevModeUnblockBroker::kInitStateDeterminationUnblockedFlag),
      "1");
  utils_.AtomicFileWrite(
      base::FilePath(DevModeUnblockBroker::kEnrollmentUnblockedFlag), "1");
  InitBroker();
  EXPECT_FALSE(broker_->IsDevModeBlockedForCarrierLock());
  EXPECT_FALSE(broker_->IsDevModeBlockedForInitialStateDetermination());
  EXPECT_FALSE(broker_->IsDevModeBlockedForEnrollment());
}

// Verify that broker also updates the persistent configuration when unblock
// is received from the carrier lock module.
TEST_F(DevModeUnblockBrokerTest, VerifyPersistCellularUnblock) {
  InitBroker();
  base::FilePath persist_path(DevModeUnblockBroker::kCarrierLockUnblockedFlag);
  ASSERT_TRUE(utils_.AtomicFileWrite(persist_path, "1"));
  broker_->UnblockDevModeForCarrierLock(base::BindRepeating(&UnblockAtInit));
}

// Verify that broker also updates the persistent configuration when unblock
// is received from the initial state determination module.
TEST_F(DevModeUnblockBrokerTest, VerifyPersistInitStateUnblock) {
  InitBroker();
  base::FilePath persist_path(
      DevModeUnblockBroker::kInitStateDeterminationUnblockedFlag);
  ASSERT_TRUE(utils_.AtomicFileWrite(persist_path, "1"));
  broker_->UnblockDevModeForInitialStateDetermination(
      base::BindRepeating(&UnblockAtInit));
}

// Verify that broker also updates the persistent configuration when unblock
// is received from the initial state determination module.
TEST_F(DevModeUnblockBrokerTest, VerifyPersistEnrollmentUnblock) {
  InitBroker();
  base::FilePath persist_path(DevModeUnblockBroker::kEnrollmentUnblockedFlag);
  ASSERT_TRUE(utils_.AtomicFileWrite(persist_path, "1"));
  broker_->UnblockDevModeForEnrollment(base::BindRepeating(&UnblockAtInit));
}

// Verify that broker can detect dev mode is currently blocked by
// checking FWMP and VPD flags.
TEST_F(DevModeUnblockBrokerTest, DetectBlockedDevMode) {
  utils_.AtomicFileWrite(
      base::FilePath(DevModeUnblockBroker::kFirmwareVariantPath), "Test_Modem");
  EXPECT_CALL(*fwmp_proxy_, DoWaitForServiceToBeAvailable(_))
      .WillOnce(Invoke(
          this, &DevModeUnblockBrokerTest::StoreDoWaitForServiceToBeAvailable));
  crossystem_.VbSetSystemPropertyInt(Crossystem::kBlockDevmode, 1);
  InitBroker();
  InvokeServiceAvailableFromStored();
  EXPECT_TRUE(broker_->IsDevModeBlockedForCarrierLock());
  EXPECT_TRUE(broker_->IsDevModeBlockedForInitialStateDetermination());
  EXPECT_TRUE(broker_->IsDevModeBlockedForEnrollment());
}

// Verify that broker can detect dev mode is currently unblocked
TEST_F(DevModeUnblockBrokerTest, DetectUnBlockedDevMode) {
  utils_.AtomicFileWrite(
      base::FilePath(DevModeUnblockBroker::kFirmwareVariantPath), "Test_Modem");
  EXPECT_CALL(*fwmp_proxy_, DoWaitForServiceToBeAvailable(_))
      .WillOnce(Invoke(
          this, &DevModeUnblockBrokerTest::StoreDoWaitForServiceToBeAvailable));
  EXPECT_CALL(*fwmp_proxy_, CallMethodAndBlock(_, _))
      .WillRepeatedly(
          Invoke(this, &DevModeUnblockBrokerTest::CreateMockProxyResponse));
  crossystem_.VbSetSystemPropertyInt(Crossystem::kBlockDevmode, 0);
  InitBroker();
  InvokeServiceAvailableFromStored();
  EXPECT_FALSE(broker_->IsDevModeBlockedForCarrierLock());
  EXPECT_FALSE(broker_->IsDevModeBlockedForInitialStateDetermination());
  EXPECT_FALSE(broker_->IsDevModeBlockedForEnrollment());
}

// Verify that broker unblocks dev mode in FWMP and VPD on receiving
// unblock from all the modules
TEST_F(DevModeUnblockBrokerTest, VerifyFwmpVpdUpdatOneUnblockFromAll) {
  utils_.AtomicFileWrite(
      base::FilePath(DevModeUnblockBroker::kFirmwareVariantPath), "Test_Modem");
  EXPECT_CALL(*fwmp_proxy_, DoWaitForServiceToBeAvailable(_))
      .WillOnce(Invoke(
          this, &DevModeUnblockBrokerTest::StoreDoWaitForServiceToBeAvailable));
  crossystem_.VbSetSystemPropertyInt(Crossystem::kBlockDevmode, 1);
  crossystem_.VbSetSystemPropertyInt(Crossystem::kNvramCleared, 1);
  InitBroker();
  InvokeServiceAvailableFromStored();

  VpdProcess::KeyValuePairs updates{{Crossystem::kBlockDevmode, "0"},
                                    {Crossystem::kCheckEnrollment, "0"}};

  EXPECT_CALL(*fwmp_proxy_, DoWaitForServiceToBeAvailable(_))
      .WillOnce(Invoke(
          this, &DevModeUnblockBrokerTest::StoreDoWaitForServiceToBeAvailable));
  dbus::ObjectProxy::ResponseCallback fwmp_removal_callback;
  EXPECT_CALL(*fwmp_proxy_,
              DoCallMethod(_, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT, _))
      .WillOnce(MovePointee<2>(&fwmp_removal_callback));

  EXPECT_CALL(vpd_process_, RunInBackground(updates, false, _))
      .WillOnce(Return(true));
  broker_->UnblockDevModeForCarrierLock(base::BindRepeating(&UnblockAtInit));
  broker_->UnblockDevModeForInitialStateDetermination(
      base::BindRepeating(&UnblockAtInit));
  broker_->UnblockDevModeForEnrollment(base::BindRepeating(&UnblockAtInit));
  InvokeServiceAvailableFromStored();

  user_data_auth::RemoveFirmwareManagementParametersReply reply;
  std::unique_ptr<dbus::Response> response = dbus::Response::CreateEmpty();
  dbus::MessageWriter writer(response.get());
  writer.AppendProtoAsArrayOfBytes(reply);
  std::move(fwmp_removal_callback).Run(response.get());

  EXPECT_EQ(0, crossystem_.VbGetSystemPropertyInt(Crossystem::kBlockDevmode));
}

// Verify that broker waits on unblock from all the modules before clearing
// block_devmode in FWMP and VPD
TEST_F(DevModeUnblockBrokerTest, VerifyWaitForUnblockFromAll) {
  utils_.AtomicFileWrite(
      base::FilePath(DevModeUnblockBroker::kFirmwareVariantPath), "Test_Modem");
  EXPECT_CALL(*fwmp_proxy_, DoWaitForServiceToBeAvailable(_))
      .WillOnce(Invoke(
          this, &DevModeUnblockBrokerTest::StoreDoWaitForServiceToBeAvailable));
  crossystem_.VbSetSystemPropertyInt(Crossystem::kBlockDevmode, 1);
  InitBroker();
  InvokeServiceAvailableFromStored();
  dbus::ObjectProxy::ResponseCallback fwmp_removal_callback;
  broker_->UnblockDevModeForCarrierLock(base::BindRepeating(&UnblockAtInit));
  EXPECT_EQ(1, crossystem_.VbGetSystemPropertyInt(Crossystem::kBlockDevmode));
}

// Verify that broker detects any previous interrupted unblocking operation and
// retry at init
TEST_F(DevModeUnblockBrokerTest, VerifyRestartInterrupted) {
  utils_.AtomicFileWrite(
      base::FilePath(DevModeUnblockBroker::kCarrierLockUnblockedFlag), "1");
  utils_.AtomicFileWrite(
      base::FilePath(
          DevModeUnblockBroker::kInitStateDeterminationUnblockedFlag),
      "1");
  utils_.AtomicFileWrite(
      base::FilePath(DevModeUnblockBroker::kEnrollmentUnblockedFlag), "1");
  utils_.AtomicFileWrite(
      base::FilePath(DevModeUnblockBroker::kFirmwareVariantPath), "Test_Modem");
  crossystem_.VbSetSystemPropertyInt(Crossystem::kBlockDevmode, 1);
  crossystem_.VbSetSystemPropertyInt(Crossystem::kNvramCleared, 1);

  EXPECT_CALL(*fwmp_proxy_, DoWaitForServiceToBeAvailable(_))
      .WillRepeatedly(Invoke(
          this, &DevModeUnblockBrokerTest::StoreDoWaitForServiceToBeAvailable));
  EXPECT_CALL(*fwmp_proxy_, CallMethodAndBlock(_, _))
      .WillRepeatedly(
          Invoke(this, &DevModeUnblockBrokerTest::CreateMockProxyResponse));
  dbus::ObjectProxy::ResponseCallback fwmp_removal_callback;
  EXPECT_CALL(*fwmp_proxy_,
              DoCallMethod(_, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT, _))
      .WillOnce(MovePointee<2>(&fwmp_removal_callback));
  VpdProcess::KeyValuePairs updates{{Crossystem::kBlockDevmode, "0"},
                                    {Crossystem::kCheckEnrollment, "0"}};
  EXPECT_CALL(vpd_process_, RunInBackground(updates, false, _))
      .WillOnce(Return(true));

  InitBroker();
  InvokeServiceAvailableFromStored();
  InvokeServiceAvailableFromStored();

  user_data_auth::RemoveFirmwareManagementParametersReply reply;
  std::unique_ptr<dbus::Response> response = dbus::Response::CreateEmpty();
  dbus::MessageWriter writer(response.get());
  writer.AppendProtoAsArrayOfBytes(reply);
  std::move(fwmp_removal_callback).Run(response.get());

  EXPECT_EQ(0, crossystem_.VbGetSystemPropertyInt(Crossystem::kBlockDevmode));
}

}  // namespace login_manager
