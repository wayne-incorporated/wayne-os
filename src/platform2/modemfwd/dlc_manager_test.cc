// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "modemfwd/dlc_manager.h"

#include <list>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/test/mock_callback.h>
#include <base/test/task_environment.h>
#include <dbus/dlcservice/dbus-constants.h>
#include <dbus/mock_object_proxy.h>
#include "dlcservice/dbus-proxy-mocks.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "modemfwd/mock_metrics.h"

using modemfwd::metrics::DlcInstallResult;
using modemfwd::metrics::DlcUninstallResult;
using testing::_;
using testing::DoAll;
using testing::InSequence;
using testing::Invoke;
using testing::InvokeArgument;
using testing::NotNull;
using testing::Return;
using testing::StrictMock;
using testing::WithArg;

using ServiceAvailableCallback =
    dbus::ObjectProxy::WaitForServiceToBeAvailableCallback;

MATCHER_P(EqualsProto,
          message,
          "Match a proto Message equal to the matcher's argument.") {
  std::string expected_serialized, actual_serialized;
  message.SerializeToString(&expected_serialized);
  arg.SerializeToString(&actual_serialized);
  return expected_serialized == actual_serialized;
}

namespace {
constexpr char kDeviceVariant[] = "variant";
constexpr char kOtherVariant1[] = "other_variant1";
constexpr char kOtherVariant2[] = "other_variant2";

constexpr char kDeviceDlc[] = "dlc";
constexpr char kOtherDlc1[] = "other_dlc1";
constexpr char kOtherDlc2[] = "other_dlc2";

constexpr char kDeviceDlcMountPath[] = "/mount/path";

}  // namespace
namespace modemfwd {

class DlcManagerHelper : public DlcManager {
 public:
  explicit DlcManagerHelper(
      Metrics* metrics,
      std::map<std::string, Dlc> dlc_per_variant,
      std::string variant,
      std::unique_ptr<org::chromium::DlcServiceInterfaceProxyInterface> proxy)
      : DlcManager(metrics, dlc_per_variant, variant, std::move(proxy)) {}
};

class DlcManagerTest : public ::testing::Test {
 public:
  DlcManagerTest() {
    mock_dlcservice_proxy_ = std::make_unique<
        StrictMock<org::chromium::DlcServiceInterfaceProxyMock>>();
    mock_dlcservice_proxy_ptr_ = mock_dlcservice_proxy_.get();
    mock_metrics_ = std::make_unique<testing::StrictMock<MockMetrics>>();
  }

  void AddWaitForServiceExpects() {
    EXPECT_CALL(*mock_dlcservice_proxy_ptr_, GetObjectProxy())
        .WillOnce(Return(object_proxy_.get()));
    EXPECT_CALL(*object_proxy_, DoWaitForServiceToBeAvailable(_))
        .WillOnce(
            Invoke(this, &DlcManagerTest::StoreDoWaitForServiceToBeAvailable));
  }

  void StoreDoWaitForServiceToBeAvailable(ServiceAvailableCallback* cb) {
    service_available_ = std::move(*cb);
  }

  void InvokeServiceAvailableFromStored(bool available = true) {
    std::move(service_available_).Run(available);
  }
  // Install
  void StoreInstallAsync(
      dlcservice::InstallRequest install_request,
      base::OnceCallback<void()> success_callback,
      base::OnceCallback<void(brillo::Error*)> error_callback,
      int timeout_ms) {
    ASSERT_TRUE(install_async_success_cb_.is_null() ||
                install_async_error_cb_.is_null());
    install_request_ = install_request;
    install_async_success_cb_ = std::move(success_callback);
    install_async_error_cb_ = std::move(error_callback);
  }

  void InvokeInstallSuccessFromStored() {
    ASSERT_FALSE(install_async_success_cb_.is_null());
    std::move(install_async_success_cb_).Run();
  }

  void InvokeInstallFailureFromStored(std::string error_code) {
    ASSERT_FALSE(install_async_error_cb_.is_null());
    auto err = brillo::Error::Create(FROM_HERE, "domain", error_code, "msg");
    std::move(install_async_error_cb_).Run(err.get());
  }

  // GetDlcState
  void StoreGetDlcStateAsync(
      const std::string dlc_id,
      base::OnceCallback<void(const dlcservice::DlcState&)> success_callback,
      base::OnceCallback<void(brillo::Error*)> error_callback,
      int timeout_ms) {
    ASSERT_TRUE(get_dlc_state_success_cb_.is_null() ||
                get_dlc_state_error_cb_.is_null());
    get_dlc_state_dlc_id_ = dlc_id;
    get_dlc_state_success_cb_ = std::move(success_callback);
    get_dlc_state_error_cb_ = std::move(error_callback);
  }

  void InvokeGetDlcStateSuccessFromStored(dlcservice::DlcState::State state) {
    dlcservice::DlcState dlc_state;
    dlc_state.set_state(state);
    dlc_state.set_root_path(kDeviceDlcMountPath);
    std::move(get_dlc_state_success_cb_).Run(dlc_state);
  }

  void InvokeGetDlcStateSuccessInstalling(
      const std::string dlc_id,
      base::OnceCallback<void(const dlcservice::DlcState&)> success_callback,
      base::OnceCallback<void(brillo::Error*)> error_callback,
      int timeout_ms) {
    dlcservice::DlcState dlc_state;
    dlc_state.set_state(dlcservice::DlcState::INSTALLING);
    std::move(success_callback).Run(dlc_state);
  }

  void InvokeGetDlcStateFailureFromStored(std::string error_code) {
    auto err = brillo::Error::Create(FROM_HERE, "domain", error_code, "msg");
    std::move(get_dlc_state_error_cb_).Run(err.get());
  }

  // GetExistingDlcs
  void StoreGetExistingDlcsAsync(
      base::OnceCallback<void(const dlcservice::DlcsWithContent&)>
          success_callback,
      base::OnceCallback<void(brillo::Error*)> error_callback,
      int timeout_ms) {
    ASSERT_TRUE(get_existing_dlcs_success_cb_.is_null() ||
                get_existing_dlcs_error_cb_.is_null());
    get_existing_dlcs_success_cb_ = std::move(success_callback);
    get_existing_dlcs_error_cb_ = std::move(error_callback);
  }

  void InvokeGetExistingDlcsFromStored(std::list<std::string> dlc_ids) {
    dlcservice::DlcsWithContent dlc_list;
    for (const auto& id : dlc_ids) {
      auto* dlc_info = dlc_list.add_dlc_infos();
      dlc_info->set_id(id);
    }
    std::move(get_existing_dlcs_success_cb_).Run(dlc_list);
  }

  void InvokeGetExistingDlcsFailureFromStored(std::string error_code) {
    auto err = brillo::Error::Create(FROM_HERE, "domain", error_code, "msg");
    std::move(get_existing_dlcs_error_cb_).Run(err.get());
  }

  // Purge
  void StorePurgeAsync(const std::string& in_id,
                       base::OnceCallback<void()> success_callback,
                       base::OnceCallback<void(brillo::Error*)> error_callback,
                       int timeout_ms) {
    ASSERT_TRUE(purge_async_success_cb_.is_null() ||
                purge_async_error_cb_.is_null());
    purge_async_success_cb_ = std::move(success_callback);
    purge_async_error_cb_ = std::move(error_callback);
  }

  void InvokePurgeSuccessFromStored() {
    std::move(purge_async_success_cb_).Run();
  }

  void InvokePurgeFailureFromStored(std::string error_code) {
    auto err = brillo::Error::Create(FROM_HERE, "domain", error_code, "msg");
    std::move(purge_async_error_cb_).Run(err.get());
  }

 protected:
  base::test::SingleThreadTaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  std::unique_ptr<DlcManagerHelper> dlc_manager_;
  std::unique_ptr<MockMetrics> mock_metrics_;

  std::unique_ptr<org::chromium::DlcServiceInterfaceProxyMock>
      mock_dlcservice_proxy_;
  org::chromium::DlcServiceInterfaceProxyMock* mock_dlcservice_proxy_ptr_;
  scoped_refptr<dbus::MockObjectProxy> object_proxy_ =
      new dbus::MockObjectProxy(
          nullptr, "", dbus::ObjectPath(dlcservice::kDlcServiceServicePath));

  dlcservice::InstallRequest default_install_request_;

  // WaitForServiceToBeAvailable
  ServiceAvailableCallback service_available_;
  // InstallAsync
  dlcservice::InstallRequest install_request_;
  base::OnceCallback<void()> install_async_success_cb_;
  base::OnceCallback<void(brillo::Error*)> install_async_error_cb_;
  // GetDlcState
  std::string get_dlc_state_dlc_id_;
  base::OnceCallback<void(const dlcservice::DlcState&)>
      get_dlc_state_success_cb_;
  base::OnceCallback<void(brillo::Error*)> get_dlc_state_error_cb_;
  // GetExistingDlcs
  base::OnceCallback<void(const dlcservice::DlcsWithContent&)>
      get_existing_dlcs_success_cb_;
  base::OnceCallback<void(brillo::Error*)> get_existing_dlcs_error_cb_;
  // PurgeAsync
  base::OnceCallback<void()> purge_async_success_cb_;
  base::OnceCallback<void(brillo::Error*)> purge_async_error_cb_;

  using InstallModemDlcOnceCallbackMock = StrictMock<
      base::MockOnceCallback<void(const std::string&, const brillo::Error*)>>;

  void SetUpDefaultDlcManagerHelper() {
    Dlc dlc1;
    Dlc dlc2;
    Dlc dlc3;
    dlc1.set_dlc_id(kOtherDlc1);
    dlc2.set_dlc_id(kDeviceDlc);
    dlc3.set_dlc_id(kOtherDlc2);
    std::map<std::string, Dlc> dlc_per_variant = {
        {kOtherVariant1, std::move(dlc1)},
        {kDeviceVariant, std::move(dlc2)},
        {kOtherVariant2, std::move(dlc3)}};

    dlc_manager_ = std::make_unique<DlcManagerHelper>(
        mock_metrics_.get(), dlc_per_variant, kDeviceVariant,
        std::move(mock_dlcservice_proxy_));

    default_install_request_.set_id(kDeviceDlc);
    default_install_request_.set_reserve(true);
  }
};

TEST_F(DlcManagerTest, DlcId) {
  SetUpDefaultDlcManagerHelper();
  EXPECT_EQ(kDeviceDlc, dlc_manager_->DlcId());
}

TEST_F(DlcManagerTest, InstallModemDlcSuccess) {
  SetUpDefaultDlcManagerHelper();
  InstallModemDlcOnceCallbackMock install_cb;
  AddWaitForServiceExpects();
  EXPECT_CALL(*mock_dlcservice_proxy_ptr_,
              InstallAsync(EqualsProto(default_install_request_), _, _, _))
      .WillOnce(Invoke(this, &DlcManagerTest::StoreInstallAsync));

  EXPECT_CALL(*mock_dlcservice_proxy_ptr_,
              GetDlcStateAsync(kDeviceDlc, _, _, _))
      .WillOnce(Invoke(this, &DlcManagerTest::StoreGetDlcStateAsync));

  EXPECT_CALL(install_cb, Run(kDeviceDlcMountPath, nullptr));
  EXPECT_CALL(*mock_metrics_, SendDlcInstallResult(DlcInstallResult::kSuccess));

  dlc_manager_->InstallModemDlc(install_cb.Get());

  InvokeServiceAvailableFromStored();
  InvokeInstallSuccessFromStored();
  InvokeGetDlcStateSuccessFromStored(dlcservice::DlcState::INSTALLED);
}

TEST_F(DlcManagerTest, InstallModemDlcServiceNotAvailable) {
  SetUpDefaultDlcManagerHelper();
  InstallModemDlcOnceCallbackMock install_cb;
  AddWaitForServiceExpects();
  EXPECT_CALL(install_cb, Run("", NotNull()));  // error returned
  EXPECT_CALL(*mock_metrics_,
              SendDlcInstallResult(
                  DlcInstallResult::kFailedTimeoutWaitingForDlcService));

  dlc_manager_->InstallModemDlc(install_cb.Get());
  task_environment_.FastForwardBy(dlcmanager::kInstallTimeout +
                                  base::Seconds(1));
}

TEST_F(DlcManagerTest, InstallModemDlcInstallAsyncTimeout) {
  SetUpDefaultDlcManagerHelper();
  InstallModemDlcOnceCallbackMock install_cb;
  AddWaitForServiceExpects();
  EXPECT_CALL(*mock_dlcservice_proxy_ptr_,
              InstallAsync(EqualsProto(default_install_request_), _, _, _))
      .WillOnce(Invoke(this, &DlcManagerTest::StoreInstallAsync));

  EXPECT_CALL(install_cb, Run("", NotNull()));  // error returned
  EXPECT_CALL(*mock_metrics_,
              SendDlcInstallResult(
                  DlcInstallResult::kFailedTimeoutWaitingForDlcInstall));

  dlc_manager_->InstallModemDlc(install_cb.Get());
  task_environment_.FastForwardBy(dlcmanager::kInstallTimeout -
                                  base::Seconds(1));
  InvokeServiceAvailableFromStored();
  task_environment_.FastForwardBy(
      base::Seconds(2));  // > dlcmanager::kInstallTimeout
}

TEST_F(DlcManagerTest, InstallModemDlcWaitingForInstalledStateFailed) {
  SetUpDefaultDlcManagerHelper();
  InstallModemDlcOnceCallbackMock install_cb;
  AddWaitForServiceExpects();
  EXPECT_CALL(*mock_dlcservice_proxy_ptr_,
              InstallAsync(EqualsProto(default_install_request_), _, _, _))
      .WillOnce(Invoke(this, &DlcManagerTest::StoreInstallAsync));

  int64_t expected_calls = dlcmanager::kInstallTimeout.InMilliseconds() /
                           dlcmanager::kGetDlcStatePollPeriod.InMilliseconds();
  EXPECT_CALL(*mock_dlcservice_proxy_ptr_,
              GetDlcStateAsync(kDeviceDlc, _, _, _))
      .Times(testing::Between(expected_calls, expected_calls + 1))
      .WillRepeatedly(
          Invoke(this, &DlcManagerTest::InvokeGetDlcStateSuccessInstalling));

  EXPECT_CALL(install_cb, Run("", NotNull()));  // error returned
  EXPECT_CALL(*mock_metrics_,
              SendDlcInstallResult(
                  DlcInstallResult::kFailedTimeoutWaitingForInstalledState));

  dlc_manager_->InstallModemDlc(install_cb.Get());
  InvokeServiceAvailableFromStored();
  InvokeInstallSuccessFromStored();
  task_environment_.FastForwardBy(dlcmanager::kInstallTimeout);
}

TEST_F(DlcManagerTest, InstallModemDlcWaitingForInstalledStateSucceed) {
  SetUpDefaultDlcManagerHelper();
  InSequence s;
  InstallModemDlcOnceCallbackMock install_cb;
  AddWaitForServiceExpects();
  EXPECT_CALL(*mock_dlcservice_proxy_ptr_,
              InstallAsync(EqualsProto(default_install_request_), _, _, _))
      .WillOnce(Invoke(this, &DlcManagerTest::StoreInstallAsync));

  int64_t expected_calls = dlcmanager::kInstallTimeout.InMilliseconds() /
                           dlcmanager::kGetDlcStatePollPeriod.InMilliseconds();

  EXPECT_CALL(*mock_dlcservice_proxy_ptr_,
              GetDlcStateAsync(kDeviceDlc, _, _, _))
      .Times(expected_calls - 3)
      .WillRepeatedly(
          Invoke(this, &DlcManagerTest::InvokeGetDlcStateSuccessInstalling));

  EXPECT_CALL(*mock_dlcservice_proxy_ptr_,
              GetDlcStateAsync(kDeviceDlc, _, _, _))
      .WillOnce(Invoke(this, &DlcManagerTest::StoreGetDlcStateAsync));

  EXPECT_CALL(install_cb, Run(kDeviceDlcMountPath, nullptr));
  EXPECT_CALL(*mock_metrics_, SendDlcInstallResult(DlcInstallResult::kSuccess));

  dlc_manager_->InstallModemDlc(install_cb.Get());
  InvokeServiceAvailableFromStored();
  InvokeInstallSuccessFromStored();
  task_environment_.FastForwardBy(dlcmanager::kInstallTimeout -
                                  base::Seconds(3));
  InvokeGetDlcStateSuccessFromStored(dlcservice::DlcState::INSTALLED);
  task_environment_.FastForwardBy(base::Seconds(5));
}

TEST_F(DlcManagerTest, InstallModemDlcInstallAsyncError) {
  SetUpDefaultDlcManagerHelper();
  InstallModemDlcOnceCallbackMock install_cb;
  AddWaitForServiceExpects();
  EXPECT_CALL(*mock_dlcservice_proxy_ptr_,
              InstallAsync(EqualsProto(default_install_request_), _, _, _))
      .Times(dlcmanager::kMaxRetriesBeforeFallbackToRootfs + 1)
      .WillRepeatedly(Invoke(this, &DlcManagerTest::StoreInstallAsync));

  EXPECT_CALL(install_cb, Run("", NotNull()));  // error returned
  EXPECT_CALL(
      *mock_metrics_,
      SendDlcInstallResult(DlcInstallResult::kDlcServiceReturnedNoImageFound));

  dlc_manager_->InstallModemDlc(install_cb.Get());
  InvokeServiceAvailableFromStored();
  for (int i = 0; i < dlcmanager::kMaxRetriesBeforeFallbackToRootfs; i++) {
    InvokeInstallFailureFromStored(dlcservice::kErrorNoImageFound);
    while (install_async_error_cb_.is_null()) {
      task_environment_.FastForwardBy(base::Seconds(1));
    }
  }
  InvokeInstallFailureFromStored(dlcservice::kErrorNoImageFound);
}

TEST_F(DlcManagerTest, InstallModemDlcGetDlcStateAsyncError) {
  SetUpDefaultDlcManagerHelper();
  InstallModemDlcOnceCallbackMock install_cb;
  AddWaitForServiceExpects();
  EXPECT_CALL(*mock_dlcservice_proxy_ptr_,
              InstallAsync(EqualsProto(default_install_request_), _, _, _))
      .Times(dlcmanager::kMaxRetriesBeforeFallbackToRootfs + 1)
      .WillRepeatedly(Invoke(this, &DlcManagerTest::StoreInstallAsync));

  EXPECT_CALL(*mock_dlcservice_proxy_ptr_,
              GetDlcStateAsync(kDeviceDlc, _, _, _))
      .Times(dlcmanager::kMaxRetriesBeforeFallbackToRootfs + 1)
      .WillRepeatedly(Invoke(this, &DlcManagerTest::StoreGetDlcStateAsync));

  EXPECT_CALL(install_cb, Run("", NotNull()));  // error returned
  EXPECT_CALL(
      *mock_metrics_,
      SendDlcInstallResult(DlcInstallResult::kDlcServiceReturnedNeedReboot));

  dlc_manager_->InstallModemDlc(install_cb.Get());
  InvokeServiceAvailableFromStored();
  InvokeInstallSuccessFromStored();
  for (int i = 0; i < dlcmanager::kMaxRetriesBeforeFallbackToRootfs; i++) {
    InvokeGetDlcStateFailureFromStored(dlcservice::kErrorNeedReboot);
    while (install_async_success_cb_.is_null()) {
      task_environment_.FastForwardBy(base::Seconds(1));
    }
    InvokeInstallSuccessFromStored();
  }
  InvokeGetDlcStateFailureFromStored(dlcservice::kErrorNeedReboot);
}

TEST_F(DlcManagerTest,
       InstallModemDlcGetDlcStateAsyncErrorOnSecondAndFutureCalls) {
  SetUpDefaultDlcManagerHelper();
  InstallModemDlcOnceCallbackMock install_cb;
  AddWaitForServiceExpects();
  EXPECT_CALL(*mock_dlcservice_proxy_ptr_,
              InstallAsync(EqualsProto(default_install_request_), _, _, _))
      .Times(dlcmanager::kMaxRetriesBeforeFallbackToRootfs + 1)
      .WillRepeatedly(Invoke(this, &DlcManagerTest::StoreInstallAsync));

  EXPECT_CALL(*mock_dlcservice_proxy_ptr_,
              GetDlcStateAsync(kDeviceDlc, _, _, _))
      .Times(dlcmanager::kMaxRetriesBeforeFallbackToRootfs + 2)
      .WillRepeatedly(Invoke(this, &DlcManagerTest::StoreGetDlcStateAsync));

  EXPECT_CALL(install_cb, Run("", NotNull()));  // error returned
  EXPECT_CALL(
      *mock_metrics_,
      SendDlcInstallResult(DlcInstallResult::kDlcServiceReturnedAllocation));

  dlc_manager_->InstallModemDlc(install_cb.Get());
  InvokeServiceAvailableFromStored();
  InvokeInstallSuccessFromStored();
  InvokeGetDlcStateSuccessFromStored(dlcservice::DlcState::INSTALLING);
  task_environment_.FastForwardBy(dlcmanager::kGetDlcStatePollPeriod);
  for (int i = 0; i < dlcmanager::kMaxRetriesBeforeFallbackToRootfs; i++) {
    InvokeGetDlcStateFailureFromStored(dlcservice::kErrorAllocation);
    while (install_async_success_cb_.is_null()) {
      task_environment_.FastForwardBy(base::Seconds(1));
    }
    InvokeInstallSuccessFromStored();
  }
  InvokeGetDlcStateFailureFromStored(dlcservice::kErrorAllocation);
}

TEST_F(DlcManagerTest, InstallModemDlcGetDlcStateAsyncUnexpectedState) {
  SetUpDefaultDlcManagerHelper();
  InstallModemDlcOnceCallbackMock install_cb;
  AddWaitForServiceExpects();
  EXPECT_CALL(*mock_dlcservice_proxy_ptr_,
              InstallAsync(EqualsProto(default_install_request_), _, _, _))
      .Times(dlcmanager::kMaxRetriesBeforeFallbackToRootfs + 1)
      .WillRepeatedly(Invoke(this, &DlcManagerTest::StoreInstallAsync));

  EXPECT_CALL(*mock_dlcservice_proxy_ptr_,
              GetDlcStateAsync(kDeviceDlc, _, _, _))
      .Times(dlcmanager::kMaxRetriesBeforeFallbackToRootfs + 1)
      .WillRepeatedly(Invoke(this, &DlcManagerTest::StoreGetDlcStateAsync));

  EXPECT_CALL(install_cb, Run("", NotNull()));  // error returned
  EXPECT_CALL(*mock_metrics_, SendDlcInstallResult(
                                  DlcInstallResult::kFailedUnexpectedDlcState));

  dlc_manager_->InstallModemDlc(install_cb.Get());
  InvokeServiceAvailableFromStored();
  InvokeInstallSuccessFromStored();
  for (int i = 0; i < dlcmanager::kMaxRetriesBeforeFallbackToRootfs; i++) {
    InvokeGetDlcStateSuccessFromStored(dlcservice::DlcState::NOT_INSTALLED);
    while (install_async_success_cb_.is_null()) {
      task_environment_.FastForwardBy(base::Seconds(1));
    }
    InvokeInstallSuccessFromStored();
  }
  InvokeGetDlcStateSuccessFromStored(dlcservice::DlcState::NOT_INSTALLED);
}

TEST_F(DlcManagerTest, InstallModemDlcRetryInstallOnFailure) {
  InSequence s;
  SetUpDefaultDlcManagerHelper();
  InstallModemDlcOnceCallbackMock install_cb;
  AddWaitForServiceExpects();
  EXPECT_CALL(*mock_dlcservice_proxy_ptr_,
              InstallAsync(EqualsProto(default_install_request_), _, _, _))
      .WillOnce(Invoke(this, &DlcManagerTest::StoreInstallAsync));

  EXPECT_CALL(*mock_dlcservice_proxy_ptr_,
              InstallAsync(EqualsProto(default_install_request_), _, _, _))
      .WillOnce(Invoke(this, &DlcManagerTest::StoreInstallAsync));

  EXPECT_CALL(*mock_dlcservice_proxy_ptr_,
              GetDlcStateAsync(kDeviceDlc, _, _, _))
      .WillOnce(Invoke(this, &DlcManagerTest::StoreGetDlcStateAsync));

  EXPECT_CALL(install_cb, Run(kDeviceDlcMountPath, nullptr));  // error returned
  EXPECT_CALL(*mock_metrics_, SendDlcInstallResult(DlcInstallResult::kSuccess));

  dlc_manager_->InstallModemDlc(install_cb.Get());
  InvokeServiceAvailableFromStored();
  InvokeInstallFailureFromStored(dlcservice::kErrorNoImageFound);
  task_environment_.FastForwardBy(dlcmanager::kInitialInstallRetryPeriod);
  InvokeInstallSuccessFromStored();
  InvokeGetDlcStateSuccessFromStored(dlcservice::DlcState::INSTALLED);
}

TEST_F(DlcManagerTest, RemoveUnecessaryModemDlcsFullSuccess) {
  SetUpDefaultDlcManagerHelper();
  EXPECT_CALL(*mock_dlcservice_proxy_ptr_, GetExistingDlcsAsync(_, _, _))
      .WillOnce(Invoke(this, &DlcManagerTest::StoreGetExistingDlcsAsync));

  EXPECT_CALL(*mock_dlcservice_proxy_ptr_, PurgeAsync(kOtherDlc1, _, _, _))
      .WillOnce(Invoke(this, &DlcManagerTest::StorePurgeAsync));
  EXPECT_CALL(*mock_dlcservice_proxy_ptr_, PurgeAsync(kOtherDlc2, _, _, _))
      .WillOnce(Invoke(this, &DlcManagerTest::StorePurgeAsync));

  EXPECT_CALL(*mock_metrics_,
              SendDlcUninstallResult(DlcUninstallResult::kSuccess))
      .Times(2);

  dlc_manager_->RemoveUnecessaryModemDlcs();
  InvokeGetExistingDlcsFromStored({kOtherDlc1, kOtherDlc2});
  InvokePurgeSuccessFromStored();
  InvokePurgeSuccessFromStored();
}

TEST_F(DlcManagerTest, RemoveUnecessaryModemDlcsPartialSuccess) {
  SetUpDefaultDlcManagerHelper();
  EXPECT_CALL(*mock_dlcservice_proxy_ptr_, GetExistingDlcsAsync(_, _, _))
      .WillOnce(Invoke(this, &DlcManagerTest::StoreGetExistingDlcsAsync));

  EXPECT_CALL(*mock_dlcservice_proxy_ptr_, PurgeAsync(kOtherDlc2, _, _, _))
      .WillOnce(Invoke(this, &DlcManagerTest::StorePurgeAsync));

  EXPECT_CALL(*mock_metrics_,
              SendDlcUninstallResult(DlcUninstallResult::kSuccess));

  dlc_manager_->RemoveUnecessaryModemDlcs();
  InvokeGetExistingDlcsFromStored({kOtherDlc2});
  InvokePurgeSuccessFromStored();
}

TEST_F(DlcManagerTest, RemoveUnecessaryModemDlcsNoneSuccess) {
  SetUpDefaultDlcManagerHelper();
  EXPECT_CALL(*mock_dlcservice_proxy_ptr_, GetExistingDlcsAsync(_, _, _))
      .WillOnce(Invoke(this, &DlcManagerTest::StoreGetExistingDlcsAsync));

  dlc_manager_->RemoveUnecessaryModemDlcs();
  InvokeGetExistingDlcsFromStored({});
}

TEST_F(DlcManagerTest, RemoveUnecessaryModemDlcsNoDeviceVariant) {
  Dlc dlc1;
  Dlc dlc2;
  Dlc dlc3;
  dlc1.set_dlc_id(kOtherDlc1);
  dlc2.set_dlc_id(kDeviceDlc);
  dlc3.set_dlc_id(kOtherDlc2);
  std::map<std::string, Dlc> dlc_per_variant = {
      {kOtherVariant1, std::move(dlc1)},
      {kDeviceVariant, std::move(dlc2)},
      {kOtherVariant2, std::move(dlc3)}};

  dlc_manager_ = std::make_unique<DlcManagerHelper>(
      mock_metrics_.get(), dlc_per_variant, "" /* no variant*/,
      std::move(mock_dlcservice_proxy_));

  EXPECT_CALL(*mock_metrics_, SendDlcUninstallResult(
                                  DlcUninstallResult::kUnexpectedEmptyVariant));

  dlc_manager_->RemoveUnecessaryModemDlcs();
}

TEST_F(DlcManagerTest, RemoveUnecessaryModemDlcsGetExistingDlcsError) {
  SetUpDefaultDlcManagerHelper();
  EXPECT_CALL(*mock_dlcservice_proxy_ptr_, GetExistingDlcsAsync(_, _, _))
      .WillOnce(Invoke(this, &DlcManagerTest::StoreGetExistingDlcsAsync));

  EXPECT_CALL(
      *mock_metrics_,
      SendDlcUninstallResult(
          DlcUninstallResult::kDlcServiceReturnedErrorOnGetExistingDlcs));

  dlc_manager_->RemoveUnecessaryModemDlcs();
  // Use unknown dbus error to check kDlcServiceReturnedErrorOnGetExistingDlcs
  InvokeGetExistingDlcsFailureFromStored("unknown_error_code");
}

TEST_F(DlcManagerTest, RemoveUnecessaryModemDlcsFirstPurgeError) {
  SetUpDefaultDlcManagerHelper();
  InSequence s;
  EXPECT_CALL(*mock_dlcservice_proxy_ptr_, GetExistingDlcsAsync(_, _, _))
      .WillOnce(Invoke(this, &DlcManagerTest::StoreGetExistingDlcsAsync));

  EXPECT_CALL(*mock_dlcservice_proxy_ptr_, PurgeAsync(kOtherDlc1, _, _, _))
      .WillOnce(Invoke(this, &DlcManagerTest::StorePurgeAsync));
  EXPECT_CALL(*mock_metrics_,
              SendDlcUninstallResult(
                  DlcUninstallResult::kDlcServiceReturnedAllocation));

  EXPECT_CALL(*mock_dlcservice_proxy_ptr_, PurgeAsync(kOtherDlc2, _, _, _))
      .WillOnce(Invoke(this, &DlcManagerTest::StorePurgeAsync));
  EXPECT_CALL(*mock_metrics_,
              SendDlcUninstallResult(DlcUninstallResult::kSuccess));

  dlc_manager_->RemoveUnecessaryModemDlcs();
  InvokeGetExistingDlcsFromStored({kOtherDlc1, kOtherDlc2});
  InvokePurgeFailureFromStored(dlcservice::kErrorAllocation);
  InvokePurgeSuccessFromStored();
}

}  // namespace modemfwd
