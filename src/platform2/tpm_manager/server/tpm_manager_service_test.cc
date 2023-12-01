// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/run_loop.h>
#include <base/synchronization/lock.h>
#include <base/synchronization/waitable_event.h>
#include <base/test/bind.h>
#include <base/test/task_environment.h>
#include <base/threading/platform_thread.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/tpm/tpm_version.h>

#include "tpm_manager/server/mock_local_data_store.h"
#include "tpm_manager/server/mock_pinweaver_provision.h"
#include "tpm_manager/server/mock_tpm_allowlist.h"
#include "tpm_manager/server/mock_tpm_initializer.h"
#include "tpm_manager/server/mock_tpm_manager_metrics.h"
#include "tpm_manager/server/mock_tpm_nvram.h"
#include "tpm_manager/server/mock_tpm_status.h"
#include "tpm_manager/server/tpm_manager_metrics_names.h"
#include "tpm_manager/server/tpm_manager_service.h"

using testing::_;
using testing::AtLeast;
using testing::AtMost;
using testing::DoAll;
using testing::Expectation;
using testing::Ge;
using testing::Invoke;
using testing::Le;
using testing::NiceMock;
using testing::Return;
using testing::SaveArg;
using testing::SetArgPointee;
using testing::WithoutArgs;

namespace {

const char kOwnerPassword[] = "owner";
const char kOwnerDependency[] = "owner_dependency";
const char kOtherDependency[] = "other_dependency";

}  // namespace

namespace tpm_manager {

// A test fixture that takes care of message loop management and configuring a
// TpmManagerService instance with mock dependencies. Template variables
// |perform_preinit| are passed to the constructor of
// TpmManagerService, and |shall_setup_service| indicates if, during dixture
// setup, TpmManagerService is also set up as well.
template <bool perform_preinit, bool shall_setup_service>
class TpmManagerServiceTestBase : public testing::Test {
 public:
  ~TpmManagerServiceTestBase() override = default;
  void SetUp() override {
    EXPECT_CALL(mock_tpm_manager_metrics_, ReportVersionFingerprint(_))
        .Times(AtMost(1));
    auto mock_pinweaver_provision =
        std::make_unique<NiceMock<MockPinWeaverProvision>>();
    mock_pinweaver_provision_ = mock_pinweaver_provision.get();
    service_.reset(new TpmManagerService(
        perform_preinit, &mock_local_data_store_,
        std::move(mock_pinweaver_provision), &mock_tpm_status_,
        &mock_tpm_initializer_, &mock_tpm_nvram_, &mock_tpm_manager_metrics_));
    service_->set_tpm_allowlist_for_testing(&mock_tpm_allowlist_);
    ON_CALL(mock_tpm_allowlist_, IsAllowed()).WillByDefault(Return(true));
    DisablePeriodicDictionaryAttackReset();
    if (shall_setup_service) {
      SetupService();
    }
    // We remove the pinweaver provision from `TpmManagerService`. None should
    // be all at any time.
    EXPECT_CALL(*mock_pinweaver_provision_, Provision()).Times(0);
  }

  // This should be a protected method, but it was moved to public to avoid
  // polluting the test code with generated test fixture class names.
  void Quit() { run_loop_.Quit(); }

 protected:
  void Run() { run_loop_.Run(); }

  void RunServiceWorkerAndQuit() {
    // Run out the service worker loop by posting a new command and waiting for
    // the response.
    auto callback = [](TpmManagerServiceTestBase* self,
                       const GetTpmStatusReply& reply) { self->Quit(); };
    GetTpmStatusRequest request;
    request.set_ignore_cache(true);
    service_->GetTpmStatus(request, base::BindOnce(callback, this));
    Run();
  }

  void SetupService() { CHECK(service_->Initialize()); }

  void DisablePeriodicDictionaryAttackReset() {
    // Virtually disables the DA reset timer to reduce noises of expectations.
    PassiveTimer timer(base::Hours(5));
    timer.Reset();
    service_->set_dictionary_attack_reset_timer_for_testing(timer);
  }

  NiceMock<MockLocalDataStore> mock_local_data_store_;
  NiceMock<MockTpmInitializer> mock_tpm_initializer_;
  NiceMock<MockTpmNvram> mock_tpm_nvram_;
  NiceMock<MockTpmStatus> mock_tpm_status_;
  NiceMock<MockTpmAllowlist> mock_tpm_allowlist_;
  NiceMock<MockTpmManagerMetrics> mock_tpm_manager_metrics_;
  // Owned by `service_` after `SetUp()`.
  NiceMock<MockPinWeaverProvision>* mock_pinweaver_provision_;
  std::unique_ptr<TpmManagerService> service_;

 private:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY};
  base::RunLoop run_loop_;
};

class TpmManagerServiceTest : public TpmManagerServiceTestBase<true, true> {};
// Tests must call SetupService() for the following test fixtures where
// |shall_setup_service| is set to false.
class TpmManagerServiceTest_NoPreinit
    : public TpmManagerServiceTestBase<false, false> {};
class TpmManagerServiceTest_Preinit
    : public TpmManagerServiceTestBase<true, false> {};

class TpmManagerServiceTest_NoSetup : public TpmManagerServiceTest {
 public:
  void SetUp() override {}
};

TEST_F(TpmManagerServiceTest_Preinit, AutoInitialize) {
  // Called in InitializeTask()
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_))
      .Times(1)
      .WillRepeatedly(
          DoAll(SetArgPointee<0>(TpmStatus::kTpmUnowned), Return(true)));

  // Make sure InitializeTpm doesn't get multiple calls.
  EXPECT_CALL(mock_tpm_initializer_, InitializeTpm(_));
  EXPECT_CALL(mock_tpm_initializer_, PreInitializeTpm()).Times(0);
  EXPECT_CALL(mock_tpm_manager_metrics_, ReportTimeToTakeOwnership(_)).Times(1);
  SetupService();
  RunServiceWorkerAndQuit();
}

TEST_F(TpmManagerServiceTest_Preinit, InitializeMetrics) {
  // Called in InitializeTask()
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_))
      .Times(1)
      .WillRepeatedly(
          DoAll(SetArgPointee<0>(TpmStatus::kTpmUnowned), Return(true)));

  EXPECT_CALL(mock_tpm_status_, GetVersionInfo(_, _, _, _, _, _))
      .WillOnce(Return(true));

  EXPECT_CALL(mock_tpm_status_, GetAlertsData(_)).WillOnce(Return(true));

  EXPECT_CALL(mock_tpm_status_, GetGscVersion())
      .WillRepeatedly(Return(GscVersion::GSC_VERSION_TI50));

  EXPECT_CALL(mock_tpm_status_, GetTi50Stats(_, _, _, _))
      .WillOnce(Return(true));

  EXPECT_CALL(mock_tpm_manager_metrics_, ReportTimeToTakeOwnership(_)).Times(1);
  EXPECT_CALL(mock_tpm_manager_metrics_, ReportVersionFingerprint(_)).Times(1);
  EXPECT_CALL(mock_tpm_manager_metrics_, ReportAlertsData(_))
      .WillOnce([this](auto&&) { Quit(); });
  EXPECT_CALL(mock_tpm_manager_metrics_, ReportFilesystemInitTime(_)).Times(1);
  EXPECT_CALL(mock_tpm_manager_metrics_, ReportFilesystemUtilization(_))
      .Times(1);
  EXPECT_CALL(mock_tpm_manager_metrics_, ReportApRoVerificationTime(_))
      .Times(1);
  EXPECT_CALL(mock_tpm_manager_metrics_, ReportExpApRoVerificationStatus(_))
      .Times(1);
  SetupService();
  Run();
}

TEST_F(TpmManagerServiceTest_Preinit, NoNeedToInitialize) {
  // Called in InitializeTask()
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_))
      .Times(1)
      .WillRepeatedly(
          DoAll(SetArgPointee<0>(TpmStatus::kTpmOwned), Return(true)));
  EXPECT_CALL(mock_tpm_initializer_, InitializeTpm(_)).Times(0);
  EXPECT_CALL(mock_tpm_initializer_, PreInitializeTpm()).Times(0);
  SetupService();
  RunServiceWorkerAndQuit();
}

TEST_F(TpmManagerServiceTest_Preinit, AutoInitializeNoTpm) {
  EXPECT_CALL(mock_tpm_status_, IsTpmEnabled()).WillRepeatedly(Return(false));
  EXPECT_CALL(mock_tpm_initializer_, InitializeTpm(_)).Times(0);
  EXPECT_CALL(mock_tpm_initializer_, PreInitializeTpm()).Times(0);
  SetupService();
  RunServiceWorkerAndQuit();
}

TEST_F(TpmManagerServiceTest_Preinit, AutoInitializeFailure) {
  // Called in InitializeTask()
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_))
      .Times(1)
      .WillRepeatedly(
          DoAll(SetArgPointee<0>(TpmStatus::kTpmUnowned), Return(true)));
  EXPECT_CALL(mock_tpm_initializer_, InitializeTpm(_))
      .WillRepeatedly(Return(false));
  EXPECT_CALL(mock_tpm_manager_metrics_, ReportTimeToTakeOwnership(_)).Times(0);
  SetupService();
  RunServiceWorkerAndQuit();
}

TEST_F(TpmManagerServiceTest_Preinit, TakeOwnershipAfterAutoInitialize) {
  // Called in InitializeTask()
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_))
      .WillOnce(DoAll(SetArgPointee<0>(TpmStatus::kTpmUnowned), Return(true)));
  EXPECT_CALL(mock_tpm_initializer_, InitializeTpm(_))
      .WillOnce(DoAll(SetArgPointee<0>(false), Return(true)))
      .WillOnce(DoAll(SetArgPointee<0>(true), Return(true)));
  EXPECT_CALL(mock_tpm_manager_metrics_, ReportTimeToTakeOwnership(_)).Times(1);
  EXPECT_CALL(mock_tpm_manager_metrics_, ReportDictionaryAttackResetStatus(_))
      .Times(1);
  EXPECT_CALL(mock_tpm_manager_metrics_, ReportDictionaryAttackCounter(_))
      .Times(1);
  SetupService();
  auto callback = [](TpmManagerServiceTestBase* self,
                     const TakeOwnershipReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    self->Quit();
  };
  TakeOwnershipRequest request;
  service_->TakeOwnership(request, base::BindOnce(callback, this));
  Run();
}

TEST_F(TpmManagerServiceTest_NoPreinit, NoAutoInitialize) {
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_))
      .WillRepeatedly(
          DoAll(SetArgPointee<0>(TpmStatus::kTpmUnowned), Return(true)));
  EXPECT_CALL(mock_tpm_initializer_, InitializeTpm(_)).Times(0);
  SetupService();
  RunServiceWorkerAndQuit();
}

TEST_F(TpmManagerServiceTest_Preinit, TpmAlreadyOwned) {
  // Called in InitializeTask()
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_))
      .Times(1)
      .WillRepeatedly(
          DoAll(SetArgPointee<0>(TpmStatus::kTpmOwned), Return(true)));
  EXPECT_CALL(mock_tpm_initializer_, InitializeTpm(_)).Times(0);
  EXPECT_CALL(mock_tpm_initializer_, PreInitializeTpm()).Times(0);
  EXPECT_CALL(mock_tpm_status_, IsDictionaryAttackMitigationEnabled(_))
      .WillOnce(DoAll(SetArgPointee<0>(true), Return(true)));
  EXPECT_CALL(mock_tpm_initializer_, DisableDictionaryAttackMitigation())
      .Times(1);
  SetupService();
  RunServiceWorkerAndQuit();
}

TEST_F(TpmManagerServiceTest_Preinit, TpmAlreadyOwnedSkipDisableDA) {
  // Called in InitializeTask()
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_))
      .Times(1)
      .WillRepeatedly(
          DoAll(SetArgPointee<0>(TpmStatus::kTpmOwned), Return(true)));
  EXPECT_CALL(mock_tpm_initializer_, InitializeTpm(_)).Times(0);
  EXPECT_CALL(mock_tpm_initializer_, PreInitializeTpm()).Times(0);
  EXPECT_CALL(mock_tpm_status_, IsDictionaryAttackMitigationEnabled(_))
      .WillOnce(DoAll(SetArgPointee<0>(false), Return(true)));
  EXPECT_CALL(mock_tpm_initializer_, DisableDictionaryAttackMitigation())
      .Times(0);
  SetupService();
  RunServiceWorkerAndQuit();
}

TEST_F(TpmManagerServiceTest_Preinit,
       TpmAlreadyOwnedStillDisableDAWhenCheckFails) {
  // Called in InitializeTask()
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_))
      .Times(1)
      .WillRepeatedly(
          DoAll(SetArgPointee<0>(TpmStatus::kTpmOwned), Return(true)));
  EXPECT_CALL(mock_tpm_initializer_, InitializeTpm(_)).Times(0);
  EXPECT_CALL(mock_tpm_initializer_, PreInitializeTpm()).Times(0);
  EXPECT_CALL(mock_tpm_status_, IsDictionaryAttackMitigationEnabled(_))
      .WillOnce(Return(false));
  EXPECT_CALL(mock_tpm_initializer_, DisableDictionaryAttackMitigation())
      .Times(1);
  SetupService();
  RunServiceWorkerAndQuit();
}

TEST_F(TpmManagerServiceTest_Preinit, GetTpmStatusOwnershipStatusFailure) {
  // Called in InitializeTask()
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_))
      .Times(2)
      .WillRepeatedly(Return(false));
  EXPECT_CALL(mock_tpm_manager_metrics_, ReportDictionaryAttackCounter(0))
      .Times(1);
  EXPECT_CALL(mock_tpm_manager_metrics_,
              ReportDictionaryAttackResetStatus(
                  DictionaryAttackResetStatus::kResetNotNecessary))
      .Times(1);

  SetupService();

  auto callback = [](TpmManagerServiceTestBase* self,
                     const GetTpmStatusReply& reply) {
    EXPECT_EQ(STATUS_DEVICE_ERROR, reply.status());
    self->Quit();
  };
  GetTpmStatusRequest request;
  service_->GetTpmStatus(request, base::BindOnce(callback, this));
  Run();
}

TEST_F(TpmManagerServiceTest_Preinit, PruneLocalData) {
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_))
      .WillRepeatedly(
          DoAll(SetArgPointee<0>(TpmStatus::kTpmUnowned), Return(true)));

  EXPECT_CALL(mock_tpm_initializer_, PruneStoredPasswords()).Times(1);
  EXPECT_CALL(mock_tpm_nvram_, PrunePolicies()).Times(1);

  SetupService();
  RunServiceWorkerAndQuit();
}

TEST_F(TpmManagerServiceTest_NoPreinit, NoPreInitialize) {
  EXPECT_CALL(mock_tpm_initializer_, InitializeTpm(_)).Times(0);
  EXPECT_CALL(mock_tpm_initializer_, PreInitializeTpm()).Times(0);
  SetupService();
  RunServiceWorkerAndQuit();
}

// This item checks if the prompt reset right after taking ownership does reset
// the periodic reset timer. For more information, see the comments inlined.
//
// TODO(b/152485752): Finds out non-flaky version to test it and re-enable it.
TEST_F(TpmManagerServiceTest_Preinit,
       DISABLED_DictionaryAttackResetTimerReset) {
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_))
      .WillRepeatedly(
          DoAll(SetArgPointee<0>(TpmStatus::kTpmOwned), Return(true)));
  EXPECT_CALL(mock_tpm_initializer_, InitializeTpm(_))
      .WillOnce(DoAll(SetArgPointee<0>(false), Return(true)));
  EXPECT_CALL(mock_tpm_initializer_, PreInitializeTpm()).Times(0);
  EXPECT_CALL(mock_tpm_manager_metrics_, ReportTimeToTakeOwnership(_)).Times(1);

  // Sets the period to 50 ms.
  service_->set_dictionary_attack_reset_timer_for_testing(
      PassiveTimer(base::Milliseconds(50)));
  base::WaitableEvent first_periodic_event(
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED);
  base::WaitableEvent second_periodic_event(
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED);

  EXPECT_CALL(mock_tpm_status_, GetDictionaryAttackInfo(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<0>(0),
                      WithoutArgs([&first_periodic_event]() {
                        first_periodic_event.Signal();
                      }),
                      Return(true)))
      .WillOnce(Return(true))
      .WillOnce(DoAll(SetArgPointee<0>(0),
                      WithoutArgs([&second_periodic_event]() {
                        second_periodic_event.Signal();
                      }),
                      Return(true)))
      .WillRepeatedly(DoAll(SetArgPointee<0>(0), Return(true)));
  EXPECT_CALL(mock_tpm_manager_metrics_,
              ReportDictionaryAttackResetStatus(
                  DictionaryAttackResetStatus::kResetNotNecessary))
      .Times(AtLeast(3));
  EXPECT_CALL(mock_tpm_manager_metrics_, ReportDictionaryAttackCounter(0))
      .Times(AtLeast(3));
  // The DA reset is triggered for the first time here once the TPM is confirmed
  // to be owned.
  SetupService();
  auto callback = [](TpmManagerServiceTestBase* self,
                     const TakeOwnershipReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    self->Quit();
  };
  base::TimeTicks start_time = base::TimeTicks::Now();
  base::PlatformThread::Sleep(base::Milliseconds(25));
  first_periodic_event.Wait();
  TakeOwnershipRequest request;
  // The DA reset is triggered for the second time here once the TPM is owned.
  service_->TakeOwnership(request, base::BindOnce(callback, this));
  Run();
  second_periodic_event.Wait();
  base::TimeTicks finish_time = base::TimeTicks::Now();
  // Supposedly finish_time-start_time is ~75ms and can't be <50ms or >100ms.
  // 1. Even if the threading doesn't make any promise that the timely trigger
  // is accurate, 20 ms window should be generous enough.
  // 2. In case |TakeOwnership| doesn't even trigger DA reset, the duration
  // would be larger than 100ms and fails the test.
  EXPECT_THAT(finish_time - start_time, Le(base::Milliseconds(95)));
  // If the timer doesn't get reset, it could be triggered @ ~50ms and fails the
  // test.
  EXPECT_THAT(finish_time - start_time, Ge(base::Milliseconds(55)));
}

TEST_F(TpmManagerServiceTest_Preinit, GetTpmStatusSuccess) {
  LocalData local_data;
  local_data.set_owner_password(kOwnerPassword);
  local_data.set_no_srk_auth(false);
  EXPECT_CALL(mock_local_data_store_, Read(_))
      .WillRepeatedly(DoAll(SetArgPointee<0>(local_data), Return(true)));

  SetupService();

  auto callback_nonsensitive = [](TpmManagerServiceTestBase* self,
                                  const GetTpmNonsensitiveStatusReply& reply) {
    EXPECT_TRUE(reply.has_status());
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_TRUE(reply.is_enabled());
    EXPECT_TRUE(reply.is_owned());
    // kOwnerPassword is not empty.
    EXPECT_TRUE(reply.is_owner_password_present());
    EXPECT_FALSE(reply.has_reset_lock_permissions());
    EXPECT_TRUE(reply.is_srk_default_auth());
  };
  auto callback = [](TpmManagerServiceTestBase* self,
                     const GetTpmStatusReply& reply) {
    EXPECT_TRUE(reply.has_status());
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_TRUE(reply.enabled());
    EXPECT_TRUE(reply.owned());
    EXPECT_EQ(kOwnerPassword, reply.local_data().owner_password());
    EXPECT_FALSE(reply.local_data().no_srk_auth());
    self->Quit();
  };
  service_->GetTpmNonsensitiveStatus(
      GetTpmNonsensitiveStatusRequest(),
      base::BindOnce(callback_nonsensitive, this));
  service_->GetTpmStatus(GetTpmStatusRequest(), base::BindOnce(callback, this));
  Run();
}

TEST_F(TpmManagerServiceTest_Preinit,
       GetTpmNonsensitiveStatusHasLockoutPassword) {
  LocalData local_data;
  local_data.set_lockout_password("lockout password");
  EXPECT_CALL(mock_local_data_store_, Read(_))
      .WillRepeatedly(DoAll(SetArgPointee<0>(local_data), Return(true)));

  SetupService();

  auto callback = [](TpmManagerServiceTestBase* self,
                     const GetTpmNonsensitiveStatusReply& reply) {
    EXPECT_TRUE(reply.has_reset_lock_permissions());
    self->Quit();
  };
  service_->GetTpmNonsensitiveStatus(GetTpmNonsensitiveStatusRequest(),
                                     base::BindOnce(callback, this));
  Run();
}

TEST_F(TpmManagerServiceTest_Preinit,
       GetTpmNonsensitiveStatusDelegateCanResetDA) {
  LocalData local_data;
  local_data.mutable_owner_delegate()->set_has_reset_lock_permissions(true);
  EXPECT_CALL(mock_local_data_store_, Read(_))
      .WillRepeatedly(DoAll(SetArgPointee<0>(local_data), Return(true)));

  SetupService();

  auto callback = [](TpmManagerServiceTestBase* self,
                     const GetTpmNonsensitiveStatusReply& reply) {
    EXPECT_TRUE(reply.has_reset_lock_permissions());
    self->Quit();
  };
  GetTpmStatusRequest request;
  service_->GetTpmNonsensitiveStatus(GetTpmNonsensitiveStatusRequest(),
                                     base::BindOnce(callback, this));
  Run();
}

TEST_F(TpmManagerServiceTest_Preinit, GetTpmStatusLocalDataFailure) {
  EXPECT_CALL(mock_local_data_store_, Read(_)).WillRepeatedly(Return(false));

  SetupService();

  auto callback = [](TpmManagerServiceTestBase* self,
                     const GetTpmStatusReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_TRUE(reply.enabled());
    EXPECT_TRUE(reply.owned());
    EXPECT_FALSE(reply.has_local_data());
    self->Quit();
  };
  GetTpmStatusRequest request;
  service_->GetTpmStatus(request, base::BindOnce(callback, this));
  Run();
}

TEST_F(TpmManagerServiceTest_Preinit, GetTpmStatusNoTpm) {
  EXPECT_CALL(mock_tpm_status_, IsTpmEnabled()).WillRepeatedly(Return(false));

  SetupService();

  auto callback = [](TpmManagerServiceTestBase* self,
                     const GetTpmStatusReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_FALSE(reply.enabled());
    EXPECT_FALSE(reply.owned());
    EXPECT_FALSE(reply.has_local_data());
    self->Quit();
  };
  GetTpmStatusRequest request;
  service_->GetTpmStatus(request, base::BindOnce(callback, this));
  Run();
}

TEST_F(TpmManagerServiceTest_Preinit, GetVersionInfoSuccess) {
  EXPECT_CALL(mock_tpm_status_, GetVersionInfo(_, _, _, _, _, _))
      .WillOnce(Invoke([](uint32_t* family, uint64_t* spec_level,
                          uint32_t* manufacturer, uint32_t* tpm_model,
                          uint64_t* firmware_version,
                          std::vector<uint8_t>* vendor_specific) {
        *family = 1;
        *spec_level = 2;
        *manufacturer = 3;
        *tpm_model = 4;
        *firmware_version = 5;
        *vendor_specific = {'a', 'b'};
        return true;
      }));

  SetupService();

  auto callback = [](TpmManagerServiceTestBase* self, int* call_count,
                     base::Lock* call_count_lock,
                     const GetVersionInfoReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_EQ(1, reply.family());
    EXPECT_EQ(2, reply.spec_level());
    EXPECT_EQ(3, reply.manufacturer());
    EXPECT_EQ(4, reply.tpm_model());
    EXPECT_EQ(5, reply.firmware_version());
    EXPECT_EQ("ab", reply.vendor_specific());

    {
      base::AutoLock lock(*call_count_lock);
      ++*call_count;
      if (*call_count == 2) {
        self->Quit();
      }
    }
  };

  int count = 0;
  GetVersionInfoRequest request;
  base::Lock call_count_lock;

  // Only one of the following calls will get version info from the TPM. The
  // other call will return from cache directly.
  service_->GetVersionInfo(
      request, base::BindOnce(callback, this, &count, &call_count_lock));
  service_->GetVersionInfo(
      request, base::BindOnce(callback, this, &count, &call_count_lock));
  Run();
}

TEST_F(TpmManagerServiceTest_Preinit, GetVersionInfoError) {
  EXPECT_CALL(mock_tpm_status_, GetVersionInfo(_, _, _, _, _, _))
      .WillOnce(Return(false))
      .WillOnce(Return(false));

  SetupService();

  auto callback = [](TpmManagerServiceTestBase* self,
                     const GetVersionInfoReply& reply) {
    EXPECT_EQ(STATUS_DEVICE_ERROR, reply.status());
    self->Quit();
  };

  GetVersionInfoRequest request;
  service_->GetVersionInfo(request, base::BindOnce(callback, this));
  Run();
}

TEST_F(TpmManagerServiceTest, GetSupportedFeatures) {
  EXPECT_CALL(mock_tpm_status_, SupportU2f()).WillOnce(Return(true));

  auto callback = [](TpmManagerServiceTestBase* self,
                     const GetSupportedFeaturesReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_TRUE(reply.support_u2f());
    self->Quit();
  };

  GetSupportedFeaturesRequest request;
  service_->GetSupportedFeatures(request, base::BindOnce(callback, this));
  Run();
}

TEST_F(TpmManagerServiceTest, GetSupportedFeaturesFalse) {
  EXPECT_CALL(mock_tpm_status_, SupportU2f()).WillOnce(Return(false));

  auto callback = [](TpmManagerServiceTestBase* self,
                     const GetSupportedFeaturesReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_FALSE(reply.support_u2f());
    self->Quit();
  };

  GetSupportedFeaturesRequest request;
  service_->GetSupportedFeatures(request, base::BindOnce(callback, this));
  Run();
}

TEST_F(TpmManagerServiceTest, GetDictionaryAttackInfo) {
  EXPECT_CALL(mock_tpm_status_, GetDictionaryAttackInfo(_, _, _, _))
      .WillOnce(Invoke([](uint32_t* counter, uint32_t* threshold, bool* lockout,
                          uint32_t* seconds_remaining) {
        *counter = 5;
        *threshold = 6;
        *lockout = true;
        *seconds_remaining = 7;
        return true;
      }));

  auto callback = [](TpmManagerServiceTestBase* self,
                     const GetDictionaryAttackInfoReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_EQ(5, reply.dictionary_attack_counter());
    EXPECT_EQ(6, reply.dictionary_attack_threshold());
    EXPECT_TRUE(reply.dictionary_attack_lockout_in_effect());
    EXPECT_EQ(7, reply.dictionary_attack_lockout_seconds_remaining());
    self->Quit();
  };

  GetDictionaryAttackInfoRequest request;
  service_->GetDictionaryAttackInfo(request, base::BindOnce(callback, this));
  Run();
}

TEST_F(TpmManagerServiceTest, GetDictionaryAttackInfoError) {
  EXPECT_CALL(mock_tpm_status_, GetDictionaryAttackInfo(_, _, _, _))
      .WillOnce(Return(false));

  auto callback = [](TpmManagerServiceTestBase* self,
                     const GetDictionaryAttackInfoReply& reply) {
    EXPECT_EQ(STATUS_DEVICE_ERROR, reply.status());
    self->Quit();
  };

  GetDictionaryAttackInfoRequest request;
  service_->GetDictionaryAttackInfo(request, base::BindOnce(callback, this));
  Run();
}

TEST_F(TpmManagerServiceTest, ResetDictionaryAttackLockReset) {
  EXPECT_CALL(mock_tpm_status_, GetDictionaryAttackInfo(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<0>(1), Return(true)));
  EXPECT_CALL(mock_tpm_manager_metrics_, ReportDictionaryAttackCounter(1))
      .Times(1);
  EXPECT_CALL(mock_tpm_manager_metrics_,
              ReportDictionaryAttackResetStatus(
                  DictionaryAttackResetStatus::kResetAttemptSucceeded))
      .Times(1);
  EXPECT_CALL(mock_tpm_initializer_, ResetDictionaryAttackLock())
      .WillOnce(Return(DictionaryAttackResetStatus::kResetAttemptSucceeded));

  auto callback = [](TpmManagerServiceTestBase* self,
                     const ResetDictionaryAttackLockReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    self->Quit();
  };

  service_->ResetDictionaryAttackLock(ResetDictionaryAttackLockRequest(),
                                      base::BindOnce(callback, this));
  Run();
}

TEST_F(TpmManagerServiceTest, ResetDictionaryAttackLockSuccessNoNeed) {
  EXPECT_CALL(mock_tpm_status_, GetDictionaryAttackInfo(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<0>(0), Return(true)));
  EXPECT_CALL(mock_tpm_manager_metrics_,
              ReportDictionaryAttackResetStatus(
                  DictionaryAttackResetStatus::kResetNotNecessary))
      .Times(1);
  EXPECT_CALL(mock_tpm_manager_metrics_, ReportDictionaryAttackCounter(0))
      .Times(1);
  EXPECT_CALL(mock_tpm_initializer_, ResetDictionaryAttackLock()).Times(0);

  auto callback = [](TpmManagerServiceTest* self,
                     const ResetDictionaryAttackLockReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    self->Quit();
  };

  service_->ResetDictionaryAttackLock(ResetDictionaryAttackLockRequest(),
                                      base::BindOnce(callback, this));
  Run();
}

TEST_F(TpmManagerServiceTest, ResetDictionaryAttackLockFailure) {
  EXPECT_CALL(mock_tpm_status_, GetDictionaryAttackInfo(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<0>(1), Return(true)));
  EXPECT_CALL(mock_tpm_manager_metrics_, ReportDictionaryAttackCounter(1))
      .Times(1);
  EXPECT_CALL(mock_tpm_manager_metrics_,
              ReportDictionaryAttackResetStatus(
                  DictionaryAttackResetStatus::kResetAttemptFailed))
      .Times(1);
  EXPECT_CALL(mock_tpm_initializer_, ResetDictionaryAttackLock())
      .WillOnce(Return(DictionaryAttackResetStatus::kResetAttemptFailed));

  auto callback = [](TpmManagerServiceTestBase* self,
                     const ResetDictionaryAttackLockReply& reply) {
    EXPECT_EQ(STATUS_DEVICE_ERROR, reply.status());
    self->Quit();
  };

  service_->ResetDictionaryAttackLock(ResetDictionaryAttackLockRequest(),
                                      base::BindOnce(callback, this));
  Run();
}

TEST_F(TpmManagerServiceTest, TakeOwnershipSuccess) {
  // Make sure InitializeTpm doesn't get multiple calls.
  EXPECT_CALL(mock_tpm_initializer_, InitializeTpm(_)).Times(1);
  // Successful TPM initialization should trigger the DA reset and metrics
  // collection.
  EXPECT_CALL(mock_tpm_status_, GetDictionaryAttackInfo(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<0>(0), Return(true)));
  EXPECT_CALL(mock_tpm_manager_metrics_,
              ReportDictionaryAttackResetStatus(
                  DictionaryAttackResetStatus::kResetNotNecessary))
      .Times(1);
  EXPECT_CALL(mock_tpm_manager_metrics_, ReportDictionaryAttackCounter(0))
      .Times(1);
  EXPECT_CALL(mock_tpm_manager_metrics_, ReportTimeToTakeOwnership(_)).Times(1);
  auto callback = [](TpmManagerServiceTestBase* self,
                     const TakeOwnershipReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    self->Quit();
  };
  TakeOwnershipRequest request;
  service_->TakeOwnership(request, base::BindOnce(callback, this));
  Run();
}

TEST_F(TpmManagerServiceTest_Preinit, TakeOwnershipFailure) {
  EXPECT_CALL(mock_tpm_initializer_, InitializeTpm(_))
      .WillRepeatedly(Return(false));

  EXPECT_CALL(mock_tpm_manager_metrics_, ReportTimeToTakeOwnership(_)).Times(0);

  SetupService();

  auto callback = [](TpmManagerServiceTestBase* self,
                     const TakeOwnershipReply& reply) {
    EXPECT_EQ(STATUS_DEVICE_ERROR, reply.status());
    self->Quit();
  };
  TakeOwnershipRequest request;
  service_->TakeOwnership(request, base::BindOnce(callback, this));
  Run();
}

TEST_F(TpmManagerServiceTest_Preinit, TakeOwnershipNoTpm) {
  EXPECT_CALL(mock_tpm_status_, IsTpmEnabled()).WillRepeatedly(Return(false));
  EXPECT_CALL(mock_tpm_initializer_, InitializeTpm(_)).Times(0);

  EXPECT_CALL(mock_tpm_manager_metrics_, ReportTimeToTakeOwnership(_)).Times(0);

  SetupService();

  auto callback = [](TpmManagerServiceTestBase* self,
                     const TakeOwnershipReply& reply) {
    EXPECT_EQ(STATUS_NOT_AVAILABLE, reply.status());
    self->Quit();
  };
  TakeOwnershipRequest request;
  service_->TakeOwnership(request, base::BindOnce(callback, this));
  Run();
}

#if !USE_OS_INSTALL_SERVICE
TEST_F(TpmManagerServiceTest_NoPreinit, TakeOwnershipFollowedByDisableDA) {
  // Called in `InitializeTask()`.
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_))
      .WillOnce(DoAll(SetArgPointee<0>(TpmStatus::kTpmUnowned), Return(true)));
  EXPECT_CALL(mock_tpm_initializer_, InitializeTpm(_)).WillOnce(Return(true));
  EXPECT_CALL(mock_tpm_status_, IsDictionaryAttackMitigationEnabled(_))
      .WillOnce(DoAll(SetArgPointee<0>(true), Return(true)));
  EXPECT_CALL(mock_tpm_initializer_, DisableDictionaryAttackMitigation())
      .Times(1);

  SetupService();

  auto callback = [](TpmManagerServiceTestBase* self,
                     const TakeOwnershipReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    self->Quit();
  };
  TakeOwnershipRequest request;
  service_->TakeOwnership(request, base::BindOnce(callback, this));
  Run();
}
#endif

TEST_F(TpmManagerServiceTest_Preinit, RemoveOwnerDependencyReadFailure) {
  EXPECT_CALL(mock_local_data_store_, Read(_)).WillRepeatedly(Return(false));

  SetupService();

  auto callback = [](TpmManagerServiceTestBase* self,
                     const RemoveOwnerDependencyReply& reply) {
    EXPECT_EQ(STATUS_DEVICE_ERROR, reply.status());
    self->Quit();
  };
  RemoveOwnerDependencyRequest request;
  request.set_owner_dependency(kOwnerDependency);
  service_->RemoveOwnerDependency(request, base::BindOnce(callback, this));
  Run();
}

TEST_F(TpmManagerServiceTest_Preinit, RemoveOwnerDependencyWriteFailure) {
  EXPECT_CALL(mock_local_data_store_, Write(_)).WillRepeatedly(Return(false));

  SetupService();

  auto callback = [](TpmManagerServiceTestBase* self,
                     const RemoveOwnerDependencyReply& reply) {
    EXPECT_EQ(STATUS_DEVICE_ERROR, reply.status());
    self->Quit();
  };
  RemoveOwnerDependencyRequest request;
  request.set_owner_dependency(kOwnerDependency);
  service_->RemoveOwnerDependency(request, base::BindOnce(callback, this));
  Run();
}

TEST_F(TpmManagerServiceTest_Preinit, RemoveOwnerDependencyNotCleared) {
  LocalData local_data;
  local_data.set_owner_password(kOwnerPassword);
  local_data.add_owner_dependency(kOwnerDependency);
  local_data.add_owner_dependency(kOtherDependency);
  EXPECT_CALL(mock_local_data_store_, Read(_))
      .WillOnce(DoAll(SetArgPointee<0>(local_data), Return(true)))
      .WillOnce(DoAll(SetArgPointee<0>(local_data), Return(true)));
  EXPECT_CALL(mock_local_data_store_, Write(_))
      .WillOnce(DoAll(SaveArg<0>(&local_data), Return(true)));

  SetupService();

  auto callback = [](TpmManagerServiceTestBase* self, LocalData* data,
                     const RemoveOwnerDependencyReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_EQ(1, data->owner_dependency_size());
    EXPECT_EQ(kOtherDependency, data->owner_dependency(0));
    EXPECT_TRUE(data->has_owner_password());
    EXPECT_EQ(kOwnerPassword, data->owner_password());
    self->Quit();
  };
  RemoveOwnerDependencyRequest request;
  request.set_owner_dependency(kOwnerDependency);
  service_->RemoveOwnerDependency(request,
                                  base::BindOnce(callback, this, &local_data));
  Run();
}

TEST_F(TpmManagerServiceTest_Preinit, RemoveOwnerDependencyCleared) {
  LocalData local_data;
  local_data.set_owner_password(kOwnerPassword);
  local_data.add_owner_dependency(kOwnerDependency);
  EXPECT_CALL(mock_local_data_store_, Read(_))
      .WillOnce(DoAll(SetArgPointee<0>(local_data), Return(true)))
      .WillOnce(DoAll(SetArgPointee<0>(local_data), Return(true)));
  EXPECT_CALL(mock_local_data_store_, Write(_))
      .WillOnce(DoAll(SaveArg<0>(&local_data), Return(true)));

  SetupService();

  auto callback = [](TpmManagerServiceTestBase* self, LocalData* data,
                     const RemoveOwnerDependencyReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_EQ(0, data->owner_dependency_size());
    EXPECT_TRUE(data->has_owner_password());
    self->Quit();
  };
  RemoveOwnerDependencyRequest request;
  request.set_owner_dependency(kOwnerDependency);
  service_->RemoveOwnerDependency(request,
                                  base::BindOnce(callback, this, &local_data));
  Run();
}

TEST_F(TpmManagerServiceTest_Preinit, RemoveOwnerDependencyNotPresent) {
  LocalData local_data;
  local_data.set_owner_password(kOwnerPassword);
  local_data.add_owner_dependency(kOwnerDependency);
  EXPECT_CALL(mock_local_data_store_, Read(_))
      .WillOnce(DoAll(SetArgPointee<0>(local_data), Return(true)))
      .WillOnce(DoAll(SetArgPointee<0>(local_data), Return(true)));
  EXPECT_CALL(mock_local_data_store_, Write(_))
      .WillOnce(DoAll(SaveArg<0>(&local_data), Return(true)));

  SetupService();

  auto callback = [](TpmManagerServiceTestBase* self, LocalData* data,
                     const RemoveOwnerDependencyReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_EQ(1, data->owner_dependency_size());
    EXPECT_EQ(kOwnerDependency, data->owner_dependency(0));
    EXPECT_TRUE(data->has_owner_password());
    EXPECT_EQ(kOwnerPassword, data->owner_password());
    self->Quit();
  };
  RemoveOwnerDependencyRequest request;
  request.set_owner_dependency(kOtherDependency);
  service_->RemoveOwnerDependency(request,
                                  base::BindOnce(callback, this, &local_data));
  Run();
}

TEST_F(TpmManagerServiceTest_Preinit, ClearStoredOwnerPasswordReadFailure) {
  EXPECT_CALL(mock_local_data_store_, Read(_)).WillRepeatedly(Return(false));

  SetupService();

  auto callback = [](TpmManagerServiceTestBase* self,
                     const ClearStoredOwnerPasswordReply& reply) {
    EXPECT_EQ(STATUS_DEVICE_ERROR, reply.status());
    self->Quit();
  };
  ClearStoredOwnerPasswordRequest request;
  service_->ClearStoredOwnerPassword(request, base::BindOnce(callback, this));
  Run();
}

TEST_F(TpmManagerServiceTest_Preinit, ClearStoredOwnerPasswordWriteFailure) {
  LocalData local_data;
  local_data.set_owner_password(kOwnerPassword);
  EXPECT_CALL(mock_local_data_store_, Read(_))
      .WillOnce(DoAll(SetArgPointee<0>(local_data), Return(true)))
      .WillOnce(DoAll(SetArgPointee<0>(local_data), Return(true)));
  EXPECT_CALL(mock_local_data_store_, Write(_)).WillRepeatedly(Return(false));

  SetupService();

  auto callback = [](TpmManagerServiceTestBase* self,
                     const ClearStoredOwnerPasswordReply& reply) {
    EXPECT_EQ(STATUS_DEVICE_ERROR, reply.status());
    self->Quit();
  };
  ClearStoredOwnerPasswordRequest request;
  service_->ClearStoredOwnerPassword(request, base::BindOnce(callback, this));
  Run();
}

TEST_F(TpmManagerServiceTest_Preinit,
       ClearStoredOwnerPasswordRemainingDependencies) {
  LocalData local_data;
  local_data.set_owner_password(kOwnerPassword);
  local_data.add_owner_dependency(kOwnerDependency);
  local_data.add_owner_dependency(kOtherDependency);
  EXPECT_CALL(mock_local_data_store_, Read(_))
      .WillOnce(DoAll(SetArgPointee<0>(local_data), Return(true)))
      .WillOnce(DoAll(SetArgPointee<0>(local_data), Return(true)));
  EXPECT_CALL(mock_local_data_store_, Write(_)).Times(0);

  SetupService();

  auto callback = [](TpmManagerServiceTestBase* self, LocalData* data,
                     const ClearStoredOwnerPasswordReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_TRUE(data->has_owner_password());
    EXPECT_EQ(kOwnerPassword, data->owner_password());
    self->Quit();
  };
  ClearStoredOwnerPasswordRequest request;
  service_->ClearStoredOwnerPassword(
      request, base::BindOnce(callback, this, &local_data));
  Run();
}

TEST_F(TpmManagerServiceTest_Preinit, ClearStoredOwnerPasswordNoDependencies) {
  LocalData local_data;
  local_data.set_owner_password(kOwnerPassword);
  local_data.set_endorsement_password("endorsement password");
  local_data.set_lockout_password("lockout password");
  EXPECT_CALL(mock_local_data_store_, Read(_))
      .WillOnce(DoAll(SetArgPointee<0>(local_data), Return(true)))
      .WillOnce(DoAll(SetArgPointee<0>(local_data), Return(true)));
  EXPECT_CALL(mock_local_data_store_, Write(_))
      .WillOnce(DoAll(SaveArg<0>(&local_data), Return(true)));

  SetupService();

  auto callback = [](TpmManagerServiceTestBase* self, LocalData* data,
                     const ClearStoredOwnerPasswordReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_FALSE(data->has_owner_password());
    EXPECT_TRUE(data->has_endorsement_password());
    EXPECT_TRUE(data->has_lockout_password());
    self->Quit();
  };
  ClearStoredOwnerPasswordRequest request;
  service_->ClearStoredOwnerPassword(
      request, base::BindOnce(callback, this, &local_data));
  Run();
}

TEST_F(TpmManagerServiceTest, DefineSpaceFailure) {
  uint32_t nvram_index = 5;
  size_t nvram_size = 32;
  std::vector<NvramSpaceAttribute> attributes{NVRAM_BOOT_WRITE_LOCK};
  NvramSpacePolicy policy = NVRAM_POLICY_PCR0;
  std::string auth_value = "1234";
  EXPECT_CALL(mock_tpm_nvram_, DefineSpace(nvram_index, nvram_size, attributes,
                                           auth_value, policy))
      .WillRepeatedly(Return(NVRAM_RESULT_INVALID_PARAMETER));
  auto callback = [](TpmManagerServiceTestBase* self,
                     const DefineSpaceReply& reply) {
    EXPECT_EQ(NVRAM_RESULT_INVALID_PARAMETER, reply.result());
    self->Quit();
  };
  DefineSpaceRequest request;
  request.set_index(nvram_index);
  request.set_size(nvram_size);
  request.add_attributes(NVRAM_BOOT_WRITE_LOCK);
  request.set_policy(policy);
  request.set_authorization_value(auth_value);
  service_->DefineSpace(request, base::BindOnce(callback, this));
  Run();
}

TEST_F(TpmManagerServiceTest, DefineSpaceSuccess) {
  uint32_t nvram_index = 5;
  uint32_t nvram_size = 32;
  auto define_callback = [](const DefineSpaceReply& reply) {
    EXPECT_EQ(NVRAM_RESULT_SUCCESS, reply.result());
  };
  auto list_callback = [](uint32_t index, const ListSpacesReply& reply) {
    EXPECT_EQ(NVRAM_RESULT_SUCCESS, reply.result());
    EXPECT_EQ(1, reply.index_list_size());
    EXPECT_EQ(index, reply.index_list(0));
  };
  auto info_callback = [](uint32_t size, const GetSpaceInfoReply& reply) {
    EXPECT_EQ(NVRAM_RESULT_SUCCESS, reply.result());
    EXPECT_EQ(size, reply.size());
  };
  DefineSpaceRequest define_request;
  define_request.set_index(nvram_index);
  define_request.set_size(nvram_size);
  service_->DefineSpace(define_request, base::BindOnce(define_callback));
  ListSpacesRequest list_request;
  service_->ListSpaces(list_request,
                       base::BindOnce(list_callback, nvram_index));
  GetSpaceInfoRequest info_request;
  info_request.set_index(nvram_index);
  service_->GetSpaceInfo(info_request,
                         base::BindOnce(info_callback, nvram_size));
  RunServiceWorkerAndQuit();
}

TEST_F(TpmManagerServiceTest, DestroyUnitializedNvram) {
  auto callback = [](TpmManagerServiceTestBase* self,
                     const DestroySpaceReply& reply) {
    EXPECT_EQ(NVRAM_RESULT_SPACE_DOES_NOT_EXIST, reply.result());
    self->Quit();
  };
  DestroySpaceRequest request;
  service_->DestroySpace(request, base::BindOnce(callback, this));
  Run();
}

TEST_F(TpmManagerServiceTest, DestroySpaceSuccess) {
  uint32_t nvram_index = 5;
  uint32_t nvram_size = 32;
  auto define_callback = [](const DefineSpaceReply& reply) {
    EXPECT_EQ(NVRAM_RESULT_SUCCESS, reply.result());
  };
  auto destroy_callback = [](const DestroySpaceReply& reply) {
    EXPECT_EQ(NVRAM_RESULT_SUCCESS, reply.result());
  };
  DefineSpaceRequest define_request;
  define_request.set_index(nvram_index);
  define_request.set_size(nvram_size);
  service_->DefineSpace(define_request, base::BindOnce(define_callback));
  DestroySpaceRequest destroy_request;
  destroy_request.set_index(nvram_index);
  service_->DestroySpace(destroy_request, base::BindOnce(destroy_callback));
  RunServiceWorkerAndQuit();
}

TEST_F(TpmManagerServiceTest, DoubleDestroySpace) {
  uint32_t nvram_index = 5;
  uint32_t nvram_size = 32;
  auto define_callback = [](const DefineSpaceReply& reply) {
    EXPECT_EQ(NVRAM_RESULT_SUCCESS, reply.result());
  };
  auto destroy_callback_success = [](const DestroySpaceReply& reply) {
    EXPECT_EQ(NVRAM_RESULT_SUCCESS, reply.result());
  };
  auto destroy_callback_failure = [](const DestroySpaceReply& reply) {
    EXPECT_EQ(NVRAM_RESULT_SPACE_DOES_NOT_EXIST, reply.result());
  };
  DefineSpaceRequest define_request;
  define_request.set_index(nvram_index);
  define_request.set_size(nvram_size);
  service_->DefineSpace(define_request, base::BindOnce(define_callback));
  DestroySpaceRequest destroy_request;
  destroy_request.set_index(nvram_index);
  service_->DestroySpace(destroy_request,
                         base::BindOnce(destroy_callback_success));
  service_->DestroySpace(destroy_request,
                         base::BindOnce(destroy_callback_failure));
  RunServiceWorkerAndQuit();
}

TEST_F(TpmManagerServiceTest, WriteSpaceIncorrectSize) {
  uint32_t nvram_index = 5;
  std::string nvram_data("nvram_data");
  auto define_callback = [](const DefineSpaceReply& reply) {
    EXPECT_EQ(NVRAM_RESULT_SUCCESS, reply.result());
  };
  auto write_callback = [](const WriteSpaceReply& reply) {
    EXPECT_EQ(NVRAM_RESULT_INVALID_PARAMETER, reply.result());
  };
  DefineSpaceRequest define_request;
  define_request.set_index(nvram_index);
  define_request.set_size(nvram_data.size() - 1);
  service_->DefineSpace(define_request, base::BindOnce(define_callback));
  WriteSpaceRequest write_request;
  write_request.set_index(nvram_index);
  write_request.set_data(nvram_data);
  service_->WriteSpace(write_request, base::BindOnce(write_callback));
  RunServiceWorkerAndQuit();
}

TEST_F(TpmManagerServiceTest, WriteBeforeAfterLock) {
  uint32_t nvram_index = 5;
  std::string nvram_data("nvram_data");
  auto define_callback = [](const DefineSpaceReply& reply) {
    EXPECT_EQ(NVRAM_RESULT_SUCCESS, reply.result());
  };
  auto write_callback_success = [](const WriteSpaceReply& reply) {
    EXPECT_EQ(NVRAM_RESULT_SUCCESS, reply.result());
  };
  auto lock_callback = [](const LockSpaceReply& reply) {
    EXPECT_EQ(NVRAM_RESULT_SUCCESS, reply.result());
  };
  auto write_callback_failure = [](const WriteSpaceReply& reply) {
    EXPECT_EQ(NVRAM_RESULT_OPERATION_DISABLED, reply.result());
  };
  DefineSpaceRequest define_request;
  define_request.set_index(nvram_index);
  define_request.set_size(nvram_data.size());
  service_->DefineSpace(define_request, base::BindOnce(define_callback));
  WriteSpaceRequest write_request;
  write_request.set_index(nvram_index);
  write_request.set_data(nvram_data);
  service_->WriteSpace(write_request, base::BindOnce(write_callback_success));
  LockSpaceRequest lock_request;
  lock_request.set_index(nvram_index);
  lock_request.set_lock_write(true);
  service_->LockSpace(lock_request, base::BindOnce(lock_callback));
  service_->WriteSpace(write_request, base::BindOnce(write_callback_failure));
  RunServiceWorkerAndQuit();
}

TEST_F(TpmManagerServiceTest, ReadUninitializedNvram) {
  auto callback = [](TpmManagerServiceTestBase* self,
                     const ReadSpaceReply& reply) {
    EXPECT_EQ(NVRAM_RESULT_SPACE_DOES_NOT_EXIST, reply.result());
    self->Quit();
  };
  ReadSpaceRequest request;
  service_->ReadSpace(request, base::BindOnce(callback, this));
  Run();
}

TEST_F(TpmManagerServiceTest, ReadWriteSpaceSuccess) {
  uint32_t nvram_index = 5;
  std::string nvram_data("nvram_data");
  auto define_callback = [](const DefineSpaceReply& reply) {
    EXPECT_EQ(NVRAM_RESULT_SUCCESS, reply.result());
  };
  auto write_callback = [](const WriteSpaceReply& reply) {
    EXPECT_EQ(NVRAM_RESULT_SUCCESS, reply.result());
  };
  auto read_callback = [](const std::string& data,
                          const ReadSpaceReply& reply) {
    EXPECT_EQ(NVRAM_RESULT_SUCCESS, reply.result());
    EXPECT_EQ(data, reply.data());
  };
  DefineSpaceRequest define_request;
  define_request.set_index(nvram_index);
  define_request.set_size(nvram_data.size());
  service_->DefineSpace(define_request, base::BindOnce(define_callback));
  WriteSpaceRequest write_request;
  write_request.set_index(nvram_index);
  write_request.set_data(nvram_data);
  service_->WriteSpace(write_request, base::BindOnce(write_callback));
  ReadSpaceRequest read_request;
  read_request.set_index(nvram_index);
  service_->ReadSpace(read_request, base::BindOnce(read_callback, nvram_data));
  RunServiceWorkerAndQuit();
}

#if USE_TPM_DYNAMIC || (!USE_TPM1 && !USE_TPM2)
TEST_F(TpmManagerServiceTest_NoSetup, TpmManagerNoCrash) {
  SET_NO_TPM_FOR_TESTING;
  EXPECT_CALL(mock_tpm_manager_metrics_, ReportVersionFingerprint(_))
      .Times(AtMost(1));
  service_.reset(new TpmManagerService(true, &mock_local_data_store_));
  DisablePeriodicDictionaryAttackReset();
  SetupService();
  service_->GetVersionInfo(GetVersionInfoRequest(), base::DoNothing());
  service_->GetSupportedFeatures(GetSupportedFeaturesRequest(),
                                 base::DoNothing());
  service_->ResetDictionaryAttackLock(ResetDictionaryAttackLockRequest(),
                                      base::DoNothing());
  service_->TakeOwnership(TakeOwnershipRequest(), base::DoNothing());
  service_->RemoveOwnerDependency(RemoveOwnerDependencyRequest(),
                                  base::DoNothing());
  service_->ClearStoredOwnerPassword(ClearStoredOwnerPasswordRequest(),
                                     base::DoNothing());
  service_->DefineSpace(DefineSpaceRequest(), base::DoNothing());
  service_->ListSpaces(ListSpacesRequest(), base::DoNothing());
  service_->GetSpaceInfo(GetSpaceInfoRequest(), base::DoNothing());
  service_->DestroySpace(DestroySpaceRequest(), base::DoNothing());
  service_->WriteSpace(WriteSpaceRequest(), base::DoNothing());
  service_->LockSpace(LockSpaceRequest(), base::DoNothing());
  service_->ReadSpace(ReadSpaceRequest(), base::DoNothing());
  service_->GetTpmStatus(GetTpmStatusRequest(), base::DoNothing());
  service_->GetTpmNonsensitiveStatus(GetTpmNonsensitiveStatusRequest(),
                                     base::DoNothing());
  RunServiceWorkerAndQuit();
}
#endif

TEST_F(TpmManagerServiceTest_Preinit, TpmManagerTpmNotAllowedNoCrash) {
  EXPECT_CALL(mock_tpm_allowlist_, IsAllowed()).WillRepeatedly(Return(false));

  SetupService();

  service_->GetVersionInfo(GetVersionInfoRequest(), base::DoNothing());
  service_->GetSupportedFeatures(GetSupportedFeaturesRequest(),
                                 base::DoNothing());
  service_->ResetDictionaryAttackLock(ResetDictionaryAttackLockRequest(),
                                      base::DoNothing());
  service_->TakeOwnership(TakeOwnershipRequest(), base::DoNothing());
  service_->RemoveOwnerDependency(RemoveOwnerDependencyRequest(),
                                  base::DoNothing());
  service_->ClearStoredOwnerPassword(ClearStoredOwnerPasswordRequest(),
                                     base::DoNothing());
  service_->DefineSpace(DefineSpaceRequest(), base::DoNothing());
  service_->ListSpaces(ListSpacesRequest(), base::DoNothing());
  service_->GetSpaceInfo(GetSpaceInfoRequest(), base::DoNothing());
  service_->DestroySpace(DestroySpaceRequest(), base::DoNothing());
  service_->WriteSpace(WriteSpaceRequest(), base::DoNothing());
  service_->LockSpace(LockSpaceRequest(), base::DoNothing());
  service_->ReadSpace(ReadSpaceRequest(), base::DoNothing());
  service_->GetTpmStatus(GetTpmStatusRequest(), base::DoNothing());
  service_->GetTpmNonsensitiveStatus(GetTpmNonsensitiveStatusRequest(),
                                     base::DoNothing());
  RunServiceWorkerAndQuit();
}

#if !USE_OS_INSTALL_SERVICE
TEST_F(TpmManagerServiceTest_NoPreinit, UpdateTpmStatusAfterTakeOwnership) {
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_))
      .WillOnce(DoAll(SetArgPointee<0>(TpmStatus::kTpmUnowned), Return(true)))
      .WillOnce(DoAll(SetArgPointee<0>(TpmStatus::kTpmOwned), Return(true)));
  LocalData local_data;
  local_data.set_owner_password(kOwnerPassword);
  EXPECT_CALL(mock_local_data_store_, Read(_))
      .WillOnce(Return(true))
      .WillOnce(DoAll(SetArgPointee<0>(local_data), Return(true)));

  EXPECT_CALL(mock_tpm_initializer_, InitializeTpm(_))
      .WillOnce(DoAll(SetArgPointee<0>(false), Return(true)));

  EXPECT_CALL(mock_tpm_manager_metrics_, ReportDictionaryAttackCounter(0))
      .Times(1);
  EXPECT_CALL(mock_tpm_manager_metrics_,
              ReportDictionaryAttackResetStatus(
                  DictionaryAttackResetStatus::kResetNotNecessary))
      .Times(1);

  EXPECT_CALL(mock_tpm_manager_metrics_, ReportTimeToTakeOwnership(_)).Times(1);

  SetupService();

  auto callback_owned = [](TpmManagerServiceTestBase* self,
                           const GetTpmStatusReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_TRUE(reply.enabled());
    EXPECT_TRUE(reply.owned());
    EXPECT_EQ(kOwnerPassword, reply.local_data().owner_password());
    self->Quit();
  };

  auto callback_unowned = [](const GetTpmStatusReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_TRUE(reply.enabled());
    EXPECT_FALSE(reply.owned());
    EXPECT_EQ("", reply.local_data().owner_password());
  };

  auto callback_taken = [&](const TakeOwnershipReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    GetTpmStatusRequest request;
    service_->GetTpmStatus(request, base::BindOnce(callback_owned, this));
  };

  GetTpmStatusRequest get_request;
  service_->GetTpmStatus(get_request, base::BindOnce(callback_unowned));
  TakeOwnershipRequest take_request;
  service_->TakeOwnership(take_request,
                          base::BindLambdaForTesting(callback_taken));
  Run();
}
#endif

TEST_F(TpmManagerServiceTest_Preinit, RetryGetTpmStatusUntilSuccess) {
  EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_))
      .WillRepeatedly(Return(false));  // Called in InitializeTask()

  EXPECT_CALL(mock_tpm_manager_metrics_, ReportDictionaryAttackCounter(0))
      .Times(1);
  EXPECT_CALL(mock_tpm_manager_metrics_,
              ReportDictionaryAttackResetStatus(
                  DictionaryAttackResetStatus::kResetNotNecessary))
      .Times(1);

  LocalData local_data;
  local_data.set_owner_password(kOwnerPassword);
  EXPECT_CALL(mock_local_data_store_, Read(_))
      .WillOnce(DoAll(SetArgPointee<0>(local_data), Return(true)))
      // Extra call for ignoring cache.
      .WillOnce(DoAll(SetArgPointee<0>(local_data), Return(true)));

  SetupService();
  auto owned_check = [](const GetTpmStatusReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_TRUE(reply.enabled());
    EXPECT_TRUE(reply.owned());
    EXPECT_EQ(kOwnerPassword, reply.local_data().owner_password());
  };

  auto owned_check_quit = [&](const GetTpmStatusReply& reply) {
    owned_check(reply);
    Quit();
  };

  int counter = 3;
  base::RepeatingCallback<void(const GetTpmStatusReply&)> callback_fail;
  auto callback_fail_lambda = [&](const GetTpmStatusReply& reply) {
    EXPECT_EQ(STATUS_DEVICE_ERROR, reply.status());
    GetTpmStatusRequest request;
    counter--;
    if (counter) {
      service_->GetTpmStatus(request, base::BindOnce(callback_fail));
    } else {
      service_->GetTpmStatus(request, base::BindOnce(owned_check));
      // Call it multiple times to check the cache is working.
      service_->GetTpmStatus(request, base::BindOnce(owned_check));
      service_->GetTpmStatus(request, base::BindOnce(owned_check));
      service_->GetTpmStatus(request, base::BindOnce(owned_check));
      service_->GetTpmStatus(request, base::BindOnce(owned_check));

      // Chaining the ignore cache callback.
      auto ignore_cache_callback = [&](const GetTpmStatusReply& reply) {
        owned_check(reply);
        GetTpmStatusRequest request;
        request.set_ignore_cache(true);
        service_->GetTpmStatus(request,
                               base::BindLambdaForTesting(owned_check_quit));
      };
      service_->GetTpmStatus(request,
                             base::BindLambdaForTesting(ignore_cache_callback));
    }
  };
  callback_fail = base::BindLambdaForTesting(callback_fail_lambda);

  auto callback_first_fail = [&](const GetTpmStatusReply& reply) {
    EXPECT_EQ(STATUS_DEVICE_ERROR, reply.status());

    // Overwrite the GetTpmOwned return mode
    EXPECT_CALL(mock_tpm_status_, GetTpmOwned(_))
        .WillOnce(Return(false))  // Called in GetTpmStatusTask()
        .WillOnce(Return(false))  // Called in GetTpmStatusTask()
        .WillOnce(Return(false))  // Called in GetTpmStatusTask()
        .WillOnce(DoAll(SetArgPointee<0>(TpmStatus::kTpmOwned), Return(true)))
        // Extra call for ignoring cache.
        .WillOnce(DoAll(SetArgPointee<0>(TpmStatus::kTpmOwned), Return(true)));

    GetTpmStatusRequest request;
    service_->GetTpmStatus(request, base::BindOnce(callback_fail));
  };

  GetTpmStatusRequest request;
  service_->GetTpmStatus(request,
                         base::BindLambdaForTesting(callback_first_fail));
  Run();
}

namespace {

bool operator==(const SecretStatus& lhs, const SecretStatus& rhs) {
  return lhs.has_owner_password == rhs.has_owner_password &&
         lhs.has_endorsement_password == rhs.has_endorsement_password &&
         lhs.has_lockout_password == rhs.has_lockout_password &&
         lhs.has_owner_delegate == rhs.has_owner_delegate &&
         lhs.has_reset_lock_permissions == rhs.has_reset_lock_permissions;
}

}  // namespace

class TpmManagerServiceTest_SecretStatus
    : public TpmManagerServiceTest_Preinit {};

TEST_F(TpmManagerServiceTest_SecretStatus, OwnerPassword) {
  LocalData local_data;
  local_data.set_owner_password(kOwnerPassword);
  EXPECT_CALL(mock_local_data_store_, Read(_))
      .WillOnce(DoAll(SetArgPointee<0>(local_data), Return(true)));

  const SecretStatus expected_status = {
      .has_owner_password = true,
  };
  SecretStatus result_status;
  EXPECT_CALL(mock_tpm_manager_metrics_, ReportSecretStatus(_))
      .WillOnce(SaveArg<0>(&result_status));

  SetupService();
  RunServiceWorkerAndQuit();

  EXPECT_TRUE(expected_status == result_status);
}

TEST_F(TpmManagerServiceTest_SecretStatus, EndorsementPassword) {
  LocalData local_data;
  local_data.set_endorsement_password("endorsement");
  EXPECT_CALL(mock_local_data_store_, Read(_))
      .WillOnce(DoAll(SetArgPointee<0>(local_data), Return(true)));

  const SecretStatus expected_status = {
      .has_endorsement_password = true,
  };
  SecretStatus result_status;
  EXPECT_CALL(mock_tpm_manager_metrics_, ReportSecretStatus(_))
      .WillOnce(SaveArg<0>(&result_status));

  SetupService();
  RunServiceWorkerAndQuit();

  EXPECT_TRUE(expected_status == result_status);
}

TEST_F(TpmManagerServiceTest_SecretStatus, LockoutPassword) {
  LocalData local_data;
  local_data.set_lockout_password("lockout");
  EXPECT_CALL(mock_local_data_store_, Read(_))
      .WillOnce(DoAll(SetArgPointee<0>(local_data), Return(true)));

  const SecretStatus expected_status = {
      .has_lockout_password = true,
      .has_reset_lock_permissions = true,
  };
  SecretStatus result_status;
  EXPECT_CALL(mock_tpm_manager_metrics_, ReportSecretStatus(_))
      .WillOnce(SaveArg<0>(&result_status));

  SetupService();
  RunServiceWorkerAndQuit();

  EXPECT_TRUE(expected_status == result_status);
}

TEST_F(TpmManagerServiceTest_SecretStatus, OwnerDelegate) {
  LocalData local_data;
  local_data.mutable_owner_delegate()->set_secret("secret");
  local_data.mutable_owner_delegate()->set_blob("blob");
  EXPECT_CALL(mock_local_data_store_, Read(_))
      .WillOnce(DoAll(SetArgPointee<0>(local_data), Return(true)));

  const SecretStatus expected_status = {
      .has_owner_delegate = true,
  };
  SecretStatus result_status;
  EXPECT_CALL(mock_tpm_manager_metrics_, ReportSecretStatus(_))
      .WillOnce(SaveArg<0>(&result_status));

  SetupService();
  RunServiceWorkerAndQuit();

  EXPECT_TRUE(expected_status == result_status);
}

TEST_F(TpmManagerServiceTest_SecretStatus, OwnerDelegateCanResetDA) {
  LocalData local_data;
  local_data.mutable_owner_delegate()->set_secret("secret");
  local_data.mutable_owner_delegate()->set_blob("blob");
  local_data.mutable_owner_delegate()->set_has_reset_lock_permissions(true);
  EXPECT_CALL(mock_local_data_store_, Read(_))
      .WillOnce(DoAll(SetArgPointee<0>(local_data), Return(true)));

  const SecretStatus expected_status = {
      .has_owner_delegate = true,
      .has_reset_lock_permissions = true,
  };
  SecretStatus result_status;
  EXPECT_CALL(mock_tpm_manager_metrics_, ReportSecretStatus(_))
      .WillOnce(SaveArg<0>(&result_status));

  SetupService();
  RunServiceWorkerAndQuit();

  EXPECT_TRUE(expected_status == result_status);
}

}  // namespace tpm_manager
