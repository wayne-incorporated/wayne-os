// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

#include <base/test/task_environment.h>
#include <brillo/dbus/dbus_object_test_helpers.h>
#include <brillo/message_loops/base_message_loop.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_exported_object.h>
#include <dbus/mock_object_proxy.h>
#include <gmock/gmock.h>
#include <hps/daemon/dbus_adaptor.h>
#include <hps/hps.h>

using brillo::dbus_utils::AsyncEventSequencer;
using testing::_;
using testing::InSequence;
using testing::NiceMock;
using testing::Return;
using testing::StrictMock;

namespace hps {

class MockHps : public HPS {
 public:
  MOCK_METHOD(void,
              Init,
              (uint32_t,
               const base::FilePath&,
               const base::FilePath&,
               const base::FilePath&),
              (override));
  MOCK_METHOD(void, Boot, (), (override));
  MOCK_METHOD(bool, ShutDown, (), (override));
  MOCK_METHOD(bool, IsRunning, (), (override));
  MOCK_METHOD(bool, Enable, (uint8_t), (override));
  MOCK_METHOD(bool, Disable, (uint8_t), (override));
  MOCK_METHOD(FeatureResult, Result, (int), (override));
  MOCK_METHOD(DevInterface*, Device, (), (override));
  MOCK_METHOD(bool, Download, (HpsBank, const base::FilePath&), (override));
  MOCK_METHOD(void, SetDownloadObserver, (DownloadObserver), (override));
};

class HpsDaemonTest : public testing::Test {
 public:
  HpsDaemonTest() {
    dbus::Bus::Options options;
    mock_bus_ = base::MakeRefCounted<NiceMock<dbus::MockBus>>(options);
    dbus::ObjectPath path(::hps::kHpsServicePath);

    mock_object_proxy_ = base::MakeRefCounted<NiceMock<dbus::MockObjectProxy>>(
        mock_bus_.get(), kHpsServicePath, path);

    mock_exported_object_ =
        base::MakeRefCounted<StrictMock<dbus::MockExportedObject>>(
            mock_bus_.get(), path);

    ON_CALL(*mock_bus_, GetExportedObject(path))
        .WillByDefault(Return(mock_exported_object_.get()));

    ON_CALL(*mock_bus_, GetDBusTaskRunner())
        .WillByDefault(
            Return(task_environment_.GetMainThreadTaskRunner().get()));

    EXPECT_CALL(*mock_exported_object_, ExportMethod(_, _, _, _))
        .Times(testing::AnyNumber());

    auto hps = std::make_unique<StrictMock<MockHps>>();
    mock_hps_ = hps.get();
    EXPECT_CALL(*mock_hps_, ShutDown()).WillOnce(Return(true));
    hps_daemon_.reset(
        new DBusAdaptor(mock_bus_, std::move(hps),
                        static_cast<uint32_t>(kPollTime.InMilliseconds())));

    feature_config_.set_allocated_basic_filter_config(
        new FeatureConfig_BasicFilterConfig());

    brillo_loop_.SetAsCurrent();
  }

 protected:
  base::test::SingleThreadTaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  brillo::BaseMessageLoop brillo_loop_{
      task_environment_.GetMainThreadTaskRunner().get()};

  scoped_refptr<dbus::MockBus> mock_bus_;
  scoped_refptr<dbus::MockObjectProxy> mock_object_proxy_;
  scoped_refptr<dbus::MockExportedObject> mock_exported_object_;
  StrictMock<MockHps>* mock_hps_;
  std::unique_ptr<DBusAdaptor> hps_daemon_;
  FeatureConfig feature_config_;
  static constexpr base::TimeDelta kPollTime = base::Milliseconds(500);
};

// Failing to enable or disable a feature at the hardware level should trigger a
// crash.
TEST_F(HpsDaemonTest, EnableFeatureFailed) {
  EXPECT_DEATH(
      {
        EXPECT_CALL(*mock_hps_, Boot());
        EXPECT_CALL(*mock_hps_, Enable(0)).WillOnce(Return(false));
        brillo::ErrorPtr error;
        hps_daemon_->EnableHpsSense(&error, feature_config_);
      },
      ".*Failed to enable feature.*");
}

TEST_F(HpsDaemonTest, DisableFeatureFailed) {
  EXPECT_DEATH(
      {
        EXPECT_CALL(*mock_hps_, Boot());
        EXPECT_CALL(*mock_hps_, Enable(0)).WillOnce(Return(true));
        EXPECT_CALL(*mock_hps_, IsRunning()).WillOnce(Return(true));
        EXPECT_CALL(*mock_hps_, Disable(0)).WillOnce(Return(false));
        brillo::ErrorPtr error;
        EXPECT_TRUE(hps_daemon_->EnableHpsSense(&error, feature_config_));
        hps_daemon_->DisableHpsSense(&error);
      },
      ".*Failed to disable feature.*");
}

TEST_F(HpsDaemonTest, EnableFeatureReady) {
  EXPECT_CALL(*mock_hps_, Boot());
  EXPECT_CALL(*mock_hps_, Enable(0)).WillOnce(Return(true));
  brillo::ErrorPtr error;
  bool result = hps_daemon_->EnableHpsSense(&error, feature_config_);
  EXPECT_TRUE(result);
}

TEST_F(HpsDaemonTest, DisableFeatureNotEnabled) {
  brillo::ErrorPtr error;
  bool result = hps_daemon_->DisableHpsSense(&error);
  EXPECT_FALSE(result);
}

// With another feature still enabled the device is not shutdown
TEST_F(HpsDaemonTest, DisableFeatureReady) {
  EXPECT_CALL(*mock_hps_, Boot());
  EXPECT_CALL(*mock_hps_, IsRunning()).WillRepeatedly(Return(true));
  EXPECT_CALL(*mock_hps_, Enable(0)).WillOnce(Return(true));
  EXPECT_CALL(*mock_hps_, Enable(1)).WillOnce(Return(true));
  EXPECT_CALL(*mock_hps_, Disable(0)).WillOnce(Return(true));
  brillo::ErrorPtr error;
  ASSERT_TRUE(hps_daemon_->EnableHpsSense(&error, feature_config_));
  ASSERT_TRUE(hps_daemon_->EnableHpsNotify(&error, feature_config_));
  bool result = hps_daemon_->DisableHpsSense(&error);
  EXPECT_TRUE(result);
}

// When the last feature is disabled the device is shutdown
TEST_F(HpsDaemonTest, DisableFeatureReadyLast) {
  EXPECT_CALL(*mock_hps_, Boot());
  EXPECT_CALL(*mock_hps_, IsRunning()).WillRepeatedly(Return(true));
  EXPECT_CALL(*mock_hps_, Enable(0)).WillOnce(Return(true));
  EXPECT_CALL(*mock_hps_, Disable(0)).WillOnce(Return(true));
  EXPECT_CALL(*mock_hps_, ShutDown()).WillOnce(Return(true));
  brillo::ErrorPtr error;
  bool result = hps_daemon_->EnableHpsSense(&error, feature_config_);
  EXPECT_TRUE(result);
  result = hps_daemon_->DisableHpsSense(&error);
  EXPECT_TRUE(result);
}

// When the last feature is disabled, the device is shutdown. If a feature gets
// enabled again, we boot the device.
TEST_F(HpsDaemonTest, DisableThenEnableFeature) {
  brillo::ErrorPtr error;
  {
    InSequence sequence;
    EXPECT_CALL(*mock_hps_, Boot());
    EXPECT_CALL(*mock_hps_, Enable(0)).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, IsRunning()).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, Disable(0)).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, ShutDown()).WillOnce(Return(true));
    bool result = hps_daemon_->EnableHpsSense(&error, feature_config_);
    EXPECT_TRUE(result);
    result = hps_daemon_->DisableHpsSense(&error);
    EXPECT_TRUE(result);
  }
  {
    InSequence sequence;
    EXPECT_CALL(*mock_hps_, Boot());
    EXPECT_CALL(*mock_hps_, Enable(0)).WillOnce(Return(true));
    bool result = hps_daemon_->EnableHpsSense(&error, feature_config_);
    EXPECT_TRUE(result);
  }
}

TEST_F(HpsDaemonTest, GetFeatureResultNotEnabled) {
  brillo::ErrorPtr error;
  HpsResultProto result;

  bool call_result = hps_daemon_->GetResultHpsSense(&error, &result);
  EXPECT_FALSE(call_result);
  EXPECT_EQ("hpsd: Feature not enabled.", error->GetMessage());
}

TEST_F(HpsDaemonTest, TestPollTimer) {
  FeatureResult feature_result{.valid = true};
  {
    InSequence sequence;
    EXPECT_CALL(*mock_hps_, Boot());
    EXPECT_CALL(*mock_hps_, Enable(0)).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, IsRunning()).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, Result(0)).WillOnce(Return(feature_result));
    EXPECT_CALL(*mock_hps_, IsRunning()).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, Result(0)).WillOnce(Return(feature_result));
    EXPECT_CALL(*mock_hps_, IsRunning()).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, Disable(0)).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, ShutDown()).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, Result(0)).Times(0);
  }

  brillo::ErrorPtr error;
  bool result = hps_daemon_->EnableHpsSense(&error, feature_config_);
  EXPECT_TRUE(result);

  // Advance timer far enough so that the poll timer should fire twice.
  task_environment_.FastForwardBy(kPollTime * 2);

  // Disable the feature, time should no longer fire.
  result = hps_daemon_->DisableHpsSense(&error);
  EXPECT_TRUE(result);

  // Poll task should no longer fire if we advance the timer.
  task_environment_.FastForwardBy(kPollTime * 2);
  EXPECT_EQ(task_environment_.GetPendingMainThreadTaskCount(), 0u);
}

TEST_F(HpsDaemonTest, TestPollTimerMultipleFeatures) {
  FeatureResult feature_result{.valid = true};
  {
    InSequence sequence;
    EXPECT_CALL(*mock_hps_, Boot());
    EXPECT_CALL(*mock_hps_, Enable(0)).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, IsRunning()).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, Enable(1)).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, IsRunning()).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, Result(0)).WillOnce(Return(feature_result));
    EXPECT_CALL(*mock_hps_, Result(1)).WillOnce(Return(feature_result));
    EXPECT_CALL(*mock_hps_, IsRunning()).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, Disable(0)).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, IsRunning()).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, Result(0)).Times(0);
    EXPECT_CALL(*mock_hps_, Result(1)).WillOnce(Return(feature_result));
    EXPECT_CALL(*mock_hps_, IsRunning()).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, Disable(1)).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, ShutDown()).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, Result(1)).Times(0);
  }

  brillo::ErrorPtr error;

  // Enable features 0 & 1
  bool result = hps_daemon_->EnableHpsSense(&error, feature_config_);
  EXPECT_TRUE(result);
  result = hps_daemon_->EnableHpsNotify(&error, feature_config_);
  EXPECT_TRUE(result);

  // Advance timer far enough so that the poll timer should fire.
  task_environment_.FastForwardBy(kPollTime);

  // Disable the feature, timer should no longer fire for feature 0.
  result = hps_daemon_->DisableHpsSense(&error);
  EXPECT_TRUE(result);

  // Advance timer far enough so that the poll timer should fire.
  task_environment_.FastForwardBy(kPollTime);

  // Disable the feature, timer should no longer fire for feature 1.
  result = hps_daemon_->DisableHpsNotify(&error);
  EXPECT_TRUE(result);

  // Advance time to ensure no more features are firing.
  task_environment_.FastForwardBy(kPollTime);
  EXPECT_EQ(task_environment_.GetPendingMainThreadTaskCount(), 0u);
}

// TODO(slangley): Work out how to check that the signal was fired, on first
// inspection it doesn't come via the mocks we have.
TEST_F(HpsDaemonTest, DISABLED_TestSignals) {
  // This result indicates a positive inference from HPS.
  FeatureResult valid_feature_result{.inference_result = 100, .valid = true};
  FeatureResult invalid_feature_result{.inference_result = 100, .valid = false};
  {
    InSequence sequence;
    EXPECT_CALL(*mock_hps_, Enable(0)).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, Enable(1)).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, Result(0)).WillOnce(Return(valid_feature_result));
    EXPECT_CALL(*mock_hps_, Result(1)).WillOnce(Return(valid_feature_result));
    EXPECT_CALL(*mock_hps_, Result(0)).WillOnce(Return(invalid_feature_result));
    EXPECT_CALL(*mock_hps_, Result(1)).WillOnce(Return(invalid_feature_result));
    EXPECT_CALL(*mock_hps_, Disable(0)).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, Disable(1)).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, ShutDown()).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, Result(0)).Times(0);
    EXPECT_CALL(*mock_hps_, Result(1)).Times(0);
  }

  brillo::ErrorPtr error;

  // Enable features 0 & 1
  bool result = hps_daemon_->EnableHpsSense(&error, feature_config_);
  EXPECT_TRUE(result);
  result = hps_daemon_->EnableHpsNotify(&error, feature_config_);
  EXPECT_TRUE(result);

  // Advance timer far enough so that the poll timer should fire.
  task_environment_.FastForwardBy(kPollTime);

  // Advance timer far enough so that the poll timer should fire again.
  task_environment_.FastForwardBy(kPollTime);

  // Disable the feature, timer should no longer fire for feature 0.
  result = hps_daemon_->DisableHpsSense(&error);
  EXPECT_TRUE(result);

  // Disable the feature, timer should no longer fire for feature 1.
  result = hps_daemon_->DisableHpsNotify(&error);
  EXPECT_TRUE(result);

  // Advance time to ensure no more features are firing.
  task_environment_.FastForwardBy(kPollTime);
}

TEST_F(HpsDaemonTest, TestSuspendAndResume) {
  FeatureResult feature_result{.valid = true};
  {
    InSequence sequence;
    EXPECT_CALL(*mock_hps_, Boot());
    EXPECT_CALL(*mock_hps_, Enable(0)).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, IsRunning()).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, Result(0)).WillOnce(Return(feature_result));
    EXPECT_CALL(*mock_hps_, IsRunning()).WillOnce(Return(false));
    EXPECT_CALL(*mock_hps_, ShutDown()).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, Boot());
    EXPECT_CALL(*mock_hps_, Enable(0)).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, Result(0)).WillOnce(Return(feature_result));
    EXPECT_CALL(*mock_hps_, IsRunning()).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, Disable(0)).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, ShutDown()).WillOnce(Return(true));
  }

  brillo::ErrorPtr error;
  bool result = hps_daemon_->EnableHpsSense(&error, feature_config_);
  EXPECT_TRUE(result);

  // Advance timer far enough so that the poll timer should fire twice. On the
  // second invocation, HPS pretends that it has rebooted (IsRunning() ==
  // false), so we reinitialize the enabled features before resuming polling.
  task_environment_.FastForwardBy(kPollTime * 2);

  // Disable the feature, time should no longer fire.
  result = hps_daemon_->DisableHpsSense(&error);
  EXPECT_TRUE(result);

  // Poll task should no longer fire if we advance the timer.
  task_environment_.FastForwardBy(kPollTime * 2);
  EXPECT_EQ(task_environment_.GetPendingMainThreadTaskCount(), 0u);
}

TEST_F(HpsDaemonTest, DisableFeatureAfterResume) {
  {
    InSequence sequence;
    EXPECT_CALL(*mock_hps_, Boot());
    EXPECT_CALL(*mock_hps_, Enable(0)).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, IsRunning()).WillOnce(Return(false));
    EXPECT_CALL(*mock_hps_, ShutDown()).WillOnce(Return(true));
  }

  brillo::ErrorPtr error;
  bool result = hps_daemon_->EnableHpsSense(&error, feature_config_);
  EXPECT_TRUE(result);

  result = hps_daemon_->DisableHpsSense(&error);
  EXPECT_TRUE(result);

  // Poll task should no longer fire if we advance the timer.
  task_environment_.FastForwardBy(kPollTime * 2);
  EXPECT_EQ(task_environment_.GetPendingMainThreadTaskCount(), 0u);
}

TEST_F(HpsDaemonTest, AverageFilter) {
  feature_config_.set_allocated_average_filter_config(
      new FeatureConfig_AverageFilterConfig());
  feature_config_.mutable_average_filter_config()->set_average_window_size(2);

  FeatureResult feature_result1{.inference_result = 100, .valid = true};
  FeatureResult feature_result2{.inference_result = -100, .valid = true};
  {
    InSequence sequence;
    EXPECT_CALL(*mock_hps_, Boot());
    EXPECT_CALL(*mock_hps_, Enable(0)).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, IsRunning()).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, Result(0)).WillOnce(Return(feature_result1));
    EXPECT_CALL(*mock_hps_, IsRunning()).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, Result(0)).WillOnce(Return(feature_result2));
  }

  brillo::ErrorPtr error;
  bool result = hps_daemon_->EnableHpsSense(&error, feature_config_);
  EXPECT_TRUE(result);

  // Advance timer far enough so that the poll timer should fire twice.
  task_environment_.FastForwardBy(kPollTime * 2);

  HpsResultProto value;
  result = hps_daemon_->GetResultHpsSense(&error, &value);
  EXPECT_TRUE(result);
  EXPECT_EQ(value.value(), HpsResult::POSITIVE);
  EXPECT_EQ(value.inference_result(), 0);
  EXPECT_FALSE(value.inference_result_valid());
}

TEST_F(HpsDaemonTest, ReportRawResults) {
  feature_config_.set_allocated_average_filter_config(
      new FeatureConfig_AverageFilterConfig());
  feature_config_.mutable_average_filter_config()->set_average_window_size(2);
  feature_config_.set_report_raw_results(true);

  FeatureResult feature_result{.inference_result = 100, .valid = true};
  {
    InSequence sequence;
    EXPECT_CALL(*mock_hps_, Boot());
    EXPECT_CALL(*mock_hps_, Enable(0)).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, IsRunning()).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, Result(0)).WillOnce(Return(feature_result));
  }

  brillo::ErrorPtr error;
  bool result = hps_daemon_->EnableHpsSense(&error, feature_config_);
  EXPECT_TRUE(result);
  task_environment_.FastForwardBy(kPollTime);

  HpsResultProto value;
  result = hps_daemon_->GetResultHpsSense(&error, &value);
  EXPECT_TRUE(result);
  EXPECT_EQ(value.inference_result(), feature_result.inference_result);
  EXPECT_TRUE(value.inference_result_valid());
}

TEST_F(HpsDaemonTest, ResetFilterOnResume) {
  feature_config_.set_allocated_average_filter_config(
      new FeatureConfig_AverageFilterConfig());
  feature_config_.mutable_average_filter_config()->set_average_window_size(2);

  FeatureResult feature_result1{.inference_result = 100, .valid = true};
  FeatureResult feature_result2{.inference_result = -100, .valid = true};
  {
    InSequence sequence;
    EXPECT_CALL(*mock_hps_, Boot());
    EXPECT_CALL(*mock_hps_, Enable(0)).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, IsRunning()).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, Result(0)).WillOnce(Return(feature_result1));
    EXPECT_CALL(*mock_hps_, IsRunning()).WillOnce(Return(false));
    EXPECT_CALL(*mock_hps_, ShutDown()).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, Boot());
    EXPECT_CALL(*mock_hps_, Enable(0)).WillOnce(Return(true));
    EXPECT_CALL(*mock_hps_, Result(0)).WillOnce(Return(feature_result2));
  }

  brillo::ErrorPtr error;
  bool result = hps_daemon_->EnableHpsSense(&error, feature_config_);
  EXPECT_TRUE(result);

  // Advance timer far enough so that the poll timer should fire twice. Since
  // HPS resets before the second measurement, the filter also gets reset and
  // the overall result is negative.
  task_environment_.FastForwardBy(kPollTime * 2);

  HpsResultProto value;
  result = hps_daemon_->GetResultHpsSense(&error, &value);
  EXPECT_TRUE(result);
  EXPECT_EQ(value.value(), HpsResult::NEGATIVE);
}

}  // namespace hps
