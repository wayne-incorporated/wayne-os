// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "secagentd/message_sender.h"

#include <memory>
#include <optional>
#include <string>

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/functional/bind.h"
#include "base/functional/callback_forward.h"
#include "base/memory/scoped_refptr.h"
#include "base/run_loop.h"
#include "base/strings/stringprintf.h"
#include "base/test/bind.h"
#include "base/test/task_environment.h"
#include "gmock/gmock.h"  // IWYU pragma: keep
#include "gtest/gtest.h"
#include "missive/client/mock_report_queue.h"
#include "missive/client/mock_report_queue_provider.h"
#include "missive/client/report_queue.h"
#include "missive/client/report_queue_provider_test_helper.h"
#include "missive/proto/record_constants.pb.h"
#include "missive/util/status.h"
#include "missive/util/statusor.h"
#include "secagentd/proto/security_xdr_events.pb.h"
#include "secagentd/test/mock_message_sender.h"

namespace secagentd::testing {

namespace pb = cros_xdr::reporting;
using ::testing::_;
using ::testing::Eq;
using ::testing::Invoke;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::StrictMock;
using ::testing::WithArg;
using ::testing::WithArgs;

class MessageSenderTestFixture : public ::testing::Test {
 protected:
  MessageSenderTestFixture()
      : task_environment_(base::test::TaskEnvironment::TimeSource::MOCK_TIME) {}
  void SetUp() override {
    ASSERT_TRUE(fake_root_.CreateUniqueTempDir());
    const base::FilePath timezone_dir =
        fake_root_.GetPath().Append("var/lib/timezone");
    ASSERT_TRUE(base::CreateDirectory(timezone_dir));
    timezone_symlink_ = timezone_dir.Append("localtime");
    zoneinfo_dir_ = fake_root_.GetPath().Append("usr/share/zoneinfo");
    ASSERT_TRUE(base::CreateDirectory(zoneinfo_dir_));

    message_sender_ = MessageSender::CreateForTesting(fake_root_.GetPath());

    provider_ =
        std::make_unique<NiceMock<reporting::MockReportQueueProvider>>();
    reporting::report_queue_provider_test_helper::SetForTesting(
        provider_.get());
    provider_->ExpectCreateNewSpeculativeQueueAndReturnNewMockQueue(3);
    EXPECT_EQ(message_sender_->InitializeQueues(), absl::OkStatus());
    for (auto destination : kDestinations) {
      auto it = message_sender_->queue_map_.find(destination);
      EXPECT_NE(it, message_sender_->queue_map_.end());
      mock_queue_map_.insert(std::make_pair(
          destination, google::protobuf::down_cast<reporting::MockReportQueue*>(
                           it->second.get())));
    }
  }

  pb::CommonEventDataFields* GetCommon() { return &message_sender_->common_; }
  void CallInitializeDeviceBtime() { message_sender_->InitializeDeviceBtime(); }
  void CallUpdateDeviceTz() {
    message_sender_->UpdateDeviceTz(timezone_symlink_, false);
  }

  base::test::TaskEnvironment task_environment_;
  base::ScopedTempDir fake_root_;
  scoped_refptr<MessageSender> message_sender_;
  base::FilePath timezone_symlink_;
  base::FilePath zoneinfo_dir_;
  std::unique_ptr<NiceMock<reporting::MockReportQueueProvider>> provider_;
  std::unordered_map<reporting::Destination, reporting::MockReportQueue*>
      mock_queue_map_;
  static const reporting::Priority kPriority_ = reporting::SLOW_BATCH;
  constexpr static const reporting::Destination kDestinations[3] = {
      reporting::Destination::CROS_SECURITY_NETWORK,
      reporting::CROS_SECURITY_PROCESS, reporting::CROS_SECURITY_AGENT};
};

TEST_F(MessageSenderTestFixture, TestInitializeBtime) {
  const std::string kStatContents =
      "cpu  331574 58430 92503 1962802 6568 24763 7752 0 0 0\n"
      "cpu0 18478 11108 17247 350739 777 8197 4561 0 0 0\n"
      "cpu1 22345 8002 13230 364796 1006 3470 961 0 0 0\n"
      "cpu2 23079 8248 12590 365637 1163 2955 737 0 0 0\n"
      "cpu3 23019 8297 12074 366703 1085 2756 630 0 0 0\n"
      "cpu4 108517 11661 18315 272063 1037 3519 442 0 0 0\n"
      "cpu5 136133 11112 19045 242863 1498 3863 419 0 0 0\n"
      "intr 17153789 0 1877556 2940893 0 0 22514 424451 0 0 0 0 0 0 0 0 0 0 0 "
      "0 0 0 0 0 9546173 0 756967 263 1557 1 0 0 0 288285 62 0 158 0 0 12282 "
      "128 56 82 44 15 22533 0 192916 1 17569 519 6 0 0 0 0 0 0 0 221447 0 977 "
      "0 0 0 0 10765 0 0 0 214680 14 263403 0 0 0 0 0 1 1 0 0 0 284203 14 2 1 "
      "51429 0 2 0 0 0 0 1819\n"
      "ctxt 15507989\n"
      "btime 1667427768\n"
      "processes 20013\n"
      "procs_running 1\n"
      "procs_blocked 0\n"
      "softirq 5429921 130273 509093 53702 235430 109885 0 433061 1603480 2368 "
      "2352629";
  const base::FilePath proc_dir = fake_root_.GetPath().Append("proc");
  ASSERT_TRUE(base::CreateDirectory(proc_dir));
  ASSERT_TRUE(base::WriteFile(proc_dir.Append("stat"), kStatContents));
  CallInitializeDeviceBtime();
  EXPECT_EQ(1667427768, GetCommon()->device_boot_time());
}

TEST_F(MessageSenderTestFixture, TestTzUpdateWithPrefix) {
  const base::FilePath us_dir = zoneinfo_dir_.Append("US");
  ASSERT_TRUE(base::CreateDirectory(us_dir));
  const base::FilePath pacific = us_dir.Append("Pacific");
  ASSERT_TRUE(base::WriteFile(pacific, ""));

  ASSERT_TRUE(base::CreateSymbolicLink(pacific, timezone_symlink_));
  CallUpdateDeviceTz();
  EXPECT_EQ("US/Pacific", GetCommon()->local_timezone());
}

TEST_F(MessageSenderTestFixture, TestTzUpdateWithoutPrefix) {
  // Zulu doesn't have a prefix. Probably will never happen but supported
  // nonetheless.
  const base::FilePath zulu = zoneinfo_dir_.Append("Zulu");
  ASSERT_TRUE(base::WriteFile(zulu, ""));

  ASSERT_TRUE(base::CreateSymbolicLink(zulu, timezone_symlink_));
  CallUpdateDeviceTz();
  EXPECT_EQ("Zulu", GetCommon()->local_timezone());
}

TEST_F(MessageSenderTestFixture, TestTzUpdateNotInZoneInfo) {
  const base::FilePath bad = fake_root_.GetPath().Append("IAmError");
  ASSERT_TRUE(base::WriteFile(bad, ""));

  ASSERT_TRUE(base::CreateSymbolicLink(bad, timezone_symlink_));
  CallUpdateDeviceTz();
  // Timezone isn't updated.
  EXPECT_EQ("", GetCommon()->local_timezone());
}

TEST_F(MessageSenderTestFixture, TestSendMessageValidDestination) {
  auto common = GetCommon();
  common->set_device_boot_time(100);
  common->set_local_timezone("US/Pacific");
  std::string proto_string;

  // Process Event.
  EXPECT_CALL(*(mock_queue_map_.find(reporting::CROS_SECURITY_PROCESS)->second),
              AddProducedRecord(_, kPriority_, _))
      .WillOnce(WithArgs<0, 2>(Invoke(
          [&proto_string](
              base::OnceCallback<reporting::StatusOr<std::string>()> record_cb,
              base::OnceCallback<void(reporting::Status)> status_cb) {
            auto serialized = std::move(record_cb).Run();
            proto_string = serialized.ValueOrDie();

            std::move(status_cb).Run(reporting::Status::StatusOK());
          })));
  auto process_message =
      std::make_unique<cros_xdr::reporting::XdrProcessEvent>();
  auto mutable_common = process_message->mutable_common();
  reporting::Destination destination =
      reporting::Destination::CROS_SECURITY_PROCESS;

  message_sender_->SendMessage(destination, mutable_common,
                               std::move(process_message), std::nullopt);
  auto process_deserialized =
      std::make_unique<cros_xdr::reporting::XdrProcessEvent>();
  process_deserialized->ParseFromString(proto_string);
  EXPECT_EQ(common->device_boot_time(),
            process_deserialized->common().device_boot_time());
  EXPECT_EQ(common->local_timezone(),
            process_deserialized->common().local_timezone());

  // Agent Event.
  EXPECT_CALL(*(mock_queue_map_.find(reporting::CROS_SECURITY_AGENT)->second),
              AddProducedRecord(_, kPriority_, _))
      .WillOnce(WithArgs<0, 2>(Invoke(
          [&proto_string](
              base::OnceCallback<reporting::StatusOr<std::string>()> record_cb,
              base::OnceCallback<void(reporting::Status)> status_cb) {
            auto serialized = std::move(record_cb).Run();
            proto_string = serialized.ValueOrDie();

            std::move(status_cb).Run(reporting::Status::StatusOK());
          })));
  auto agent_message = std::make_unique<cros_xdr::reporting::XdrAgentEvent>();
  mutable_common = agent_message->mutable_common();
  destination = reporting::Destination::CROS_SECURITY_AGENT;
  message_sender_->SendMessage(destination, mutable_common,
                               std::move(agent_message), std::nullopt);
  auto agent_deserialized =
      std::make_unique<cros_xdr::reporting::XdrAgentEvent>();
  agent_deserialized->ParseFromString(proto_string);
  EXPECT_EQ(common->device_boot_time(),
            agent_deserialized->common().device_boot_time());
  EXPECT_EQ(common->local_timezone(),
            agent_deserialized->common().local_timezone());
}

TEST_F(MessageSenderTestFixture, TestSendMessageInvalidDestination) {
  auto message = std::make_unique<cros_xdr::reporting::XdrProcessEvent>();
  auto mutable_common = message->mutable_common();
  const reporting::Destination destination = reporting::Destination(-1);

  EXPECT_DEATH(
      {
        message_sender_->SendMessage(destination, mutable_common,
                                     std::move(message), std::nullopt);
      },
      ".*FATAL secagentd_testrunner:.*Check failed: it != queue_map_\\.end.*");
}

TEST_F(MessageSenderTestFixture, TestSendMessageWithCallback) {
  auto message = std::make_unique<cros_xdr::reporting::XdrProcessEvent>();
  auto mutable_common = message->mutable_common();
  const reporting::Destination destination =
      reporting::Destination::CROS_SECURITY_PROCESS;

  EXPECT_CALL(*(mock_queue_map_.find(reporting::CROS_SECURITY_PROCESS)->second),
              AddProducedRecord(_, kPriority_, _))
      .WillOnce(WithArg<2>(
          Invoke([](base::OnceCallback<void(reporting::Status)> status_cb) {
            std::move(status_cb).Run(reporting::Status::StatusOK());
          })));

  base::RunLoop run_loop;
  message_sender_->SendMessage(
      destination, mutable_common, std::move(message),
      base::BindOnce(
          [](base::RunLoop* run_loop, reporting::Status status) {
            EXPECT_OK(status);
            run_loop->Quit();
          },
          &run_loop));
  run_loop.Run();
}

}  // namespace secagentd::testing
