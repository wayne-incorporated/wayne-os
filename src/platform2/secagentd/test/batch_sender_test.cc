// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "secagentd/batch_sender.h"

#include "base/functional/bind.h"
#include "base/functional/callback_forward.h"
#include "base/memory/scoped_refptr.h"
#include "base/strings/stringprintf.h"
#include "base/test/bind.h"
#include "base/test/task_environment.h"
#include "gmock/gmock.h"  // IWYU pragma: keep
#include "gtest/gtest.h"
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

class BatchSenderTestFixture : public ::testing::Test {
 protected:
  // KeyType type.
  using KT = std::string;
  // XdrMessage type.
  using XM = pb::XdrProcessEvent;
  // AtomicVariantMessage type.
  using AVM = pb::ProcessEventAtomicVariant;
  using BatchSenderType = BatchSender<KT, XM, AVM>;

  static constexpr auto kDestination =
      reporting::Destination::CROS_SECURITY_PROCESS;
  static constexpr uint32_t kBatchInterval = 10;

  static std::string GetProcessEventKey(
      const pb::ProcessEventAtomicVariant& process_event) {
    switch (process_event.variant_type_case()) {
      case AVM::kProcessExec:
        return process_event.process_exec().spawn_process().process_uuid();
      case AVM::kProcessTerminate:
        return process_event.process_terminate().process().process_uuid();
      case AVM::VARIANT_TYPE_NOT_SET:
        CHECK(false);
        return "";
    }
  }

  BatchSenderTestFixture()
      : task_environment_(base::test::TaskEnvironment::TimeSource::MOCK_TIME),
        message_sender_(base::MakeRefCounted<StrictMock<MockMessageSender>>()) {
  }

  void SetUp() override {
    batch_sender_ = std::make_unique<BatchSenderType>(
        base::BindRepeating(&GetProcessEventKey), message_sender_, kDestination,
        kBatchInterval);
    batch_sender_->Start();
    expected_process_exec_1_.mutable_process_exec()
        ->mutable_spawn_process()
        ->set_process_uuid("uuid1");
    expected_process_exec_2_.mutable_process_exec()
        ->mutable_spawn_process()
        ->set_process_uuid("uuid2");
    expected_process_term_1_.mutable_process_terminate()
        ->mutable_process()
        ->set_process_uuid("uuid1");
  }

  base::test::TaskEnvironment task_environment_;
  scoped_refptr<StrictMock<MockMessageSender>> message_sender_;
  std::unique_ptr<BatchSenderType> batch_sender_;
  AVM expected_process_exec_1_;
  AVM expected_process_exec_2_;
  AVM expected_process_term_1_;
};

TEST_F(BatchSenderTestFixture, TestSimpleBatchingPeriodicFlush) {
  std::unique_ptr<google::protobuf::MessageLite> actual_sent_message;
  pb::CommonEventDataFields* actual_mutable_common = nullptr;
  EXPECT_CALL(*message_sender_,
              SendMessage(Eq(BatchSenderTestFixture::kDestination), _, _, _))
      .WillRepeatedly(
          [&actual_sent_message, &actual_mutable_common](
              auto d, pb::CommonEventDataFields* c,
              std::unique_ptr<google::protobuf::MessageLite> m,
              std::optional<reporting::ReportQueue::EnqueueCallback> cb) {
            // SaveArgByMove unfortunately doesn't exist.
            actual_sent_message = std::move(m);
            actual_mutable_common = c;
            return absl::OkStatus();
          });

  auto process_event_1 = std::make_unique<BatchSenderTestFixture::AVM>();
  process_event_1->CopyFrom(expected_process_exec_1_);
  batch_sender_->Enqueue(std::move(process_event_1));

  auto process_event_2 = std::make_unique<BatchSenderTestFixture::AVM>();
  process_event_2->CopyFrom(expected_process_exec_2_);
  batch_sender_->Enqueue(std::move(process_event_2));

  task_environment_.AdvanceClock(base::Seconds(kBatchInterval));
  task_environment_.RunUntilIdle();

  BatchSenderTestFixture::XM* actual_process_event =
      google::protobuf::down_cast<pb::XdrProcessEvent*>(
          actual_sent_message.get());
  EXPECT_EQ(actual_process_event->mutable_common(), actual_mutable_common);
  ASSERT_EQ(2, actual_process_event->batched_events_size());
  EXPECT_TRUE(actual_process_event->batched_events(0)
                  .common()
                  .has_create_timestamp_us());
  EXPECT_EQ(
      expected_process_exec_1_.process_exec().spawn_process().process_uuid(),
      actual_process_event->batched_events(0)
          .process_exec()
          .spawn_process()
          .process_uuid());
  EXPECT_TRUE(actual_process_event->batched_events(1)
                  .common()
                  .has_create_timestamp_us());
  EXPECT_EQ(
      expected_process_exec_2_.process_exec().spawn_process().process_uuid(),
      actual_process_event->batched_events(1)
          .process_exec()
          .spawn_process()
          .process_uuid());

  auto process_event_3 = std::make_unique<BatchSenderTestFixture::AVM>();
  process_event_3->CopyFrom(expected_process_term_1_);
  batch_sender_->Enqueue(std::move(process_event_3));

  task_environment_.AdvanceClock(base::Seconds(kBatchInterval));
  task_environment_.RunUntilIdle();

  actual_process_event = google::protobuf::down_cast<pb::XdrProcessEvent*>(
      actual_sent_message.get());
  ASSERT_EQ(1, actual_process_event->batched_events_size());
  EXPECT_EQ(
      expected_process_term_1_.process_exec().spawn_process().process_uuid(),
      actual_process_event->batched_events(0)
          .process_exec()
          .spawn_process()
          .process_uuid());
}

TEST_F(BatchSenderTestFixture, TestBatchingSizeLimit) {
  std::vector<std::unique_ptr<google::protobuf::MessageLite>>
      actual_sent_messages;
  std::vector<pb::CommonEventDataFields*> actual_mutable_commons;
  EXPECT_CALL(*message_sender_,
              SendMessage(Eq(BatchSenderTestFixture::kDestination), _, _, _))
      .WillRepeatedly(
          [&actual_sent_messages, &actual_mutable_commons](
              auto d, pb::CommonEventDataFields* c,
              std::unique_ptr<google::protobuf::MessageLite> m,
              std::optional<reporting::ReportQueue::EnqueueCallback> cb) {
            // SaveArgByMove unfortunately doesn't exist.
            actual_sent_messages.emplace_back(std::move(m));
            actual_mutable_commons.push_back(c);
            return absl::OkStatus();
          });

  size_t est_batch_size = 0;
  int sent_events = 0;
  // Enqueue more than enough for the batches to be split.
  while (est_batch_size < BatchSenderType::kMaxMessageSizeBytes * 2) {
    auto process_event = std::make_unique<BatchSenderTestFixture::AVM>();
    process_event->CopyFrom(expected_process_exec_1_);
    process_event->mutable_process_exec()
        ->mutable_spawn_process()
        ->set_process_uuid(base::StringPrintf("%s_%d",
                                              process_event->process_exec()
                                                  .spawn_process()
                                                  .process_uuid()
                                                  .c_str(),
                                              sent_events++));
    est_batch_size += process_event->ByteSizeLong();
    batch_sender_->Enqueue(std::move(process_event));
  }

  task_environment_.AdvanceClock(base::Seconds(kBatchInterval));
  task_environment_.RunUntilIdle();

  // Our math here is not perfect so tolerate a minor deviation. What we
  // actually care about is that the batches were split at least once and that
  // there weren't hundreds of batches created due to some internal glitch.
  EXPECT_LE(2, actual_sent_messages.size());
  EXPECT_GE(5, actual_sent_messages.size());
  // Verify that all the sent messages disjointly account for all of the
  // enqueued events.
  std::set<std::string> sent_ids;
  for (const auto& message : actual_sent_messages) {
    EXPECT_GE(BatchSenderType::kMaxMessageSizeBytes, message->ByteSizeLong());
    auto actual_process_event =
        google::protobuf::down_cast<pb::XdrProcessEvent*>(message.get());
    for (int i = 0; i < actual_process_event->batched_events_size(); ++i) {
      auto id = GetProcessEventKey(actual_process_event->batched_events(i));
      CHECK_EQ(0, sent_ids.count(id)) << "Found dupe id " << id;
      sent_ids.insert(id);
    }
  }
  EXPECT_EQ(sent_events, sent_ids.size());
}

TEST_F(BatchSenderTestFixture, TestVisit) {
  auto process_event_1 = std::make_unique<BatchSenderTestFixture::AVM>();
  process_event_1->CopyFrom(expected_process_exec_1_);
  batch_sender_->Enqueue(std::move(process_event_1));

  auto process_event_2 = std::make_unique<BatchSenderTestFixture::AVM>();
  process_event_2->CopyFrom(expected_process_exec_2_);
  batch_sender_->Enqueue(std::move(process_event_2));

  auto process_event_3 = std::make_unique<BatchSenderTestFixture::AVM>();
  process_event_3->CopyFrom(expected_process_term_1_);
  batch_sender_->Enqueue(std::move(process_event_3));

  ASSERT_EQ(
      expected_process_exec_1_.process_exec().spawn_process().process_uuid(),
      expected_process_term_1_.process_terminate().process().process_uuid());
  const auto& key =
      expected_process_term_1_.process_terminate().process().process_uuid();
  bool cb1_run = false;
  auto cb1 = base::BindLambdaForTesting([key, &cb1_run](AVM* process_event) {
    EXPECT_TRUE(process_event->has_process_terminate());
    EXPECT_EQ(key, process_event->process_terminate().process().process_uuid());
    cb1_run = true;
  });
  // Ask specifically for a terminate event and verify that Visit ignores the
  // exec event with the same key.
  EXPECT_TRUE(
      batch_sender_->Visit(AVM::kProcessTerminate, key, std::move(cb1)));
  EXPECT_TRUE(cb1_run);

  bool cb2_run = false;
  auto cb2 = base::BindLambdaForTesting(
      [&cb2_run](AVM* process_event) { cb2_run = true; });
  EXPECT_FALSE(batch_sender_->Visit(AVM::kProcessTerminate,
                                    "Key does not exist", std::move(cb2)));
  EXPECT_FALSE(cb2_run);
}

}  // namespace secagentd::testing
