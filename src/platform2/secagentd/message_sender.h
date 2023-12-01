// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SECAGENTD_MESSAGE_SENDER_H_
#define SECAGENTD_MESSAGE_SENDER_H_

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "base/files/file_path.h"
#include "base/files/file_path_watcher.h"
#include "base/functional/bind.h"
#include "base/memory/weak_ptr.h"
#include "base/synchronization/lock.h"
#include "base/task/sequenced_task_runner.h"
#include "google/protobuf/message_lite.h"
#include "missive/client/report_queue.h"
#include "missive/proto/record_constants.pb.h"
#include "secagentd/proto/security_xdr_events.pb.h"

namespace secagentd {

class MessageSenderInterface
    : public base::RefCountedThreadSafe<MessageSenderInterface> {
 public:
  virtual absl::Status Initialize() = 0;
  virtual void SendMessage(
      reporting::Destination destination,
      cros_xdr::reporting::CommonEventDataFields* mutable_common,
      std::unique_ptr<google::protobuf::MessageLite> message,
      std::optional<reporting::ReportQueue::EnqueueCallback> cb) = 0;
  virtual ~MessageSenderInterface() = default;
};

namespace testing {
class MessageSenderTestFixture;
}

class MessageSender : public MessageSenderInterface {
 public:
  MessageSender();

  // Initializes:
  //   A queue for each destination and stores result into queue_map.
  //   Values for some common event proto fields.
  absl::Status Initialize() override;

  // Creates and enqueues a given proto message to the given destination.
  // Populates mutable_common with common fields if not nullptr. mutable_common
  // must be owned within message.
  // Allows for an optional callback that will be called with the message
  // status.
  void SendMessage(
      reporting::Destination destination,
      cros_xdr::reporting::CommonEventDataFields* mutable_common,
      std::unique_ptr<google::protobuf::MessageLite> message,
      std::optional<reporting::ReportQueue::EnqueueCallback> cb) override;

  // Allow calling the private test-only constructor without befriending
  // scoped_refptr.
  template <typename... Args>
  static scoped_refptr<MessageSender> CreateForTesting(Args&&... args) {
    return base::WrapRefCounted(new MessageSender(std::forward<Args>(args)...));
  }

 private:
  friend class testing::MessageSenderTestFixture;
  // Internal constructor used for testing.
  explicit MessageSender(const base::FilePath& root_path);

  void InitializeDeviceBtime();
  void InitializeAndWatchDeviceTz();
  absl::Status InitializeQueues();
  // Called by common_file_watcher_.
  void UpdateDeviceTz(const base::FilePath& timezone_symlink, bool error);

  // Map linking each destination to its corresponding Report_Queue.
  std::unordered_map<
      reporting::Destination,
      std::unique_ptr<reporting::ReportQueue, base::OnTaskRunnerDeleter>>
      queue_map_;
  // Current set of common fields. Kept up to date with a file watch.
  base::FilePathWatcher common_file_watcher_;
  base::Lock common_lock_;
  cros_xdr::reporting::CommonEventDataFields common_;
  const base::FilePath root_path_;
};
}  // namespace secagentd

#endif  // SECAGENTD_MESSAGE_SENDER_H_
