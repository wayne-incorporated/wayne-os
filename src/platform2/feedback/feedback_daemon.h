// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FEEDBACK_FEEDBACK_DAEMON_H_
#define FEEDBACK_FEEDBACK_DAEMON_H_

#include <memory>

#include "base/files/file_descriptor_watcher_posix.h"
#include "base/task/single_thread_task_executor.h"
#include "base/threading/thread.h"
#include "feedback/feedback_service.h"

#include <string>

namespace feedback {

class FeedbackUploader;

class Daemon final {
 public:
  // |url| specifies which url the reports will be sent to. Note that product
  // IDs may be unique to that server, so the clients also need to be
  // configured properly for the chosen server.
  explicit Daemon(const std::string& url);
  Daemon(const Daemon&) = delete;
  Daemon& operator=(const Daemon&) = delete;

  ~Daemon();

  // Does all the work. Blocks until the daemon is finished.
  void Run();

 private:
  base::SingleThreadTaskExecutor loop_{base::MessagePumpType::IO};
  base::Thread worker_thread_;
  base::FileDescriptorWatcher watcher_;
  std::unique_ptr<feedback::FeedbackUploader> uploader_;
};

}  // namespace feedback

#endif  // FEEDBACK_FEEDBACK_DAEMON_H_
