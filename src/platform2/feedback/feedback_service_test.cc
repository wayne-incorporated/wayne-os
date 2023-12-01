// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "feedback/feedback_service.h"

#include <utime.h>

#include <memory>
#include <string>
#include <vector>

#include <base/at_exit.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_executor.h>
#include <base/threading/thread.h>
#include <chromeos/dbus/service_constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "components/feedback/feedback_common.h"
#include "components/feedback/feedback_report.h"
#include "components/feedback/feedback_uploader.h"
#include "components/feedback/proto/extension.pb.h"

namespace feedback {

namespace {

static constexpr char kThreadName[] = "FeedbackWorkerThread";
static constexpr char kFeedbackReportPath[] = "Feedback Reports";
static constexpr int kTestProductId = 84;

}  // namespace

class MockFeedbackUploader : public feedback::FeedbackUploader {
 public:
  MockFeedbackUploader(const base::FilePath& path,
                       scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : FeedbackUploader(path, task_runner) {}

  MOCK_METHOD(void, DispatchReport, (const std::string&), (override));
};

class MockFeedbackUploaderQueue : public MockFeedbackUploader {
 public:
  MockFeedbackUploaderQueue(
      const base::FilePath& path,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : MockFeedbackUploader(path, task_runner) {}

  MOCK_METHOD(void, QueueReport, (const std::string&), (override));
};

class FailedFeedbackUploader : public MockFeedbackUploader {
 public:
  FailedFeedbackUploader(
      const base::FilePath& path,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : MockFeedbackUploader(path, task_runner) {}

  void DispatchReport(const std::string& data) {
    MockFeedbackUploader::DispatchReport(data);
    RetryReport(data);
  }

  feedback::FeedbackReport* GetFirstReport() {
    scoped_refptr<feedback::FeedbackReport> report = reports_queue_.top();
    return report.get();
  }
};

class FeedbackServiceTest : public testing::Test {
 public:
  FeedbackServiceTest() : task_executor_(base::MessagePumpType::IO) {}

  static void CallbackFeedbackResult(bool expected_result,
                                     bool result,
                                     const std::string& err) {
    EXPECT_EQ(result, expected_result);
  }

  userfeedback::ExtensionSubmit GetBaseReport() {
    userfeedback::ExtensionSubmit report;
    report.mutable_common_data();
    report.mutable_web_data();
    report.set_type_id(0);
    report.set_product_id(kTestProductId);
    return report;
  }

  void WaitOnThread() { worker_thread_->FlushForTesting(); }

 protected:
  virtual void SetUp() {
    EXPECT_TRUE(temp_dir_.CreateUniqueTempDir());
    CreateDirectory(temp_dir_.GetPath().Append(kFeedbackReportPath));

    worker_thread_ = std::make_unique<base::Thread>(kThreadName);
    worker_thread_->Start();
    worker_task_runner_ = worker_thread_->task_runner();
  }

  virtual void TearDown() {
    WaitOnThread();
    worker_thread_->Stop();
  }

  base::ScopedTempDir temp_dir_;
  base::SingleThreadTaskExecutor task_executor_;
  std::unique_ptr<base::Thread> worker_thread_;
  scoped_refptr<base::SingleThreadTaskRunner> worker_task_runner_;
};

TEST_F(FeedbackServiceTest, SendFeedback) {
  MockFeedbackUploaderQueue uploader(temp_dir_.GetPath(), worker_task_runner_);
  std::string data;
  userfeedback::ExtensionSubmit report = GetBaseReport();
  report.SerializeToString(&data);
  EXPECT_CALL(uploader, QueueReport(data)).Times(1);

  scoped_refptr<FeedbackService> svc = new FeedbackService(&uploader);

  svc->SendFeedback(
      report,
      base::BindOnce(&FeedbackServiceTest::CallbackFeedbackResult, true));
}

TEST_F(FeedbackServiceTest, DispatchTest) {
  MockFeedbackUploader uploader(temp_dir_.GetPath(), worker_task_runner_);
  std::string data;
  userfeedback::ExtensionSubmit report = GetBaseReport();
  report.SerializeToString(&data);
  EXPECT_CALL(uploader, DispatchReport(data)).Times(1);

  scoped_refptr<FeedbackService> svc = new FeedbackService(&uploader);

  svc->SendFeedback(
      report,
      base::BindOnce(&FeedbackServiceTest::CallbackFeedbackResult, true));
}

TEST_F(FeedbackServiceTest, UploadFailure) {
  FailedFeedbackUploader uploader(temp_dir_.GetPath(), worker_task_runner_);
  std::string data;
  userfeedback::ExtensionSubmit report = GetBaseReport();
  report.SerializeToString(&data);
  EXPECT_CALL(uploader, DispatchReport(data)).Times(1);

  scoped_refptr<FeedbackService> svc = new FeedbackService(&uploader);

  svc->SendFeedback(
      report,
      base::BindOnce(&FeedbackServiceTest::CallbackFeedbackResult, true));
  WaitOnThread();

  // Verify that this got put back on the queue.
  EXPECT_TRUE(uploader.GetFirstReport() != nullptr);
  EXPECT_EQ(uploader.GetFirstReport()->data(), data);
}

}  // namespace feedback
