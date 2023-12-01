// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/feedback/feedback_uploader.h"

#include <stdint.h>

#include "base/command_line.h"
#include "base/files/file_path.h"
#include "base/functional/callback.h"
#include "base/task/sequenced_task_runner.h"
#include "base/time/time.h"
#include "components/feedback/feedback_report.h"

namespace feedback {
namespace {

const char kFeedbackPostUrl[] =
    "https://www.google.com/tools/feedback/chrome/__submit";

constexpr base::TimeDelta kRetryDelay = base::Hours(1);

const base::FilePath::CharType kFeedbackReportPath[] =
    FILE_PATH_LITERAL("Feedback Reports");

}  // namespace

bool FeedbackUploader::ReportsUploadTimeComparator::operator()(
    const scoped_refptr<FeedbackReport>& a,
    const scoped_refptr<FeedbackReport>& b) const {
  return a->upload_at() > b->upload_at();
}

FeedbackUploader::FeedbackUploader(
    const base::FilePath& path,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : FeedbackUploader(path, task_runner, kFeedbackPostUrl) {}

FeedbackUploader::FeedbackUploader(
    const base::FilePath& path,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    const std::string& url)
    : report_path_(path.Append(kFeedbackReportPath)),
      retry_delay_(kRetryDelay),
      task_runner_(task_runner),
      url_(url) {
  Init();
}

FeedbackUploader::~FeedbackUploader() {}

void FeedbackUploader::Init() {
  dispatch_callback_ =
      base::BindRepeating(&FeedbackUploader::DispatchReport, AsWeakPtr());
}

void FeedbackUploader::QueueReport(const std::string& data) {
  QueueReportWithDelay(data, base::TimeDelta());
}

void FeedbackUploader::UpdateUploadTimer() {
  if (reports_queue_.empty())
    return;

  scoped_refptr<FeedbackReport> report = reports_queue_.top();
  base::Time now = base::Time::Now();
  if (report->upload_at() <= now) {
    reports_queue_.pop();
    dispatch_callback_.Run(report->data());
    report->DeleteReportOnDisk();
  } else {
    // Stop the old timer and start an updated one.
    if (upload_timer_.IsRunning())
      upload_timer_.Stop();
    upload_timer_.Start(FROM_HERE, report->upload_at() - now, this,
                        &FeedbackUploader::UpdateUploadTimer);
  }
}

void FeedbackUploader::RetryReport(const std::string& data) {
  QueueReportWithDelay(data, retry_delay_);
}

void FeedbackUploader::QueueReportWithDelay(const std::string& data,
                                            base::TimeDelta delay) {
  reports_queue_.push(new FeedbackReport(
      report_path_, base::Time::Now() + delay, data, task_runner_));
  UpdateUploadTimer();
}

void FeedbackUploader::setup_for_test(
    const ReportDataCallback& dispatch_callback,
    const base::TimeDelta& retry_delay) {
  dispatch_callback_ = dispatch_callback;
  retry_delay_ = retry_delay;
}

}  // namespace feedback
