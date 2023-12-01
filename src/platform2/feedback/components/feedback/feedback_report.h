// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FEEDBACK_COMPONENTS_FEEDBACK_FEEDBACK_REPORT_H_
#define FEEDBACK_COMPONENTS_FEEDBACK_FEEDBACK_REPORT_H_

#include <string>

#include "base/files/file_path.h"
#include "base/functional/callback_forward.h"
#include "base/memory/ref_counted.h"
#include "base/time/time.h"

namespace base {
class SequencedTaskRunner;
}

namespace feedback {

typedef base::RepeatingCallback<void(const std::string&)> QueueCallback;

// This class holds a feedback report. Once a report is created, a disk backup
// for it is created automatically. This backup needs to explicitly be
// deleted by calling DeleteReportOnDisk.
class FeedbackReport : public base::RefCounted<FeedbackReport> {
 public:
  FeedbackReport(const base::FilePath& path,
                 const base::Time& upload_at,
                 const std::string& data,
                 scoped_refptr<base::SequencedTaskRunner> task_runner);
  FeedbackReport(const FeedbackReport&) = delete;
  FeedbackReport& operator=(const FeedbackReport&) = delete;

  // Stops the disk write of the report and deletes the report file if already
  // written.
  void DeleteReportOnDisk();

  const base::Time& upload_at() const { return upload_at_; }
  const std::string& data() const { return data_; }

  // Loads the reports still on disk and queues then using the given callback.
  // This call blocks on the file reads.
  static void LoadReportsAndQueue(const base::FilePath& user_dir,
                                  QueueCallback callback);

 private:
  friend class base::RefCounted<FeedbackReport>;
  virtual ~FeedbackReport();

  // Name of the file corresponding to this report.
  base::FilePath file_;

  base::FilePath reports_path_;
  base::Time upload_at_;  // Upload this report at or after this time.
  std::string data_;

  scoped_refptr<base::SequencedTaskRunner> reports_task_runner_;
};

}  // namespace feedback

#endif  // FEEDBACK_COMPONENTS_FEEDBACK_FEEDBACK_REPORT_H_
