// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FEEDBACK_FEEDBACK_UPLOADER_HTTP_H_
#define FEEDBACK_FEEDBACK_UPLOADER_HTTP_H_

#include "components/feedback/feedback_uploader.h"

#include <string>

namespace feedback {

class FeedbackUploaderHttp : public feedback::FeedbackUploader {
 public:
  FeedbackUploaderHttp(const base::FilePath& path,
                       scoped_refptr<base::SingleThreadTaskRunner> task_runner,
                       const std::string& url);
  FeedbackUploaderHttp(const FeedbackUploaderHttp&) = delete;
  FeedbackUploaderHttp& operator=(const FeedbackUploaderHttp&) = delete;

  ~FeedbackUploaderHttp() override = default;

 private:
  friend class FeedbackServiceTest;

  void DispatchReport(const std::string& data) override;
};

}  // namespace feedback

#endif  // FEEDBACK_FEEDBACK_UPLOADER_HTTP_H_
