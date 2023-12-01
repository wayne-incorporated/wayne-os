// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "feedback/feedback_uploader_http.h"

#include <base/logging.h>
#include <brillo/http/http_utils.h>
#include <brillo/mime_utils.h>

namespace feedback {

FeedbackUploaderHttp::FeedbackUploaderHttp(
    const base::FilePath& path,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    const std::string& url)
    : FeedbackUploader(path, task_runner, url) {}

void FeedbackUploaderHttp::DispatchReport(const std::string& data) {
  brillo::ErrorPtr error;
  auto response = brillo::http::PostBinaryAndBlock(
      url_, data.data(), data.size(), brillo::mime::application::kProtobuf, {},
      brillo::http::Transport::CreateDefault(), &error);
  if (response) {
    LOG(INFO) << "Sending feedback: successful";
    UpdateUploadTimer();
  } else {
    LOG(WARNING) << "Sending feedback: failed with error "
                 << error->GetMessage() << ", retrying";
    RetryReport(data);
  }
}

}  // namespace feedback
