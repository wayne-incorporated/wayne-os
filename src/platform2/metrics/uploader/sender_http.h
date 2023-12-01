// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_UPLOADER_SENDER_HTTP_H_
#define METRICS_UPLOADER_SENDER_HTTP_H_

#include <string>

#include "metrics/uploader/sender.h"

// Sender implemented using http_utils from libchromeos
class HttpSender : public Sender {
 public:
  explicit HttpSender(std::string server_url);
  HttpSender(const HttpSender&) = delete;
  HttpSender& operator=(const HttpSender&) = delete;

  ~HttpSender() override = default;
  // Sends |content| whose SHA1 hash is |hash| to server_url with a synchronous
  // POST request to server_url.
  bool Send(const std::string& content, const std::string& hash) override;

 private:
  const std::string server_url_;
};

#endif  // METRICS_UPLOADER_SENDER_HTTP_H_
