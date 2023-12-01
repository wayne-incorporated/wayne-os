// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "metrics/uploader/sender_http.h"

#include <string>

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/http/http_utils.h>
#include <brillo/mime_utils.h>

HttpSender::HttpSender(const std::string server_url)
    : server_url_(server_url) {}

bool HttpSender::Send(const std::string& content,
                      const std::string& content_hash) {
  const std::string hash =
      base::HexEncode(content_hash.data(), content_hash.size());

  brillo::http::HeaderList headers = {{"X-Chrome-UMA-Log-SHA1", hash}};
  brillo::ErrorPtr error;
  auto response = brillo::http::PostTextAndBlock(
      server_url_, content, brillo::mime::application::kWwwFormUrlEncoded,
      headers, brillo::http::Transport::CreateDefault(), &error);
  if (!response || response->ExtractDataAsString() != "OK") {
    if (error) {
      LOG(ERROR) << "Failed to send data: " << error->GetMessage();
    }
    return false;
  }
  return true;
}
