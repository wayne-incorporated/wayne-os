// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CUPS_PROXY_MHD_HTTP_REQUEST_H_
#define CUPS_PROXY_MHD_HTTP_REQUEST_H_

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include <base/strings/string_piece.h>

namespace cups_proxy {

class MHDHttpRequest {
 public:
  MHDHttpRequest();

  void SetStatusLine(base::StringPiece method,
                     base::StringPiece url,
                     base::StringPiece version);
  void AddHeader(base::StringPiece key, base::StringPiece value);
  void PushToBody(base::StringPiece data);
  void Finalize();

  const std::string& method() const { return method_; }
  const std::string& url() const { return url_; }
  const std::string& version() const { return version_; }
  const std::map<std::string, std::string>& headers() const { return headers_; }
  const std::vector<uint8_t>& body() const { return body_; }

 private:
  std::string method_;
  std::string url_;
  std::string version_;
  std::map<std::string, std::string> headers_;
  std::vector<uint8_t> body_;

  bool chunked_;
};

}  // namespace cups_proxy

#endif  // CUPS_PROXY_MHD_HTTP_REQUEST_H_
