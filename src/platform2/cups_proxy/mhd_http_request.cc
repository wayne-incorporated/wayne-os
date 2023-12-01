// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cups_proxy/mhd_http_request.h"

#include <algorithm>
#include <utility>
#include <vector>

#include <base/strings/string_piece.h>

namespace cups_proxy {

MHDHttpRequest::MHDHttpRequest() : chunked_(false) {}

void MHDHttpRequest::SetStatusLine(base::StringPiece method,
                                   base::StringPiece url,
                                   base::StringPiece version) {
  method_ = std::string(method);
  url_ = std::string(url);
  version_ = std::string(version);
}

void MHDHttpRequest::AddHeader(base::StringPiece key, base::StringPiece value) {
  // strip 100-continue message from ipp request
  if (key == "Expect" && value == "100-continue") {
    return;
  }

  // strip chunked header from ipp request
  if (key == "Transfer-Encoding" && value == "chunked") {
    chunked_ = true;
    return;
  }

  headers_[std::string(key)] = std::string(value);
}

void MHDHttpRequest::Finalize() {
  if (chunked_) {
    AddHeader("Content-Length", std::to_string(body_.size()));
  }
}

void MHDHttpRequest::PushToBody(base::StringPiece data) {
  body_.insert(body_.end(), data.begin(), data.end());
}

}  // namespace cups_proxy
