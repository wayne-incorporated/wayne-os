// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/mock_mojo_client.h"

#include <utility>

#include "diagnostics/wilco_dtc_supportd/utils/mojo_test_utils.h"
#include "diagnostics/wilco_dtc_supportd/utils/mojo_utils.h"

namespace diagnostics {
namespace wilco {

void MockMojoClient::SendWilcoDtcMessageToUi(
    mojo::ScopedHandle json_message, SendWilcoDtcMessageToUiCallback callback) {
  std::string json_message_content =
      GetStringFromMojoHandle(std::move(json_message));
  // Redirect to a separate mockable method to workaround GMock's issues with
  // move-only parameters.
  SendWilcoDtcMessageToUiImpl(json_message_content, std::move(callback));
}

void MockMojoClient::PerformWebRequest(
    MojoWilcoDtcSupportdWebRequestHttpMethod http_method,
    mojo::ScopedHandle url,
    std::vector<mojo::ScopedHandle> headers,
    mojo::ScopedHandle request_body,
    MojoPerformWebRequestCallback callback) {
  // Extract string content from mojo::Handle's.
  std::string url_content = GetStringFromMojoHandle(std::move(url));
  std::vector<std::string> header_contents;
  for (auto& header : headers) {
    header_contents.push_back(GetStringFromMojoHandle(std::move(header)));
  }
  std::string request_body_content =
      GetStringFromMojoHandle(std::move(request_body));

  // Redirect to a separate mockable method to workaround GMock's issues with
  // move-only parameters.
  PerformWebRequestImpl(http_method, url_content, header_contents,
                        request_body_content, std::move(callback));
}

}  // namespace wilco
}  // namespace diagnostics
