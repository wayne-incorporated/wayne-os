// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_HTTP_HTTP_CONNECTION_FAKE_H_
#define LIBBRILLO_BRILLO_HTTP_HTTP_CONNECTION_FAKE_H_

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <brillo/http/http_connection.h>
#include <brillo/http/http_transport_fake.h>

namespace brillo {
namespace http {
namespace fake {

// This is a fake implementation of http::Connection for unit testing.
class Connection : public http::Connection {
 public:
  Connection(const std::string& url,
             const std::string& method,
             const std::shared_ptr<http::Transport>& transport);
  Connection(const Connection&) = delete;
  Connection& operator=(const Connection&) = delete;

  ~Connection() override;

  // Overrides from http::Connection.
  // See http_connection.h for description of these methods.
  bool SendHeaders(const HeaderList& headers, brillo::ErrorPtr* error) override;
  bool SetRequestData(StreamPtr stream, brillo::ErrorPtr* error) override;
  void SetResponseData(StreamPtr /* stream */) override {}
  bool FinishRequest(brillo::ErrorPtr* error) override;
  RequestID FinishRequestAsync(SuccessCallback success_callback,
                               ErrorCallback error_callback) override;

  int GetResponseStatusCode() const override;
  std::string GetResponseStatusText() const override;
  std::string GetProtocolVersion() const override;
  std::string GetResponseHeader(const std::string& header_name) const override;
  StreamPtr ExtractDataStream(brillo::ErrorPtr* error) override;

 private:
  // A helper method for FinishRequestAsync() implementation.
  void FinishRequestAsyncHelper(SuccessCallback success_callback,
                                ErrorCallback error_callback);

  // Request and response objects passed to the user-provided request handler
  // callback. The request object contains all the request information.
  // The response object is the server response that is created by
  // the handler in response to the request.
  ServerRequest request_;
  ServerResponse response_;
};

}  // namespace fake
}  // namespace http
}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_HTTP_HTTP_CONNECTION_FAKE_H_
