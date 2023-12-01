// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_HTTP_MOCK_CONNECTION_H_
#define LIBBRILLO_BRILLO_HTTP_MOCK_CONNECTION_H_

#include <memory>
#include <string>

#include <brillo/http/http_connection.h>
#include <gmock/gmock.h>

namespace brillo {
namespace http {

class MockConnection : public Connection {
 public:
  using Connection::Connection;

  MockConnection(const MockConnection&) = delete;
  MockConnection& operator=(const MockConnection&) = delete;

  MOCK_METHOD(bool, SendHeaders, (const HeaderList&, ErrorPtr*), (override));
  MOCK_METHOD(bool, MockSetRequestData, (Stream*, ErrorPtr*));
  MOCK_METHOD(void, MockSetResponseData, (Stream*));
  MOCK_METHOD(bool, FinishRequest, (ErrorPtr*), (override));
  MOCK_METHOD(RequestID,
              FinishRequestAsync,
              (SuccessCallback, ErrorCallback),
              (override));
  MOCK_METHOD(int, GetResponseStatusCode, (), (const, override));
  MOCK_METHOD(std::string, GetResponseStatusText, (), (const, override));
  MOCK_METHOD(std::string, GetProtocolVersion, (), (const, override));
  MOCK_METHOD(std::string,
              GetResponseHeader,
              (const std::string&),
              (const, override));
  MOCK_METHOD(Stream*, MockExtractDataStream, (brillo::ErrorPtr*), (const));

 private:
  bool SetRequestData(StreamPtr stream, brillo::ErrorPtr* error) override {
    return MockSetRequestData(stream.get(), error);
  }
  void SetResponseData(StreamPtr stream) override {
    MockSetResponseData(stream.get());
  }
  StreamPtr ExtractDataStream(brillo::ErrorPtr* error) override {
    return StreamPtr{MockExtractDataStream(error)};
  }
};

}  // namespace http
}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_HTTP_MOCK_CONNECTION_H_
