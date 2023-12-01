// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P2P_SERVER_MOCK_HTTP_SERVER_H_
#define P2P_SERVER_MOCK_HTTP_SERVER_H_

#include "p2p/server/fake_http_server.h"

#include <string>

#include <gmock/gmock.h>

#include <base/files/file_path.h>
#include <base/functional/callback.h>

namespace p2p {

namespace server {

class MockHttpServer : public HttpServer {
 public:
  MockHttpServer() {
    // Delegate all calls to the fake instance
    ON_CALL(*this, Start())
        .WillByDefault(testing::Invoke(&fake_, &FakeHttpServer::Start));
    ON_CALL(*this, Stop())
        .WillByDefault(testing::Invoke(&fake_, &FakeHttpServer::Stop));
    ON_CALL(*this, IsRunning())
        .WillByDefault(testing::Invoke(&fake_, &FakeHttpServer::IsRunning));
    ON_CALL(*this, Port())
        .WillByDefault(testing::Invoke(&fake_, &FakeHttpServer::Port));
    ON_CALL(*this, SetNumConnectionsCallback(testing::_))
        .WillByDefault(testing::Invoke(
            &fake_, &FakeHttpServer::SetNumConnectionsCallback));
  }
  MockHttpServer(const MockHttpServer&) = delete;
  MockHttpServer& operator=(const MockHttpServer&) = delete;

  MOCK_METHOD(bool, Start, (), (override));
  MOCK_METHOD(bool, Stop, (), (override));
  MOCK_METHOD(bool, IsRunning, (), (override));
  MOCK_METHOD(uint16_t, Port, (), (override));
  MOCK_METHOD(void,
              SetNumConnectionsCallback,
              (NumConnectionsCallback),
              (override));

  FakeHttpServer& fake() { return fake_; }

 private:
  FakeHttpServer fake_;
};

}  // namespace server

}  // namespace p2p

#endif  // P2P_SERVER_MOCK_HTTP_SERVER_H_
