// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P2P_SERVER_FAKE_HTTP_SERVER_H_
#define P2P_SERVER_FAKE_HTTP_SERVER_H_

#include <string>

#include <base/files/file_path.h>
#include <base/functional/callback.h>

#include "p2p/server/http_server.h"

namespace p2p {

namespace server {

// A HTTP server that doesn't really serve any files and can be made
// to lie about its number of connected clients.
class FakeHttpServer : public HttpServer {
 public:
  FakeHttpServer() : is_running_(false), num_connections_(0) {}
  FakeHttpServer(const FakeHttpServer&) = delete;
  FakeHttpServer& operator=(const FakeHttpServer&) = delete;

  bool Start() override {
    is_running_ = true;
    return true;
  }

  bool Stop() override {
    is_running_ = false;
    return true;
  }

  bool IsRunning() override { return is_running_; }

  uint16_t Port() override { return 1234; }

  void SetNumConnectionsCallback(NumConnectionsCallback callback) override {
    callback_ = callback;
  }

  void SetNumConnections(int num_connections) {
    if (num_connections_ != num_connections) {
      num_connections_ = num_connections;
      if (!callback_.is_null())
        callback_.Run(num_connections);
    }
  }

 private:
  bool is_running_;
  NumConnectionsCallback callback_;
  int num_connections_;
};

}  // namespace server

}  // namespace p2p

#endif  // P2P_SERVER_FAKE_HTTP_SERVER_H_
