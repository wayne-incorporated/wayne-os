// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SYSTEM_PROXY_TEST_HTTP_SERVER_H_
#define SYSTEM_PROXY_TEST_HTTP_SERVER_H_

#include <memory>
#include <queue>
#include <string>
#include <string_view>

#include <base/files/scoped_file.h>
#include <base/memory/weak_ptr.h>
#include <base/threading/simple_thread.h>

namespace patchpanel {
class Socket;
}  // namespace patchpanel

namespace system_proxy {

// HTTP server implementation for testing purpose that runs on a separate
// thread. This server allows users to setup expected HTTP server replies and
// listen in a blocking mode until all the requests are fulfilled. It does not
// perform client request syntax validation.
class HttpTestServer : public base::SimpleThread {
 public:
  enum class HttpConnectReply {
    kOk,
    kAuthRequiredBasic,
    kAuthRequiredKerberos,
    kBadGateway
  };

  HttpTestServer();
  HttpTestServer(const HttpTestServer&) = delete;
  HttpTestServer& operator=(const HttpTestServer&) = delete;
  ~HttpTestServer() override;

  // Starts the HTTP server which will perform a blocking listen() on the
  // address returned by |GetUrl| until all the requets set via
  // |AddHttpConnectReply| are fulfilled.
  void Run() override;
  // Sets the expected HTTP responses from the server. Must be called before
  // starting the thread.
  void AddHttpConnectReply(HttpConnectReply reply);
  // Returns the URL as scheme://host:port that points to the server.
  std::string GetUrl();

 private:
  // Creates the proxy listening socket which is bound to the localhost and a
  // dynamically allocated port. The proxy address can be retrieved using
  // |GetUrl|.
  void BeforeStart() override;

  void SendConnectReply();
  // Returns the HTTP message associate with |reply|.
  std::string_view GetConnectReplyString(HttpConnectReply reply);

  uint32_t listening_addr_;
  int listening_port_;
  std::queue<HttpConnectReply> expected_responses_;
  std::unique_ptr<patchpanel::Socket> listening_socket_;
  base::WeakPtrFactory<HttpTestServer> weak_ptr_factory_{this};
};
}  // namespace system_proxy

#endif  // SYSTEM_PROXY_TEST_HTTP_SERVER_H_
