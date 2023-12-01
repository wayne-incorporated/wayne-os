// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "system-proxy/test_http_server.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <chromeos/patchpanel/net_util.h>
#include <chromeos/patchpanel/socket.h>

namespace {
constexpr int kMaxConn = 10;

const std::string_view kConnectionEstablished =
    "HTTP/1.1 200 Connection established\r\n\r\n";

const std::string_view kProxyAuthenticationRequiredBasic =
    "HTTP/1.1 407 Proxy Authentication Required\r\n"
    "Proxy-Authenticate: Basic realm=\"My Proxy\"\r\n"
    "\r\n";

const std::string_view kProxyAuthenticationRequiredNegotiate =
    "HTTP/1.1 407 Proxy Authentication Required\r\n"
    "Proxy-Authenticate: Negotiate realm=\"My Proxy\"\r\n"
    "\r\n";

const std::string_view kHttpBadGateway =
    "HTTP/1.1 502 Bad Gateway\r\n\r\nBad gateway message from the server";

}  // namespace
namespace system_proxy {

HttpTestServer::HttpTestServer()
    : base::SimpleThread("HttpTestServer"),
      listening_addr_(htonl(INADDR_LOOPBACK)),
      listening_port_(0) {}

HttpTestServer::~HttpTestServer() {
  if (!HasBeenStarted()) {
    return;
  }
  int fd = listening_socket_->release();
  if (close(fd) != 0) {
    LOG(ERROR) << "Failed to close the listening socket";
  }
  Join();
}

void HttpTestServer::Run() {
  struct sockaddr_storage client_src = {};
  socklen_t sockaddr_len = sizeof(client_src);
  while (!expected_responses_.empty()) {
    if (auto client_conn = listening_socket_->Accept(
            (struct sockaddr*)&client_src, &sockaddr_len)) {
      std::string_view server_reply =
          GetConnectReplyString(expected_responses_.front());
      expected_responses_.pop();
      client_conn->SendTo(server_reply.data(), server_reply.size());
    }
  }
}

void HttpTestServer::BeforeStart() {
  listening_socket_ =
      std::make_unique<patchpanel::Socket>(AF_INET, SOCK_STREAM);

  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(listening_port_);
  addr.sin_addr.s_addr = listening_addr_;
  if (!listening_socket_->Bind((const struct sockaddr*)&addr, sizeof(addr))) {
    LOG(ERROR) << "Cannot bind source socket" << std::endl;
    return;
  }

  if (!listening_socket_->Listen(kMaxConn)) {
    LOG(ERROR) << "Cannot listen on source socket." << std::endl;
    return;
  }

  socklen_t len = sizeof(addr);
  if (getsockname(listening_socket_->fd(), (struct sockaddr*)&addr, &len)) {
    LOG(ERROR) << "Cannot get the listening port " << std::endl;
    return;
  }
  listening_port_ = ntohs(addr.sin_port);
}

std::string HttpTestServer::GetUrl() {
  return base::StringPrintf(
      "http://%s:%d", patchpanel::IPv4AddressToString(listening_addr_).c_str(),
      listening_port_);
}

void HttpTestServer::AddHttpConnectReply(HttpConnectReply reply) {
  expected_responses_.push(reply);
}

std::string_view HttpTestServer::GetConnectReplyString(HttpConnectReply reply) {
  switch (reply) {
    case HttpConnectReply::kOk:
      return kConnectionEstablished;
    case HttpConnectReply::kAuthRequiredBasic:
      return kProxyAuthenticationRequiredBasic;
    case HttpConnectReply::kAuthRequiredKerberos:
      return kProxyAuthenticationRequiredNegotiate;
    case HttpConnectReply::kBadGateway:
      return kHttpBadGateway;
    default:
      return kConnectionEstablished;
  }
}

}  // namespace  system_proxy
