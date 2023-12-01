// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P2P_HTTP_SERVER_CONNECTION_DELEGATE_INTERFACE_H_
#define P2P_HTTP_SERVER_CONNECTION_DELEGATE_INTERFACE_H_

#include <string>

#include <base/threading/simple_thread.h>

#include "p2p/common/server_message.h"

namespace p2p {

namespace http_server {

class ServerInterface;

// The ConnectionDelegateInterface exposes a single Run() method intended to
// be run from the thread that handles this connection manager.
class ConnectionDelegateInterface
    : public base::DelegateSimpleThread::Delegate {
 public:
  virtual ~ConnectionDelegateInterface() = default;

  // The ConnectionDelegateInterface::Run() method should serve any .p2p file in
  // the |dirfd| directory over the |fd| socket and close the socket once done.
  // This should also call ServerInterface::ConnectionTerminated() on |server|
  // once the connection is closed and report the desired metrics calling
  // ServerInterface::ReportServerMessage().
  virtual void Run() = 0;
};

// A ConnectionDelegateFactory is a function that builds a
// ConnectionDelegateInterface that should serve files from the directory
// referenced by the file descriptor |dirfd| through the socket |fd| at a
// rate not bigger than |max_download_rate| bytes per second.
// |pretty_addr| is a string identifying the client's address and the |server|
// points to the ServerInterface instance to notify when the transfer is done.
typedef ConnectionDelegateInterface*(ConnectionDelegateFactory)(
    int dirfd,
    int fd,
    const std::string& pretty_addr,
    ServerInterface* server,
    int64_t max_download_rate);

}  // namespace http_server

}  // namespace p2p

#endif  // P2P_HTTP_SERVER_CONNECTION_DELEGATE_INTERFACE_H_
