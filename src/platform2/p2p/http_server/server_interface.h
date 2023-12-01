// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P2P_HTTP_SERVER_SERVER_INTERFACE_H_
#define P2P_HTTP_SERVER_SERVER_INTERFACE_H_

#include <stdint.h>

#include "p2p/common/clock_interface.h"
#include "p2p/common/server_message.h"
#include "p2p/http_server/connection_delegate_interface.h"

namespace p2p {

namespace http_server {

class ServerInterface {
 public:
  virtual ~ServerInterface() = default;

  // Starts the server. Returns false on failure.
  virtual bool Start() = 0;

  // Stops the server.
  //
  // Note that it is considered a programming error to delete the
  // object without stopping it.
  virtual void Stop() = 0;

  // Sets the maximum download rate. The special value 0 means there
  // is no limit. Note that this is per connection.
  virtual void SetMaxDownloadRate(int64_t bytes_per_sec) = 0;

  // Gets the port number the server listens on.
  virtual uint16_t Port() = 0;

  // Gets the current number of connected clients.
  virtual int NumConnections() = 0;

  // Gets the clock used by the server.
  virtual p2p::common::ClockInterface* Clock() = 0;

  // Method called in by |delegate|, in its own thread.
  virtual void ConnectionTerminated(ConnectionDelegateInterface* delegate) = 0;

  // Sends a P2PServerMessage to the stdout. This is used to report various
  // metrics and to report the number of current connections. This method is
  // thread safe and is intended to be use by the ConnectionDelegates.
  virtual void ReportServerMessage(p2p::util::P2PServerMessageType msg_type,
                                   int64_t value) = 0;
};

}  // namespace http_server

}  // namespace p2p

#endif  // P2P_HTTP_SERVER_SERVER_INTERFACE_H_
