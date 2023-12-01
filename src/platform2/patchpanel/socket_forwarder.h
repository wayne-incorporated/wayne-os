// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_SOCKET_FORWARDER_H_
#define PATCHPANEL_SOCKET_FORWARDER_H_

#include <netinet/ip.h>
#include <sys/socket.h>

#include <atomic>
#include <memory>
#include <string>

#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
// Ignore Wconversion warnings in libbase headers.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#include <base/threading/simple_thread.h>
#pragma GCC diagnostic pop
#include <brillo/brillo_export.h>

#include "patchpanel/socket.h"

namespace patchpanel {
// Forwards data between a pair of sockets.
// This is a simple implementation as a thread main function.
class BRILLO_EXPORT SocketForwarder : public base::SimpleThread {
 public:
  SocketForwarder(const std::string& name,
                  std::unique_ptr<Socket> sock0,
                  std::unique_ptr<Socket> sock1);
  SocketForwarder(const SocketForwarder&) = delete;
  SocketForwarder& operator=(const SocketForwarder&) = delete;

  virtual ~SocketForwarder();

  // Runs the forwarder. The sockets are closed and released on exit,
  // so this can only be run once.
  void Run() override;
  bool IsRunning() const;

  // Sets a closure for testing, which will be called when the forwarder is
  // stopped.
  void SetStopQuitClosureForTesting(base::OnceClosure closure);

 private:
  static constexpr int kBufSize = 4096;

  void Poll();
  bool ProcessEvents(uint32_t events, int efd, int cfd);

  std::unique_ptr<Socket> sock0_;
  std::unique_ptr<Socket> sock1_;
  char buf0_[kBufSize] = {0};
  char buf1_[kBufSize] = {0};
  size_t len0_;
  size_t len1_;
  // Indicates if an EOF has been sent (if it is greater than -1) and which
  // socket fd it was received on. This means that the socket file descriptor
  // indicated here should not be read from, only written to.
  int eof_;
  // Handles the case when the peer associated with |src| was closed for
  // writing. If the other peer is still open, the SocketForwarder will stop
  // listening for read events on the |src| socket, forward the write shutdown
  // to |dst| and return true to continue forwarding data received from the
  // other peer. If the |dst| socket is also closed for writing, it will return
  // false, which will stop the SocketForwarder instance. In case of error, it
  // returns false.
  bool HandleConnectionClosed(Socket* src, Socket* dst, int cfd);

  std::atomic<bool> poll_;
  std::atomic<bool> done_;

  base::OnceClosure stop_quit_closure_for_testing_;
};

}  // namespace patchpanel

#endif  // PATCHPANEL_SOCKET_FORWARDER_H_
