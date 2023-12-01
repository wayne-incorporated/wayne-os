// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P2P_HTTP_SERVER_FAKE_CONNECTION_DELEGATE_H_
#define P2P_HTTP_SERVER_FAKE_CONNECTION_DELEGATE_H_

#include <string>

#include "p2p/http_server/connection_delegate_interface.h"
#include "p2p/http_server/server_interface.h"

namespace p2p {

namespace http_server {

// An implementation of ConnectionDelegateInterface that doesn't actually
// serve any data.
class FakeConnectionDelegate : public ConnectionDelegateInterface {
 public:
  FakeConnectionDelegate(int dirfd,
                         int fd,
                         const std::string& pretty_addr,
                         ServerInterface* server,
                         int64_t max_download_rate)
      : fd_(fd), server_(server) {}
  FakeConnectionDelegate(const FakeConnectionDelegate&) = delete;
  FakeConnectionDelegate& operator=(const FakeConnectionDelegate&) = delete;

  // A ConnectionDelegate factory.
  static ConnectionDelegateInterface* Construct(int dirfd,
                                                int fd,
                                                const std::string& pretty_addr,
                                                ServerInterface* server,
                                                int64_t max_download_rate) {
    return new FakeConnectionDelegate(dirfd, fd, pretty_addr, server,
                                      max_download_rate);
  }

  // Overrides ConnectionDelegateInterface.
  void Run() override {
    FILE* f = fdopen(fd_, "r+");
    char* cmd = NULL;
    size_t cmd_len = 0;
    // Run a very simple server for testing.
    while (getline(&cmd, &cmd_len, f) != -1) {
      if (!strcmp("ping\n", cmd)) {
        ASSERT_EQ(fwrite("pong\n", 5, 1, f), 1);
        fflush(f);
      } else if (!strcmp("quit\n", cmd)) {
        break;
      }
    }
    free(cmd);

    server_->ConnectionTerminated(this);
    fclose(f);  // This closes fd_

    // We don't keep track of the created ConnectionDelegates, because
    // they are supposed to be deleted after Run() is called.
    delete this;
  }

 private:
  int fd_;
  ServerInterface* server_;
};

}  // namespace http_server

}  // namespace p2p

#endif  // P2P_HTTP_SERVER_FAKE_CONNECTION_DELEGATE_H_
