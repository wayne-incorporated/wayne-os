// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P2P_HTTP_SERVER_SERVER_H_
#define P2P_HTTP_SERVER_SERVER_H_

#include <glib.h>
#include <stdint.h>

#include <map>
#include <memory>
#include <string>

#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/threading/simple_thread.h>

#include "p2p/common/clock_interface.h"
#include "p2p/common/server_message.h"
#include "p2p/http_server/server_interface.h"

namespace p2p {

namespace http_server {

class Server : public ServerInterface {
 public:
  // Constructs a new Server object.
  //
  // This constructor doesn't start the server - to start listening on
  // the socket, the Start() method will need to be called.
  // If |port| is 0, the kernel assigns a random free port that can be
  // retrieved with Port(). The Server will report messages as
  // P2PServerMessage strunct on the |message_fd|.
  Server(const base::FilePath& directory,
         uint16_t port,
         int message_fd,
         ConnectionDelegateFactory delegate_factory);
  Server(const Server&) = delete;
  Server& operator=(const Server&) = delete;

  ~Server() override;

  // ServerInterface override methods.
  bool Start() override;
  void Stop() override;
  void SetMaxDownloadRate(int64_t bytes_per_sec) override;
  uint16_t Port() override;
  int NumConnections() override;
  p2p::common::ClockInterface* Clock() override;
  void ConnectionTerminated(ConnectionDelegateInterface* delegate) override;
  void ReportServerMessage(p2p::util::P2PServerMessageType msg_type,
                           int64_t value) override;

 private:
  // Callback used clients connect to our listening socket.
  static gboolean OnIOChannelActivity(GIOChannel* source,
                                      GIOCondition condition,
                                      gpointer data);

  // Updates number of connections. May be called from any thread.
  //
  // As a side-effect, prints the number of connection on stdout
  // for reporting to higher-level code.
  void UpdateNumConnections(int delta_num_connections);

  // Clock used for time-keeping and sleeping.
  std::unique_ptr<p2p::common::ClockInterface> clock_;

  // Thread pool used for worker threads.
  base::DelegateSimpleThreadPool thread_pool_;

  // The path of the directory we're serving .p2p files from.
  base::FilePath directory_;

  // The file descriptor for the directory corresponding to |directory_|.
  int dirfd_;

  // The TCP port to listen on.
  uint16_t port_;

  // The socket where the P2PServerMessage is reported.
  int message_fd_;

  // The maximum download rate of 0 if there is no limit.
  int64_t max_download_rate_;

  // Set to true only if the server is running.
  bool started_;

  // The file descriptor for the socket we're listening on.
  int listen_fd_;

  // The GLib source id for our socket.
  guint listen_source_id_;

  // The current number of connected clients.
  int num_connections_;

  // Object-wide lock.
  base::Lock lock_;

  // A ConnectionDelegateInterface factory used to serve the connections.
  ConnectionDelegateFactory* delegate_factory_;
};

}  // namespace http_server

}  // namespace p2p

#endif  // P2P_HTTP_SERVER_SERVER_H_
