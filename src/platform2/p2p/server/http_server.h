// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P2P_SERVER_HTTP_SERVER_H_
#define P2P_SERVER_HTTP_SERVER_H_

#include <stdint.h>

#include <string>

#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <metrics/metrics_library.h>

namespace p2p {

namespace server {

// Interface for starting/stopping a HTTP server and getting feedback
// about the number of connected HTTP clients.
class HttpServer {
 public:
  // Called when number of connections changes
  typedef base::RepeatingCallback<void(int num_connections)>
      NumConnectionsCallback;

  virtual ~HttpServer() = default;

  // Statrs the HTTP server.
  virtual bool Start() = 0;

  // Stops the HTTP server.
  virtual bool Stop() = 0;

  // Returns true the HTTP has been started.
  virtual bool IsRunning() = 0;

  // Returns the port number where the HTTP server is listening. A value of 0
  // means that the HTTP server is not yet listening on any port.
  virtual uint16_t Port() = 0;

  // Sets the callback function used for reporting number of connections.
  // In order to receive callbacks, you need to run the default
  // GLib main-loop.
  virtual void SetNumConnectionsCallback(NumConnectionsCallback callback) = 0;

  // Creates and initializes a suitable HttpServer instance for
  // serving files from |root_dir| on the TCP port given by |port|.
  // The passed |bin_dir| directory should contain the http-server executable
  // to launch.
  // Note that the server will not initially be running; use the  Start()
  // method to start it.
  static HttpServer* Construct(MetricsLibraryInterface* metrics_lib,
                               const base::FilePath& root_dir,
                               const base::FilePath& bin_dir,
                               uint16_t port);
};

}  // namespace server

}  // namespace p2p

#endif  // P2P_SERVER_HTTP_SERVER_H_
