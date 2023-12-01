// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P2P_SERVER_HTTP_SERVER_EXTERNAL_PROCESS_H_
#define P2P_SERVER_HTTP_SERVER_EXTERNAL_PROCESS_H_

#include "p2p/server/http_server.h"

#include "p2p/common/server_message.h"
#include "p2p/common/struct_serializer.h"

#include <memory>

#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <metrics/metrics_library.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

namespace p2p {

namespace server {

class HttpServerExternalProcess : public HttpServer {
 public:
  HttpServerExternalProcess(MetricsLibraryInterface* metrics_lib,
                            const base::FilePath& root_dir,
                            const base::FilePath& bin_dir,
                            uint16_t port);
  HttpServerExternalProcess(const HttpServerExternalProcess&) = delete;
  HttpServerExternalProcess& operator=(const HttpServerExternalProcess&) =
      delete;

  ~HttpServerExternalProcess();

  virtual bool Start();

  virtual bool Stop();

  virtual bool IsRunning();

  virtual uint16_t Port();

  virtual void SetNumConnectionsCallback(NumConnectionsCallback callback);

 private:
  // Helper function to update |num_connections_| and fire
  // |num_connections_callback_| if something has changed.
  void UpdateNumConnections(int num_connections);

  // Used for waking up and processing stdout from the child process.
  // If the output matches lines of the form "num-connections: %d",
  // calls UpdateNumConnections() with the parsed integer.

  static void OnMessageReceived(const p2p::util::P2PServerMessage& msg,
                                void* user_data);

  // Test methods are declared as friends to access the OnMessageReceived method
  // directly.
  friend int ::LLVMFuzzerTestOneInput(const uint8_t*, size_t);

  // The metrics library object to report metrics to.
  MetricsLibraryInterface* metrics_lib_;

  // The path to serve files from.
  base::FilePath root_dir_;

  // The path to the http-server binary.
  base::FilePath http_binary_path_;

  // The TCP port number for the HTTP server is requested to run on. A value
  // of 0 means that the HTTP server should pick the port number.
  uint16_t requested_port_;

  // The TCP port number reported from the HTTP server. This is the actual
  // port number where the HTTP server is listening, while |requested_port_|
  // can be 0 to indicate the HTTP server should pick the port number.
  uint16_t port_;

  // The current number of connections to the HTTP server.
  int num_connections_;
  GPid pid_;
  int child_stdout_fd_;
  NumConnectionsCallback num_connections_callback_;

  // A message watch for child P2PServerMessages.
  std::unique_ptr<
      p2p::util::StructSerializerWatcher<p2p::util::P2PServerMessage>>
      child_watch_;
};

}  // namespace server

}  // namespace p2p

#endif  // P2P_SERVER_HTTP_SERVER_EXTERNAL_PROCESS_H_
