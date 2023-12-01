// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "p2p/server/http_server.h"
#include "p2p/server/http_server_external_process.h"

#include <glib.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

#include <memory>
#include <vector>

#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/notreached.h>

#include "p2p/common/constants.h"
#include "p2p/common/server_message.h"
#include "p2p/common/struct_serializer.h"

using std::string;
using std::vector;

using base::FilePath;

using p2p::util::P2PServerMessage;
using p2p::util::P2PServerMessageType;
using p2p::util::StructSerializerWatcher;

namespace p2p {

namespace server {

HttpServerExternalProcess::HttpServerExternalProcess(
    MetricsLibraryInterface* metrics_lib,
    const FilePath& root_dir,
    const FilePath& bin_dir,
    uint16_t port)
    : metrics_lib_(metrics_lib),
      root_dir_(root_dir),
      http_binary_path_(bin_dir.Append(p2p::constants::kHttpServerBinaryName)),
      requested_port_(port),
      port_(0),
      num_connections_(0),
      pid_(0),
      child_stdout_fd_(-1) {}

HttpServerExternalProcess::~HttpServerExternalProcess() {
  child_watch_.reset(nullptr);

  if (child_stdout_fd_ != -1) {
    close(child_stdout_fd_);
  }
  if (pid_ != 0) {
    kill(pid_, SIGTERM);
  }
}

bool HttpServerExternalProcess::Start() {
  string command_line;

  if (pid_ != 0) {
    LOG(ERROR) << "Server is already running with pid " << pid_;
    return false;
  }
  CHECK_EQ(child_stdout_fd_, -1);

  vector<const char*> args;
  string dir_arg = string("--directory=") + root_dir_.value();
  string requested_port_arg =
      string("--port=") + std::to_string(requested_port_);

  args.push_back(http_binary_path_.value().c_str());
  args.push_back(dir_arg.c_str());
  args.push_back(requested_port_arg.c_str());
  args.push_back(NULL);

  GError* error = NULL;
  if (!g_spawn_async_with_pipes(NULL,  // working_dir
                                const_cast<gchar**>(args.data()),
                                NULL,  // envp
                                (GSpawnFlags)0, NULL,
                                NULL,  // child_setup, user_data
                                &pid_,
                                NULL,  // standard_input
                                &child_stdout_fd_,
                                NULL,  // standard_error
                                &error)) {
    LOG(ERROR) << "Error launching process: " << error->message;
    g_error_free(error);
    return false;
  }

  // Setup the watch class for child messages.
  child_watch_.reset(new StructSerializerWatcher<P2PServerMessage>(
      child_stdout_fd_, OnMessageReceived, reinterpret_cast<void*>(this)));

  return true;
}

void HttpServerExternalProcess::OnMessageReceived(const P2PServerMessage& msg,
                                                  void* user_data) {
  HttpServerExternalProcess* server =
      reinterpret_cast<HttpServerExternalProcess*>(user_data);
  P2PServerMessageType message_type;
  string metric;

  if (!p2p::util::ValidP2PServerMessageMagic(msg) ||
      !p2p::util::ParseP2PServerMessageType(msg.message_type, &message_type)) {
    LOG(ERROR) << "Received invalid message: " << p2p::util::ToString(msg);
    LOG(ERROR) << "Attempting to restarting P2P service.";
    // Stop the child and abort ourselves.
    server->Stop();
    exit(1);
  }

  switch (message_type) {
    case p2p::util::kP2PServerNumConnections:
      if (msg.value >= 0)
        server->UpdateNumConnections(msg.value);
      break;

    case p2p::util::kP2PServerRequestResult:
      metric = "P2P.Server.RequestResult";
      p2p::util::P2PServerRequestResult req_res;
      if (p2p::util::ParseP2PServerRequestResult(msg.value, &req_res)) {
        LOG(INFO) << "Uploading " << ToString(req_res) << " for metric "
                  << metric;
        server->metrics_lib_->SendEnumToUMA(
            metric, req_res, p2p::util::kNumP2PServerRequestResults);
      } else {
        LOG(ERROR) << "Received invalid message: " << p2p::util::ToString(msg);
      }
      break;

    case p2p::util::kP2PServerServedSuccessfullyMB:
      metric = "P2P.Server.ContentServedSuccessfullyMB";
      LOG(INFO) << "Uploading " << msg.value << " (count) for metric "
                << metric;
      server->metrics_lib_->SendToUMA(metric, msg.value, 0 /* min */,
                                      1000 /* max */, 50);
      break;

    case p2p::util::kP2PServerServedInterruptedMB:
      metric = "P2P.Server.ContentServedInterruptedMB";
      LOG(INFO) << "Uploading " << msg.value << " (count) for metric "
                << metric;
      server->metrics_lib_->SendToUMA(metric, msg.value, 0 /* min */,
                                      1000 /* max */, 50);
      break;

    case p2p::util::kP2PServerRangeBeginPercentage:
      metric = "P2P.Server.RangeBeginPercentage";
      LOG(INFO) << "Uploading " << msg.value << " (count) for metric "
                << metric;
      server->metrics_lib_->SendToUMA(metric, msg.value, 0 /* min */,
                                      100 /* max */, 100);
      break;

    case p2p::util::kP2PServerDownloadSpeedKBps:
      metric = "P2P.Server.DownloadSpeedKBps";
      LOG(INFO) << "Uploading " << msg.value << " (count) for metric "
                << metric;
      server->metrics_lib_->SendToUMA(metric, msg.value, 0 /* min */,
                                      10000 /* max */, 100);
      break;

    case p2p::util::kP2PServerPeakDownloadSpeedKBps:
      metric = "P2P.Server.PeakDownloadSpeedKBps";
      LOG(INFO) << "Uploading " << msg.value << " (count) for metric "
                << metric;
      server->metrics_lib_->SendToUMA(metric, msg.value, 0 /* min */,
                                      10000 /* max */, 100);
      break;

    case p2p::util::kP2PServerClientCount:
      metric = "P2P.Server.ClientCount";
      LOG(INFO) << "Uploading " << msg.value << " (count) for metric "
                << metric;
      server->metrics_lib_->SendToUMA(metric, msg.value, 0 /* min */,
                                      50 /* max */, 50);
      break;

    case p2p::util::kP2PServerPortNumber:
      server->port_ = msg.value;
      break;

    // ParseP2PServerMessageType ensures this case is not reached.
    case p2p::util::kNumP2PServerMessageTypes:
      NOTREACHED();
  }
}

void HttpServerExternalProcess::UpdateNumConnections(int num_connections) {
  if (num_connections_ == num_connections)
    return;

  num_connections_ = num_connections;

  if (!num_connections_callback_.is_null())
    num_connections_callback_.Run(num_connections);
}

bool HttpServerExternalProcess::Stop() {
  if (pid_ == 0) {
    LOG(ERROR) << "Server is not running";
    return false;
  }

  child_watch_.reset(nullptr);

  if (child_stdout_fd_ != -1) {
    close(child_stdout_fd_);
  }
  child_stdout_fd_ = -1;

  if (pid_ != 0) {
    kill(pid_, SIGTERM);
  }
  pid_ = 0;

  port_ = 0;

  return true;
}

bool HttpServerExternalProcess::IsRunning() {
  return pid_ != 0;
}

uint16_t HttpServerExternalProcess::Port() {
  return port_;
}

void HttpServerExternalProcess::SetNumConnectionsCallback(
    NumConnectionsCallback callback) {
  num_connections_callback_ = callback;
}

// ----------------------------------------------------------------------------

HttpServer* HttpServer::Construct(MetricsLibraryInterface* metrics_lib,
                                  const FilePath& root_dir,
                                  const FilePath& bin_dir,
                                  uint16_t port) {
  return new HttpServerExternalProcess(metrics_lib, root_dir, bin_dir, port);
}

}  // namespace server

}  // namespace p2p
