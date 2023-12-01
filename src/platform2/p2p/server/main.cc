// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <avahi-client/client.h>
#include <avahi-client/publish.h>
#include <avahi-common/error.h>
#include <avahi-glib/glib-watch.h>
#include <gio/gio.h>
#include <stdio.h>

#include <cassert>
#include <cerrno>

#include <base/command_line.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <metrics/metrics_library.h>

#include "p2p/common/constants.h"
#include "p2p/common/util.h"
#include "p2p/server/file_watcher.h"
#include "p2p/server/peer_update_manager.h"
#include "p2p/server/service_publisher.h"

using std::string;

using base::FilePath;

static void Usage(FILE* output) {
  fprintf(
      output,
      "Usage:\n"
      "  p2p-server [OPTION..]\n"
      "\n"
      "Options:\n"
      " --help            Show help options\n"
      " --path=DIR        Where to serve from\n"
      "\n"
      " --port=NUMBER     TCP port number for HTTP server (default: 16725)\n"
      " -v=NUMBER         Verbosity level (default: 0)\n"
      "\n");
}

int main(int argc, char* argv[]) {
  int ret = 1;
  GMainLoop* loop = NULL;

  base::CommandLine::Init(argc, argv);

  logging::LoggingSettings logging_settings;
  logging_settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
  logging_settings.lock_log = logging::LOCK_LOG_FILE;
  logging_settings.delete_old = logging::APPEND_TO_OLD_LOG_FILE;
  logging::InitLogging(logging_settings);
  p2p::util::SetupSyslog(p2p::constants::kServerBinaryName,
                         false /* include_pid */);

  LOG(INFO) << p2p::constants::kServerBinaryName << " starting";

  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();

  if (cl->HasSwitch("help")) {
    Usage(stdout);
    return 0;
  }

  FilePath path = cl->GetSwitchValuePath("path");
  if (path.empty()) {
    path = FilePath(p2p::constants::kP2PDir);
  }
  p2p::server::FileWatcher* file_watcher =
      p2p::server::FileWatcher::Construct(path, ".p2p");

  uint16_t http_port = p2p::constants::kHttpServerDefaultPort;
  string http_port_str = cl->GetSwitchValueNative("port");
  if (http_port_str.size() > 0) {
    char* endp;
    http_port = strtol(http_port_str.c_str(), &endp, 0);
    if (*endp != '\0') {
      fprintf(stderr, "Error parsing `%s' as port number\n",
              http_port_str.c_str());
      exit(1);
    }
  }
  MetricsLibrary metrics_lib;
  p2p::server::HttpServer* http_server = p2p::server::HttpServer::Construct(
      &metrics_lib, path, FilePath("/usr/sbin"), http_port);

  p2p::server::ServicePublisher* service_publisher =
      p2p::server::ServicePublisher::Construct(http_port);
  if (!service_publisher) {
    fprintf(stderr, "Error constructing ServicePublisher.\n");
    exit(1);
  }

  p2p::server::PeerUpdateManager manager(file_watcher, service_publisher,
                                         http_server, &metrics_lib);
  manager.Init();

  loop = g_main_loop_new(NULL, FALSE);
  g_main_loop_run(loop);

  ret = 0;

  g_main_loop_unref(loop);

  delete service_publisher;
  delete http_server;
  delete file_watcher;

  return ret;
}
