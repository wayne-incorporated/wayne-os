// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cctype>
#include <cinttypes>
#include <string>

#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/logging.h>

#include "p2p/common/constants.h"
#include "p2p/common/util.h"
#include "p2p/http_server/connection_delegate.h"
#include "p2p/http_server/server.h"

using std::string;

using base::FilePath;

static void Usage(FILE* output) {
  fprintf(output,
          "Usage:\n"
          "  p2p-http-server [OPTION..]\n"
          "\n"
          "Options:\n"
          " --help           Show help options\n"
          " --directory=DIR  Directory to serve from (default: .)\n"
          " --port=PORT      TCP port number to listen on (default: 16725)\n"
          " -v=NUMBER        Verbosity level (default: 0)\n"
          "\n");
}

int main(int argc, char* argv[]) {
  int ret = 1;

  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();

  logging::LoggingSettings logging_settings;
  logging_settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
  logging_settings.lock_log = logging::LOCK_LOG_FILE;
  logging_settings.delete_old = logging::APPEND_TO_OLD_LOG_FILE;
  logging::InitLogging(logging_settings);
  p2p::util::SetupSyslog(p2p::constants::kHttpServerBinaryName,
                         false /* include_pid */);

  LOG(INFO) << p2p::constants::kHttpServerBinaryName << " starting";

  if (cl->HasSwitch("help")) {
    Usage(stdout);
    return 0;
  }

  uint16_t port = p2p::constants::kHttpServerDefaultPort;
  string port_str = cl->GetSwitchValueNative("port");
  if (port_str.size() > 0) {
    char* endp;
    port = strtol(port_str.c_str(), &endp, 0);
    if (*endp != '\0') {
      fprintf(stderr, "Error parsing `%s' as port number\n", port_str.c_str());
      return 1;
    }
  }

  FilePath directory = cl->GetSwitchValuePath("directory");
  if (directory.empty()) {
    directory = FilePath(FilePath::kCurrentDirectory);
  }

  p2p::http_server::Server server(
      directory, port, STDOUT_FILENO,
      p2p::http_server::ConnectionDelegate::Construct);
  LOG(INFO) << "Maximum download rate per connection set to "
            << p2p::constants::kMaxSpeedPerDownload << " bytes/sec";
  server.SetMaxDownloadRate(p2p::constants::kMaxSpeedPerDownload);
  server.Start();

  GMainLoop* loop = g_main_loop_new(NULL, FALSE);

  // TODO(zeuthen): Now that we've opened all the files and sockets
  // that we need, install a seccomp filter to only allow the very
  // limited set of syscalls we need onwards. See
  //
  //  http://outflux.net/teach-seccomp/
  //
  // for more information.
  //
  // This issue is currently tracked in
  //
  //  https://code.google.com/p/chromium/issues/detail?id=243406

  g_main_loop_run(loop);
  g_main_loop_unref(loop);

  server.Stop();

  return ret;
}
