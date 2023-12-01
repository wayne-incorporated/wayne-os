// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <signal.h>
#include <stdint.h>
#include <stdio.h>

#include <cassert>
#include <cerrno>
#include <memory>

#include <base/command_line.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/rand_util.h>
#include <base/strings/string_number_conversions.h>
#include <metrics/metrics_library.h>

#include "p2p/client/peer_selector.h"
#include "p2p/client/service_finder.h"
#include "p2p/common/clock.h"
#include "p2p/common/constants.h"
#include "p2p/common/util.h"

using std::map;
using std::string;
using std::vector;

/* Global pointer to the PeerSelector being used. Only used from the signal
 * handler of SIGTERM. */
static p2p::client::PeerSelector* volatile global_peer_selector = NULL;

static void sigterm_handler(int signum) {
  /* This function is non-reentrant since is only used to handle SIGTERM.
   * A second SIGTERM signal will wait until this call finishes. */
  if (global_peer_selector)
    global_peer_selector->Abort();
}

static void Usage(FILE* output) {
  fprintf(output,
          "Usage:\n"
          "  p2p-client [OPTION..]\n"
          "\n"
          "Options:\n"
          " --help             Show help options\n"
          " --list-all         Scan network and list available files\n"
          " --list-urls=ID     Like --list-all but only show peers for ID\n"
          " --get-url=ID       Scan for ID and pick a suitable peer\n"
          " --num-connections  Show total number of connections in the LAN\n"
          " -v=NUMBER          Verbosity level (default: 0)\n"
          " --minimum-size=NUM When used with --get-url, scans for files\n"
          "                    with at least NUM bytes (default: 1).\n"
          "\n");
}

// Lists all URLs discovered via |finder|. If |id| is not the empty
// string then only lists URLs matching it.
static void ListUrls(p2p::client::ServiceFinder* finder,
                     const std::string& id) {
  vector<string> files = finder->AvailableFiles();

  for (auto const& file_name : files) {
    if (id == "" || file_name == id) {
      printf("%s\n", file_name.c_str());
      vector<const p2p::client::Peer*> peers =
          finder->GetPeersForFile(file_name);
      for (auto const& peer : peers) {
        map<string, size_t>::const_iterator file_size_it =
            peer->files.find(file_name);
        printf(" address %s, port %d, size %zu, num_connections %d\n",
               peer->address.c_str(), peer->port,
               (file_size_it == peer->files.end() ? -1 : file_size_it->second),
               peer->num_connections);
      }
    }
  }
}

int main(int argc, char* argv[]) {
  std::unique_ptr<p2p::client::ServiceFinder> finder;

  base::CommandLine::Init(argc, argv);
  logging::LoggingSettings logging_settings;
  logging_settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
  logging_settings.lock_log = logging::LOCK_LOG_FILE;
  logging_settings.delete_old = logging::APPEND_TO_OLD_LOG_FILE;
  logging::InitLogging(logging_settings);
  p2p::util::SetupSyslog("p2p-client", true /* include_pid */);

  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();

  // If help is requested, show usage and exit immediately
  if (cl->HasSwitch("help")) {
    Usage(stdout);
    return 0;
  }

  // Get us a ServiceFinder and look up all peers - this takes a couple
  // of seconds. This can fail if e.g. avahi-daemon is not running.
  finder.reset(p2p::client::ServiceFinder::Construct());
  if (finder == NULL)
    return 1;

  p2p::common::Clock clock;
  p2p::client::PeerSelector peer_selector(finder.get(), &clock);
  // The Metrics Library interface for reporting UMA stats.

  if (cl->HasSwitch("list-all")) {
    finder->Lookup();
    ListUrls(finder.get(), "");
  } else if (cl->HasSwitch("num-connections")) {
    finder->Lookup();
    int num_connections = finder->NumTotalConnections();
    printf("%d\n", num_connections);
  } else if (cl->HasSwitch("get-url")) {
    string id = cl->GetSwitchValueNative("get-url");
    uint64_t minimum_size = 1;
    if (cl->HasSwitch("minimum-size")) {
      string minimum_size_str = cl->GetSwitchValueNative("minimum-size");
      if (!base::StringToUint64(minimum_size_str, &minimum_size)) {
        LOG(ERROR) << "Invalid --minimum-size argument";
        return 1;
      }
    }

    // Register the SIGTERM signal handler in order to abort the
    // GetUrlAndWait() call, but reporting the metric.
    global_peer_selector = &peer_selector;
    signal(SIGTERM, sigterm_handler);

    string url = peer_selector.GetUrlAndWait(id, minimum_size);

    // Remove the global pointer reference to avoid a Abort() call due a
    // SIGTERM after the pointed object is destroyed.
    global_peer_selector = NULL;

    // Report the metrics.
    MetricsLibrary metrics_lib;
    peer_selector.ReportMetrics(&metrics_lib);

    if (url == "")
      return 1;
    printf("%s\n", url.c_str());
  } else if (cl->HasSwitch("list-urls")) {
    string id = cl->GetSwitchValueNative("list-urls");
    finder->Lookup();
    ListUrls(finder.get(), id);
  } else {
    Usage(stderr);
    return 1;
  }

  return 0;
}
