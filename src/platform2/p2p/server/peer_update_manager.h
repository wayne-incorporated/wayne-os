// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P2P_SERVER_PEER_UPDATE_MANAGER_H_
#define P2P_SERVER_PEER_UPDATE_MANAGER_H_

#include "p2p/server/file_watcher.h"
#include "p2p/server/http_server.h"
#include "p2p/server/service_publisher.h"

namespace p2p {

namespace server {

// Monitors files in a directory and publishes them on the LAN.
// Also manages the life-cycle of a HTTP server for including
// publishing the current number of connections to the
// HTTP server.
class PeerUpdateManager {
 public:
  // Constructs an uninitialized object. The user must call Init()
  // before calling any other method.
  PeerUpdateManager(FileWatcher* watcher,
                    ServicePublisher* publisher,
                    HttpServer* http_server,
                    MetricsLibraryInterface* metrics_lib);
  PeerUpdateManager(const PeerUpdateManager&) = delete;
  PeerUpdateManager& operator=(const PeerUpdateManager&) = delete;

  ~PeerUpdateManager();

  // Initializes the object.
  void Init();

 private:
  void Publish(const base::FilePath& file);
  void Update(const base::FilePath& file);
  void Unpublish(const base::FilePath& file);

  void OnFileWatcherChanged(const base::FilePath& file,
                            FileWatcher::EventType event_type);

  void OnHttpServerNumConnectionsChanged(int num_connections);

  // Sends a metric with the FileCount if that value was changed since the last
  // time this method was called.
  void UpdateFileCountMetric();

  void UpdateHttpServer();

  void UpdateNumConnections(int num_connections);

  FileWatcher* file_watcher_;
  ServicePublisher* publisher_;
  HttpServer* http_server_;
  MetricsLibraryInterface* metrics_lib_;
  int num_connections_;

  // A copy of publisher_->files().size() the last time it was reported
  // to libmetrics.
  int last_num_files_;
};

}  // namespace server

}  // namespace p2p

#endif  // P2P_SERVER_PEER_UPDATE_MANAGER_H_
