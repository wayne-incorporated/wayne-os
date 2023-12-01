// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "p2p/server/peer_update_manager.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

#include <base/functional/bind.h>
#include <base/logging.h>

using std::string;

using base::FilePath;

namespace p2p {

namespace server {

static size_t GetFileSize(const FilePath& file_path) {
  struct stat statbuf;
  if (stat(file_path.value().c_str(), &statbuf) != 0) {
    PLOG(ERROR) << "Error getting file size for " << file_path.value();
    return 0;
  }
  return statbuf.st_size;
}

PeerUpdateManager::PeerUpdateManager(FileWatcher* file_watcher,
                                     ServicePublisher* publisher,
                                     HttpServer* http_server,
                                     MetricsLibraryInterface* metrics_lib)
    : file_watcher_(file_watcher),
      publisher_(publisher),
      http_server_(http_server),
      metrics_lib_(metrics_lib),
      num_connections_(0) {}

PeerUpdateManager::~PeerUpdateManager() = default;

void PeerUpdateManager::Publish(const FilePath& file) {
  if (file.Extension() == file_watcher_->file_extension()) {
    string id_with_extension = file.BaseName().value();
    string id = id_with_extension.substr(0, id_with_extension.size() - 4);
    size_t file_size = GetFileSize(file);
    publisher_->AddFile(id, file_size);
    UpdateHttpServer();
  }
}

void PeerUpdateManager::Unpublish(const FilePath& file) {
  if (file.Extension() == file_watcher_->file_extension()) {
    string id_with_extension = file.BaseName().value();
    string id = id_with_extension.substr(0, id_with_extension.size() - 4);
    publisher_->RemoveFile(id);
    UpdateHttpServer();
  }
}

void PeerUpdateManager::Update(const FilePath& file) {
  if (file.Extension() == file_watcher_->file_extension()) {
    string id_with_extension = file.BaseName().value();
    string id = id_with_extension.substr(0, id_with_extension.size() - 4);
    size_t file_size = GetFileSize(file);
    publisher_->UpdateFileSize(id, file_size);
  }
}

void PeerUpdateManager::UpdateFileCountMetric() {
  int num_files = publisher_->files().size();
  if (num_files == last_num_files_)
    return;
  last_num_files_ = num_files;

  // Report P2P.Server.FileCount every time a file is added (Publish) or
  // removed (Unpublish).
  string metric = "P2P.Server.FileCount";
  LOG(INFO) << "Uploading " << metric << " (count) for metric " << num_files;
  metrics_lib_->SendToUMA(metric, num_files, 0 /* min */, 50 /* max */, 50);
}

void PeerUpdateManager::UpdateHttpServer() {
  int num_files = publisher_->files().size();
  if (num_files > 0) {
    if (!http_server_->IsRunning()) {
      http_server_->Start();
    }
  } else {
    if (http_server_->IsRunning()) {
      http_server_->Stop();
      UpdateNumConnections(0);
    }
  }
}

void PeerUpdateManager::UpdateNumConnections(int num_connections) {
  if (num_connections_ != num_connections) {
    num_connections_ = num_connections;
    publisher_->SetNumConnections(num_connections);
  }
}

void PeerUpdateManager::OnFileWatcherChanged(
    const FilePath& file, FileWatcher::EventType event_type) {
  VLOG(2) << "FileWatcher changed, path=" << file.value()
          << ", event_type=" << event_type;

  switch (event_type) {
    case FileWatcher::EventType::kFileAdded:
      Publish(file);
      UpdateFileCountMetric();
      break;

    case FileWatcher::EventType::kFileRemoved:
      Unpublish(file);
      UpdateFileCountMetric();
      break;

    case FileWatcher::EventType::kFileChanged:
      Update(file);
      break;
  }
}

void PeerUpdateManager::OnHttpServerNumConnectionsChanged(int num_connections) {
  UpdateNumConnections(num_connections);
}

void PeerUpdateManager::Init() {
  http_server_->SetNumConnectionsCallback(
      base::BindRepeating(&PeerUpdateManager::OnHttpServerNumConnectionsChanged,
                          base::Unretained(this)));

  for (auto const& file : file_watcher_->files()) {
    Publish(file);
  }
  last_num_files_ = publisher_->files().size();

  // TODO(zeuthen): Move to AddChangedCallback() for multiple
  // listeners. Or delegate pattern?
  file_watcher_->SetChangedCallback(base::BindRepeating(
      &PeerUpdateManager::OnFileWatcherChanged, base::Unretained(this)));
}

}  // namespace server

}  // namespace p2p
