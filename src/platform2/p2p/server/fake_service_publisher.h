// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P2P_SERVER_FAKE_SERVICE_PUBLISHER_H_
#define P2P_SERVER_FAKE_SERVICE_PUBLISHER_H_

#include <map>
#include <string>

#include "p2p/server/service_publisher.h"

namespace p2p {

namespace server {

// A ServicePublisher that doesn't really do anything.
class FakeServicePublisher : public ServicePublisher {
 public:
  FakeServicePublisher() : num_connections_(0) {}
  FakeServicePublisher(const FakeServicePublisher&) = delete;
  FakeServicePublisher& operator=(const FakeServicePublisher&) = delete;

  void AddFile(const std::string& file, size_t file_size) override {
    files_[file] = file_size;
  }

  void RemoveFile(const std::string& file) override {
    std::map<std::string, size_t>::iterator it = files_.find(file);
    if (it != files_.end())
      files_.erase(it);
  }

  void UpdateFileSize(const std::string& file, size_t file_size) override {
    files_[file] = file_size;
  }

  void SetNumConnections(int num_connections) override {
    num_connections_ = num_connections;
  }

  std::map<std::string, size_t> files() override { return files_; }

 private:
  std::map<std::string, size_t> files_;
  int num_connections_;
};

}  // namespace server

}  // namespace p2p

#endif  // P2P_SERVER_FAKE_SERVICE_PUBLISHER_H_
