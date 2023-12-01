// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P2P_SERVER_SERVICE_PUBLISHER_H_
#define P2P_SERVER_SERVICE_PUBLISHER_H_

#include <map>
#include <string>

namespace p2p {

namespace server {

// Interface for publishing information about files available from the
// local machine as well as how many clients are currently downloading.
class ServicePublisher {
 public:
  virtual ~ServicePublisher() = default;

  // Exports a file with identifier |file| and size in bytes given by
  // by |file_size|.
  virtual void AddFile(const std::string& file, size_t file_size) = 0;

  // Removes a file previoiusly exported with the AddFile() method.
  virtual void RemoveFile(const std::string& file) = 0;

  // Updates the file size of a file previously exported with the
  // AddFile() method.
  virtual void UpdateFileSize(const std::string& file, size_t file_size) = 0;

  // Set number of HTTP clients currently connected.
  virtual void SetNumConnections(int num_connections) = 0;

  // Gets the files currently exported.
  virtual std::map<std::string, size_t> files() = 0;

  // Creates and initializes a suitable ServicePublisher instance for
  // advertising files on a HTTP server running on the TCP port given
  // by |http_port|. By default no files are exported - use the
  // AddFile() method to start exporting files.
  static ServicePublisher* Construct(uint16_t http_port);
};

}  // namespace server

}  // namespace p2p

#endif  // P2P_SERVER_SERVICE_PUBLISHER_H_
