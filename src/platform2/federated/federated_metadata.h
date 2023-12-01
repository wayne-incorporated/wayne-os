// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FEDERATED_FEDERATED_METADATA_H_
#define FEDERATED_FEDERATED_METADATA_H_

#include <string>
#include <unordered_map>
#include <unordered_set>

namespace federated {

// The client config. One client corresponds to a task group deployed on the
// server. Its `name` must be identical to the population_name of this task, and
// on ChromeOS platform one population can only has one task group.
struct ClientConfigMetadata {
  // Unique identifier of the client that contains only lowercase letters,
  // numbers and underscore. Must not be empty.
  std::string name;
  // Leaves this empty when initialization. Could be altered with server
  // response.
  std::string retry_token;
  // The launch stage used to compose a unique population name together with
  // `name`.
  // Value can be overwritten by mojo call. After overwriting if launch stage
  // is empty, scheduler will skip this client. (No federated tasks scheduled,
  // but examples reported to this client will still be stored.)
  std::string launch_stage;
};

// Returns a map from client_name to ClientConfigMetadata.
std::unordered_map<std::string, ClientConfigMetadata> GetClientConfig();

// Returns a set of all registered client names;
std::unordered_set<std::string> GetClientNames();

}  // namespace federated

#endif  // FEDERATED_FEDERATED_METADATA_H_
