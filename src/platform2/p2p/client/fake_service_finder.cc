// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "p2p/client/fake_service_finder.h"

#include <set>

#include <base/logging.h>

using std::map;
using std::set;
using std::string;
using std::vector;

namespace p2p {

namespace client {

FakeServiceFinder::FakeServiceFinder()
    : num_lookup_calls_(0), service_filtered_(false) {}

FakeServiceFinder::~FakeServiceFinder() = default;

vector<const Peer*> FakeServiceFinder::GetPeersForFile(
    const string& file) const {
  vector<const Peer*> res;
  if (service_filtered_)
    return res;

  for (auto const& peer : peers_) {
    if (peer.files.find(file) != peer.files.end())
      res.push_back(&peer);
  }
  return res;
}

vector<string> FakeServiceFinder::AvailableFiles() const {
  if (service_filtered_)
    return vector<string>();

  set<string> retset;
  for (auto const& peer : peers_) {
    for (auto const& file : peer.files) {
      retset.insert(file.first);
    }
  }
  return vector<string>(retset.begin(), retset.end());
}

int FakeServiceFinder::NumTotalConnections() const {
  int res = 0;
  if (service_filtered_)
    return res;

  for (auto const& peer : peers_)
    res += peer.num_connections;
  return res;
}

int FakeServiceFinder::NumTotalPeers() const {
  if (service_filtered_)
    return 0;
  return peers_.size();
}

bool FakeServiceFinder::Lookup() {
  num_lookup_calls_++;

  // Execute scheduled calls.
  if (set_peer_connections_calls_.find(num_lookup_calls_) !=
      set_peer_connections_calls_.end()) {
    for (auto const& params : set_peer_connections_calls_[num_lookup_calls_])
      SetPeerConnections(params.peer_id, params.connections);
    set_peer_connections_calls_.erase(num_lookup_calls_);
  }

  if (remove_available_file_calls_.find(num_lookup_calls_) !=
      remove_available_file_calls_.end()) {
    for (auto const& params : remove_available_file_calls_[num_lookup_calls_])
      RemoveAvailableFile(params);
    remove_available_file_calls_.erase(num_lookup_calls_);
  }

  if (peer_share_file_calls_.find(num_lookup_calls_) !=
      peer_share_file_calls_.end()) {
    for (auto const& params : peer_share_file_calls_[num_lookup_calls_])
      PeerShareFile(params.peer_id, params.file, params.size);
    peer_share_file_calls_.erase(num_lookup_calls_);
  }

  return !service_filtered_;
}

void FakeServiceFinder::Abort() {}

int FakeServiceFinder::GetNumLookupCalls() {
  return num_lookup_calls_;
}

void FakeServiceFinder::SetServiceFiltered(bool filtered) {
  service_filtered_ = filtered;
}

int FakeServiceFinder::NewPeer(string address, bool is_ipv6, uint16_t port) {
  peers_.push_back((Peer){.address = address,
                          .is_ipv6 = is_ipv6,
                          .port = port,
                          .num_connections = 0,
                          .files = map<string, size_t>()});
  return peers_.size() - 1;
}

bool FakeServiceFinder::SetPeerConnections(int peer_id, int connections) {
  if (peer_id < 0 || static_cast<unsigned>(peer_id) >= peers_.size()) {
    LOG(ERROR) << "Invalid peer_id provided: " << peer_id << ".";
    return false;
  }
  peers_[peer_id].num_connections = connections;
  return true;
}

bool FakeServiceFinder::SetPeerConnectionsOnLookup(int at_call,
                                                   int peer_id,
                                                   int connections) {
  if (at_call < num_lookup_calls_)
    return false;
  if (at_call == num_lookup_calls_)
    return SetPeerConnections(peer_id, connections);
  set_peer_connections_calls_[at_call].push_back(
      (SetPeerConnectionsCall){.peer_id = peer_id, .connections = connections});
  return true;
}

bool FakeServiceFinder::PeerShareFile(int peer_id,
                                      const string& file,
                                      size_t size) {
  if (peer_id < 0 || static_cast<unsigned>(peer_id) >= peers_.size()) {
    LOG(ERROR) << "Invalid peer_id provided: " << peer_id << ".";
    return false;
  }
  peers_[peer_id].files[file] = size;
  return true;
}

bool FakeServiceFinder::PeerShareFileOnLookup(int at_call,
                                              int peer_id,
                                              const std::string& file,
                                              size_t size) {
  if (at_call < num_lookup_calls_)
    return false;
  if (at_call == num_lookup_calls_)
    return PeerShareFile(peer_id, file, size);
  peer_share_file_calls_[at_call].push_back(
      (PeerShareFileCall){.peer_id = peer_id, .file = file, .size = size});
  return true;
}

bool FakeServiceFinder::RemoveAvailableFile(const string& file) {
  int removed = 0;

  for (auto& peer : peers_) {
    map<string, size_t>::iterator file_it = peer.files.find(file);
    if (file_it != peer.files.end()) {
      peer.files.erase(file_it);
      removed++;
    }
  }

  if (!removed) {
    LOG(ERROR) << "Removing unexisting file <" << file << ">.";
    return false;
  }
  return true;
}

bool FakeServiceFinder::RemoveAvailableFileOnLookup(int at_call,
                                                    const std::string& file) {
  if (at_call < num_lookup_calls_)
    return false;
  if (at_call == num_lookup_calls_)
    return RemoveAvailableFile(file);
  // Ensure the RemoveAvailableFile() calls before the PeerShareFile() ones.
  if (peer_share_file_calls_.find(at_call) != peer_share_file_calls_.end())
    return false;
  remove_available_file_calls_[at_call].push_back(file);
  return true;
}

}  // namespace client

}  // namespace p2p
