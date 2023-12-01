// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P2P_CLIENT_PEER_H_
#define P2P_CLIENT_PEER_H_

#include <stdint.h>

#include <map>
#include <string>

namespace p2p {

namespace client {

// A data structure for carrying information about a peer on the local
// network serving files via HTTP.
struct Peer {
  // The address (IP address or hostname) of the peer.
  std::string address;

  // Set to true if |address| is a literal IPv6 address.
  bool is_ipv6;

  // The TCP port number of the HTTP server.
  uint16_t port;

  // Number of clients currently being served by the peer.
  int num_connections;

  // Identifiers and sizes of the files served by the peer.
  std::map<std::string, size_t> files;
};

}  // namespace client

}  // namespace p2p

#endif  // P2P_CLIENT_PEER_H_
