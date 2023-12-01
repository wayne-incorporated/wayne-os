// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P2P_CLIENT_SERVICE_FINDER_H_
#define P2P_CLIENT_SERVICE_FINDER_H_

#include <map>
#include <set>
#include <string>
#include <vector>

#include <base/functional/callback.h>

#include "p2p/client/peer.h"

namespace p2p {

namespace client {

// Interface for finding local peers willing to serve files.
class ServiceFinder {
 public:
  virtual ~ServiceFinder() = default;

  // Given a file identified by the |file| paramater, returns a list
  // of peers that can serve it.
  //
  // This should only be called after calling Lookup(). Does no I/O.
  virtual std::vector<const Peer*> GetPeersForFile(
      const std::string& file) const = 0;

  // Gets a list of available files served by peers on the network.
  //
  // This should only be called after calling Lookup(). Does no I/O.
  virtual std::vector<std::string> AvailableFiles() const = 0;

  // Gets the total number of p2p downloads on the local network. This
  // is defined as the sum of the "num-connections" TXT entries for
  // all _cros_p2p._tcp instances.
  //
  // This should only be called after calling Lookup(). Does no I/O.
  virtual int NumTotalConnections() const = 0;

  // Gets the number of peers implementing p2p on the local network, although
  // not all of them are sharing a file.
  //
  // This should only be called after calling Lookup(). Does no I/O.
  virtual int NumTotalPeers() const = 0;

  // Looks up services on the local network. This method does blocking
  // I/O and it can take many seconds before it returns. May be called
  // multiple times to refresh the results.
  // If the service discovery is filtered (blocked) on the local network
  // returns false. Otherwise returns true.
  virtual bool Lookup() = 0;

  // Abort() cancels any ongoing and future call to Lookup() making it
  // return as soon as possible. This function is Async-Signal-Safe and can
  // be called several times.
  virtual void Abort() = 0;

  // Constructs a suitable implementation of ServiceFinder and
  // initializes it. This does blocking I/O. Returns NULL if
  // an error occured.
  static ServiceFinder* Construct();
};

}  // namespace client

}  // namespace p2p

#endif  // P2P_CLIENT_SERVICE_FINDER_H_
