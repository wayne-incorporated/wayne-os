// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P2P_CLIENT_FAKE_SERVICE_FINDER_H_
#define P2P_CLIENT_FAKE_SERVICE_FINDER_H_

#include <stdint.h>

#include <map>
#include <string>
#include <vector>

#include "p2p/client/service_finder.h"

namespace p2p {

namespace client {

class FakeServiceFinder : public ServiceFinder {
 public:
  FakeServiceFinder();
  FakeServiceFinder(const FakeServiceFinder&) = delete;
  FakeServiceFinder& operator=(const FakeServiceFinder&) = delete;

  ~FakeServiceFinder() override;

  // ServiceFinder interface methods.
  std::vector<const Peer*> GetPeersForFile(
      const std::string& file) const override;

  std::vector<std::string> AvailableFiles() const override;

  int NumTotalConnections() const override;

  int NumTotalPeers() const override;

  bool Lookup() override;

  void Abort() override;

  // FakeServiceFinder methods.

  // Returns the number of times Lookup() was called since the object creation.
  int GetNumLookupCalls();

  // Sets if the service is filtered to |filtered|.
  void SetServiceFiltered(bool filtered);

  // NewPeer() creates a new Peer object with the given properties. The return
  // value is a peer_id used only in the context of the fake implementation.
  int NewPeer(std::string address, bool is_ipv6, uint16_t port);

  // SetPeerConnections() sets the number of active connections reported by a
  // given peer. The |peer_id| argument is the numeric peer id returned by
  // NewPeer().
  bool SetPeerConnections(int peer_id, int connections);

  // SetPeerConnectionsOnLookup() is equivalent to call SetPeerConnections()
  // at the moment when the Lookup() method gets called for its |at_call|
  // time. Calling this method with |at_call| equal to GetNumLookupCalls()
  // will apply the changes right away. If |at_call| is lower than that value,
  // this method returns false. Otherwise returns true.
  bool SetPeerConnectionsOnLookup(int at_call, int peer_id, int connections);

  // PeerShareFile() will make the peer referred by |peer_id| to share the file
  // |file| with the current size |size|. If the file was previously shared by
  // that peer, the file size will be updated.
  // In case of an error, this method returns false. Otherwise returns true.
  bool PeerShareFile(int peer_id, const std::string& file, size_t size);

  // PeerShareFileOnLookup() is equivalent to call PeerShareFile() at the moment
  // when the Lookup() method gets called for its |at_call| time.
  // During that Lookup() call, any RemoveAvailableFileOnLookup() operation
  // scheduled for that Lookup() is performed before any PeerShareFileOnLookup()
  // scheduled for the same Lookup() call.
  // Calling this method with |at_call| equal to GetNumLookupCalls()
  // will apply the changes right away instead of schedule them. If |at_call|
  // is lower than that value, this method returns false. In any other case,
  // returns true.
  bool PeerShareFileOnLookup(int at_call,
                             int peer_id,
                             const std::string& file,
                             size_t size);

  // RemoveAvailableFile() removes a previously added file |file|. All the peers
  // sharing the given fill will drop it. If the file wasn't previously added
  // this method returns false. Otherwise, it returns true.
  bool RemoveAvailableFile(const std::string& file);

  // RemoveAvailableFileOnLookup() is equivalent to call RemoveAvailableFile()
  // at the moment when the Lookup() method gets called for its |at_call|
  // time.
  // During that Lookup() call, any RemoveAvailableFileOnLookup() operation
  // scheduled for that Lookup() is performed before any PeerShareFileOnLookup()
  // scheduled for the same Lookup() call. To enforce this restriction, this
  // method returns false when a PeerShareFileOnLookup() is already scheduled
  // for the requested |at_call| call.
  // Calling this method with |at_call| equal to GetNumLookupCalls()
  // will apply the changes right away instead of schedule them. If |at_call|
  // is lower than that value, this method returns false. In any other case,
  // returns true.
  bool RemoveAvailableFileOnLookup(int at_call, const std::string& file);

 private:
  // The list of peers on the network.
  std::vector<Peer> peers_;

  // Number of times Lookup() was called.
  int num_lookup_calls_;

  // Whether the service is filtered (blocked) in the local network.
  bool service_filtered_;

  // The scheduled calls for PeerShareFile on Lookup().
  struct SetPeerConnectionsCall {
    int peer_id;
    int connections;
  };
  std::map<int, std::vector<SetPeerConnectionsCall>>
      set_peer_connections_calls_;

  // The scheduled calls for PeerShareFile on Lookup().
  struct PeerShareFileCall {
    int peer_id;
    std::string file;
    size_t size;
  };
  std::map<int, std::vector<PeerShareFileCall>> peer_share_file_calls_;

  // The scheduled calls for RemoveAvailableFile on Lookup().
  typedef std::string RemoveAvailableFileCall;
  std::map<int, std::vector<RemoveAvailableFileCall>>
      remove_available_file_calls_;
};

}  // namespace client

}  // namespace p2p

#endif  // P2P_CLIENT_FAKE_SERVICE_FINDER_H_
