// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P2P_CLIENT_PEER_SELECTOR_H_
#define P2P_CLIENT_PEER_SELECTOR_H_

#include "p2p/client/service_finder.h"

#include <stdint.h>

#include <string>

#include <gtest/gtest_prod.h>  // for FRIEND_TEST
#include <metrics/metrics_library.h>

#include "p2p/common/clock.h"

namespace p2p {

namespace client {

// Interface for finding local peers willing to serve files.
class PeerSelector {
 public:
  // Constructs the PeerSelector with the provided interfaces.
  PeerSelector(ServiceFinder* finder, p2p::common::ClockInterface* clock);
  PeerSelector(const PeerSelector&) = delete;
  PeerSelector& operator=(const PeerSelector&) = delete;

  // Finds an URL for the file |id| with at least |minimum_size| bytes and
  // waits until the number of connections in the LAN has dropped below the
  // required threshold. If there are no peers sharing this file with at least
  // |minimum_size| bytes returns "" regardless of the number of connections in
  // the LAN. On success, returns the URL found.
  std::string GetUrlAndWait(const std::string& id, size_t minimum_size);

  // Reports the following metrics based on the last call to GetUrlAndWait():
  //  * P2P.Client.LookupResult
  //  * P2P.Client.NumPeers
  //  * P2P.Client.Found.WaitingTimeSeconds
  //  * P2P.Client.Found.ConnectionCount
  //  * P2P.Client.Found.CandidateCount
  //  * P2P.Client.Vanished.WaitingTimeSeconds
  //  * P2P.Client.Canceled.WaitingTimeSeconds
  // If there is an error reporting the metrics false is returned. Otherwise,
  // returns true.
  bool ReportMetrics(MetricsLibraryInterface* metrics_lib);

  // Abort() cancels any ongoing and future call to GetUrlAndWait() making it
  // return an empty string as soon as possible. This function is
  // Async-Signal-Safe and can be called several times.
  void Abort();

 private:
  friend class PeerSelectorTest;
  FRIEND_TEST(PeerSelectorTest, PickUrlForNonExistantId);
  FRIEND_TEST(PeerSelectorTest, PickUrlForIdWithZeroBytes);
  FRIEND_TEST(PeerSelectorTest, PickUrlForIdWithMinimumSize);
  FRIEND_TEST(PeerSelectorTest, PickUrlFromTheFirstThird);
  FRIEND_TEST(PeerSelectorTest, GetUrlAndWaitWhenThePeerGoesAway);
  FRIEND_TEST(PeerSelectorTest, GetUrlDoesntWaitForSmallFiles);
  FRIEND_TEST(PeerSelectorTest, ReportMetricsOnFilteredNetwork);
  FRIEND_TEST(PeerSelectorTest, ReportMetricsWhenFound);
  FRIEND_TEST(PeerSelectorTest, ReportMetricsWhenCanceled);

  // file |id| with at least |minimum_size| bytes. If no peer is found meeting
  // those conditions, an empty string is returned. Otherwise, the URL of the
  // provided file is returned.
  std::string PickUrlForId(const std::string& id, size_t minimum_size);

  // The underlying service finder class used.
  ServiceFinder* finder_;

  // An interface to the system clock functions, used for unit testing.
  p2p::common::ClockInterface* clock_;

  enum LookupResult {
    kFound,     // The resource was found.
    kNotFound,  // The resource was not found.
    kVanished,  // The resource was found but vanished while waiting in line.
    kCanceled,  // The request was canceled with Abort().
    kFiltered,  // It was detected that mDNS was filtered.

    // Note: Add new lookup results only above this line.
    kNumLookupResults
  };
  static std::string ToString(LookupResult lookup_result);

  // The result of the last GetUrlAndWait() call.
  LookupResult lookup_result_;

  // Candidate files counter used for report metrics.
  int candidate_files_count_;

  // The number of connections of the peer picked by PickUrlForId().
  int victim_connections_;

  // The total number of peers in the network implementing P2P at the last
  // ServiceFinder::Lookup() made by GetUrlAndWait().
  int num_total_peers_;

  // The elapsed time it took GetUrlAndWait() to return in seconds.
  int64_t url_waiting_time_sec_;

  // A flag used to signal the request was canceled.
  volatile bool must_exit_now_;
};

}  // namespace client

}  // namespace p2p

#endif  // P2P_CLIENT_PEER_SELECTOR_H_
