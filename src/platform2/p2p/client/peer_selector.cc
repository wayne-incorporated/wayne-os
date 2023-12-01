// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "p2p/client/peer_selector.h"

#include <algorithm>
#include <map>
#include <vector>

#include <base/command_line.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/rand_util.h>

#include "p2p/client/peer.h"
#include "p2p/common/clock_interface.h"
#include "p2p/common/constants.h"

using std::map;
using std::string;
using std::vector;

namespace p2p {

namespace client {

PeerSelector::PeerSelector(ServiceFinder* finder,
                           p2p::common::ClockInterface* clock)
    : finder_(finder),
      clock_(clock),
      lookup_result_(kNumLookupResults),
      candidate_files_count_(-1),
      victim_connections_(-1),
      num_total_peers_(-1),
      url_waiting_time_sec_(-1),
      must_exit_now_(false) {}

// Type used for std::sort()
struct SortPeerBySize {
  explicit SortPeerBySize(const std::string& id) : id_(id) {}

  bool operator()(const Peer* a, const Peer* b) {
    map<string, size_t>::const_iterator iter_a = a->files.find(id_);
    map<string, size_t>::const_iterator iter_b = b->files.find(id_);
    if (iter_a == a->files.end())
      return false;
    // Put all the peers without the id_ file at the end of the ordering.
    if (iter_b == b->files.end())
      return true;

    return iter_a->second > iter_b->second;
  }

  string id_;
};

string PeerSelector::PickUrlForId(const string& id, size_t minimum_size) {
  vector<const Peer*> peers = finder_->GetPeersForFile(id);

  // Set an invalid victim_connections_ value in order to catch logic errors
  // during test.
  victim_connections_ = -1;

  // Compute the candidate_files_count_ for metrics purposes.
  candidate_files_count_ = 0;
  for (auto const& peer : peers) {
    map<string, size_t>::const_iterator file_size_it = peer->files.find(id);
    if (file_size_it != peer->files.end() && file_size_it->second > 0)
      candidate_files_count_++;
  }

  if (!candidate_files_count_)
    return "";

  // Sort according to size (largest file size first)
  std::sort(peers.begin(), peers.end(), SortPeerBySize(id));

  // Don't consider peers with file size lower than minimum_size.
  int big_enough_files = 0;
  for (auto const& peer : peers) {
    map<string, size_t>::const_iterator file_size_it = peer->files.find(id);
    if (file_size_it != peer->files.end() &&
        file_size_it->second >= minimum_size)
      big_enough_files++;
  }
  peers.resize(big_enough_files);

  // Return "" if no peer has a big enough file.
  if (!big_enough_files)
    return "";

  // If we have any files left, pick randomly from the top 33%
  int victim_number = 0;
  int num_possible_victims = peers.size() / 3 - 1;
  if (num_possible_victims > 1)
    victim_number = base::RandInt(0, num_possible_victims - 1);
  const Peer* victim = peers[victim_number];
  // Record the number of current connection the victim has.
  victim_connections_ = victim->num_connections;

  string address = victim->address;
  if (victim->is_ipv6)
    address = "[" + address + "]";
  return string("http://") + address + ":" + std::to_string(victim->port) +
         "/" + id;
}

string PeerSelector::GetUrlAndWait(const string& id, size_t minimum_size) {
  LOG(INFO) << "Requesting URL in the LAN for ID " << id
            << " (minimum_size=" << minimum_size << ")";

  // Set the current state to an invalid condition in order to detect logic
  // errors during test.
  lookup_result_ = kNumLookupResults;

  base::Time init_time = clock_->GetMonotonicTime();

  string url;
  int num_retries = 0;

  do {
    if (!finder_->Lookup()) {
      lookup_result_ = kFiltered;
      break;
    }
    num_total_peers_ = finder_->NumTotalPeers();
    // Check if a signal was received during the lookup.
    if (must_exit_now_)
      break;

    url = PickUrlForId(id, minimum_size);

    // If we didn't find a peer, fail.
    if (url.size() == 0) {
      LOG(INFO) << "Returning error - no peer for the given ID.";
      lookup_result_ = num_retries ? kVanished : kNotFound;
      break;
    }

    // Only return the peer if the number of connections in the LAN
    // is below the threshold.
    int num_total_conn = finder_->NumTotalConnections();
    if (num_total_conn < constants::kMaxSimultaneousDownloads) {
      LOG(INFO) << "Returning URL " << url << " after " << num_retries
                << " retries.";
      lookup_result_ = kFound;
      break;
    }

    LOG(INFO) << "Found peer for the given ID but there are already "
              << num_total_conn << " download(s) in the LAN which exceeds "
              << "the threshold of " << constants::kMaxSimultaneousDownloads
              << " download(s). "
              << "Sleeping "
              << constants::kMaxSimultaneousDownloadsPollTimeSeconds
              << " seconds until retrying.";

    clock_->Sleep(
        base::Seconds(constants::kMaxSimultaneousDownloadsPollTimeSeconds));

    // Now that we've slept for a while, the URL may not be valid
    // anymore, so we do the lookup again.
    num_retries++;
  } while (!must_exit_now_);

  if (must_exit_now_) {
    LOG(INFO) << "Abort was requested.";
    lookup_result_ = kCanceled;
    url = "";
  }

  url_waiting_time_sec_ = (clock_->GetMonotonicTime() - init_time).InSeconds();
  return url;
}

void PeerSelector::Abort() {
  // Allow several calls to this function.
  if (must_exit_now_)
    return;
  must_exit_now_ = true;

  // Signal the termination on the ServiceFinder because we could be blocked
  // in Lookup().
  finder_->Abort();
}

string PeerSelector::ToString(LookupResult lookup_result) {
  switch (lookup_result) {
    case kFound:
      return "Found";
    case kNotFound:
      return "NotFound";
    case kVanished:
      return "Vanished";
    case kCanceled:
      return "Canceled";
    case kFiltered:
      return "Filtered";

    // Don't add a default case to let the compiler warn about newly added
    // lookup results which should be added here.
    case kNumLookupResults:
      return "Unknown";
  }
  return "Unknown";
}

bool PeerSelector::ReportMetrics(MetricsLibraryInterface* metrics_lib) {
  string metric;
  int value;

  if (lookup_result_ == kNumLookupResults) {
    LOG(ERROR) << "Invalid LookupResult from the previous GetUrlAndWait() "
               << "call. Was it ever called?";
    return false;
  }

  // Report the last lookup_result.
  metric = "P2P.Client.LookupResult";
  metrics_lib->SendEnumToUMA(metric, lookup_result_, kNumLookupResults);
  LOG(INFO) << "Uploading " << ToString(lookup_result_) << " for metric "
            << metric;

  if (lookup_result_ != kFiltered && lookup_result_ != kCanceled) {
    // Report the number of peers implementing p2p file sharing on the network.
    // This metric is only reported if the mDNS service is not filtered.
    metric = "P2P.Client.NumPeers";
    value = num_total_peers_;
    LOG(INFO) << "Uploading " << value << " (count) for metric " << metric;
    metrics_lib->SendToUMA(metric, value, 1 /* min */, 1000 /* max */, 100);
  }

  if (lookup_result_ == kFound) {
    // Report
    metric = "P2P.Client.Found.WaitingTimeSeconds";
    value = url_waiting_time_sec_;
    LOG(INFO) << "Uploading " << value << " (count) for metric " << metric;
    metrics_lib->SendToUMA(metric, value, 0 /* min */, 86400 /* max */, 100);

    metric = "P2P.Client.Found.ConnectionCount";
    value = victim_connections_;
    LOG(INFO) << "Uploading " << value << " (count) for metric " << metric;
    metrics_lib->SendToUMA(metric, value, 0 /* min */, 50 /* max */, 50);

    metric = "P2P.Client.Found.CandidateCount";
    value = candidate_files_count_;
    LOG(INFO) << "Uploading " << value << " (count) for metric " << metric;
    metrics_lib->SendToUMA(metric, value, 1 /* min */, 50 /* max */, 50);
  }

  if (lookup_result_ == kVanished) {
    // Report the wall-clock time spent waiting for a resource that vanished.
    // Reported only if a URL for the requested resource vanished while
    // waiting for it.
    metric = "P2P.Client.Vanished.WaitingTimeSeconds";
    value = url_waiting_time_sec_;
    LOG(INFO) << "Uploading " << value << " (count) for metric " << metric;
    metrics_lib->SendToUMA(metric, value, 0 /* min */, 86400 /* max */, 100);
  }

  if (lookup_result_ == kCanceled) {
    // Report the wall-clock time spent until a lookup was cancelled.
    metric = "P2P.Client.Canceled.WaitingTimeSeconds";
    value = url_waiting_time_sec_;
    LOG(INFO) << "Uploading " << value << " (count) for metric " << metric;
    metrics_lib->SendToUMA(metric, value, 0 /* min */, 86400 /* max */, 100);
  }

  return true;
}

}  // namespace client

}  // namespace p2p
