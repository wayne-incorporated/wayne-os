
// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "p2p/client/peer_selector.h"

#include <string>

#include <base/functional/bind.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <metrics/metrics_library_mock.h>

#include "p2p/client/fake_service_finder.h"
#include "p2p/common/fake_clock.h"
#include "p2p/common/testutil.h"

using testing::_;

namespace p2p {

namespace client {

class PeerSelectorTest : public ::testing::Test {
 public:
  PeerSelectorTest() : ps_(&sf_, &clock_) {}

 protected:
  p2p::common::FakeClock clock_;
  FakeServiceFinder sf_;
  PeerSelector ps_;  // The PeerSelector under test.
  testing::StrictMock<MetricsLibraryMock> mock_metrics_lib_;
};

TEST_F(PeerSelectorTest, PickUrlForNonExistantId) {
  EXPECT_EQ(ps_.PickUrlForId("non-existant", 1), "");

  // Share some *other* files on the network.
  int peer = sf_.NewPeer("10.0.0.1", false, 1111);
  ASSERT_TRUE(sf_.PeerShareFile(peer, "some-file", 10240));
  ASSERT_TRUE(sf_.PeerShareFile(peer, "other-file", 10240));
  EXPECT_EQ(ps_.PickUrlForId("non-existant", 1), "");

  // PickUrlForId should not call Lookup().
  EXPECT_EQ(sf_.GetNumLookupCalls(), 0);
}

TEST_F(PeerSelectorTest, PickUrlForIdWithZeroBytes) {
  int peer1 = sf_.NewPeer("10.0.0.1", false, 1111);
  int peer2 = sf_.NewPeer("10.0.0.2", false, 2222);
  ASSERT_TRUE(sf_.PeerShareFile(peer1, "some-file", 0));
  ASSERT_TRUE(sf_.PeerShareFile(peer2, "some-file", 0));
  // PickUrlForId() should not return an URL for a peer sharing a 0-bytes file.
  EXPECT_EQ(ps_.PickUrlForId("some-file", 1), "");
}

TEST_F(PeerSelectorTest, PickUrlForIdWithMinimumSize) {
  int peer = sf_.NewPeer("10.0.0.1", false, 1111);
  ASSERT_TRUE(sf_.PeerShareFile(peer, "some-file", 999));

  // The file is too small.
  EXPECT_EQ(ps_.PickUrlForId("some-file", 1000), "");

  // The file is exactly the right size.
  EXPECT_EQ(ps_.PickUrlForId("some-file", 999),
            "http://10.0.0.1:1111/some-file");
}

TEST_F(PeerSelectorTest, PickUrlFromTheFirstThird) {
  int peer1 = sf_.NewPeer("2001:db8:85a3:0:0:8a2e:370:7334", true, 1111);
  int peer2 = sf_.NewPeer("10.0.0.2", false, 2222);
  int peer3 = sf_.NewPeer("10.0.0.3", false, 3333);
  int peer4 = sf_.NewPeer("10.0.0.4", false, 4444);
  ASSERT_TRUE(sf_.PeerShareFile(peer1, "some-file", 1000));
  ASSERT_TRUE(sf_.PeerShareFile(peer2, "some-file", 500));
  ASSERT_TRUE(sf_.PeerShareFile(peer3, "some-file", 300));
  ASSERT_TRUE(sf_.PeerShareFile(peer4, "some-file", 0));
  EXPECT_EQ(ps_.PickUrlForId("some-file", 1),
            "http://[2001:db8:85a3:0:0:8a2e:370:7334]:1111/some-file");
}

TEST_F(PeerSelectorTest, GetUrlAndWaitWithNoPeers) {
  EXPECT_EQ(ps_.GetUrlAndWait("some-file", 1), "");

  // GetUrlAndWait() should call Lookup() once, since doesn't need to wait.
  EXPECT_EQ(sf_.GetNumLookupCalls(), 1);
}

TEST_F(PeerSelectorTest, GetUrlAndWaitWithUnknownFile) {
  int peer1 = sf_.NewPeer("10.0.0.1", false, 1111);
  int peer2 = sf_.NewPeer("10.0.0.2", false, 2222);
  ASSERT_TRUE(sf_.PeerShareFile(peer1, "some-file", 1000));
  ASSERT_TRUE(sf_.PeerShareFile(peer2, "some-file", 500));

  EXPECT_EQ(ps_.GetUrlAndWait("unknown-file", 1), "");

  // GetUrlAndWait() should call Lookup() once, since doesn't need to wait.
  EXPECT_EQ(sf_.GetNumLookupCalls(), 1);
}

TEST_F(PeerSelectorTest, GetUrlAndWaitOnBusyNetwork) {
  // This test checks that GetUrlAndWait() doesn't return an URL for a file if
  // there are already too many connections on the network. The current limit is
  // set to 3. Update this test if you itentionally changed that value.
  const int max_connections = 3;

  int peer1 = sf_.NewPeer("10.0.0.1", false, 1111);
  int peer2 = sf_.NewPeer("10.0.0.2", false, 2222);
  ASSERT_TRUE(sf_.PeerShareFile(peer1, "some-file", 1000));
  ASSERT_TRUE(sf_.PeerShareFile(peer2, "some-file", 500));
  ASSERT_TRUE(sf_.SetPeerConnections(peer1, max_connections));
  ASSERT_TRUE(sf_.SetPeerConnections(peer2, max_connections - 1));

  // After 2 Lookup() calls, the network is not as busy (|max_connections|
  // connections), but still not enough.
  ASSERT_TRUE(sf_.SetPeerConnectionsOnLookup(2, peer2, 0));

  // After 4 Lookup() calls, the network reaches the limit to allow the
  // download.
  ASSERT_TRUE(sf_.SetPeerConnectionsOnLookup(4, peer1, max_connections - 1));

  // Make the test finish if more than 10 Lookup()'s are made.
  ASSERT_TRUE(sf_.RemoveAvailableFileOnLookup(10, "some-file"));

  // GetUrlAndWait should return the biggest file in this case.
  EXPECT_EQ(ps_.GetUrlAndWait("some-file", 1),
            "http://10.0.0.1:1111/some-file");

  EXPECT_EQ(sf_.GetNumLookupCalls(), 4);
  EXPECT_EQ(clock_.GetSleptTime(), base::Seconds(3 * 30));
}

TEST_F(PeerSelectorTest, GetUrlAndWaitWhenThePeerGoesAway) {
  int peer1 = sf_.NewPeer("10.0.0.1", false, 1111);
  int peer2 = sf_.NewPeer("10.0.0.2", false, 2222);
  ASSERT_TRUE(sf_.PeerShareFile(peer1, "some-file", 1000));
  ASSERT_TRUE(sf_.PeerShareFile(peer2, "some-file", 500));
  ASSERT_TRUE(sf_.PeerShareFile(peer2, "other-file", 500));
  // A super-busy network.
  ASSERT_TRUE(sf_.SetPeerConnections(peer2, 999));

  // After 3 Lookup()'s, peer2 lost the file.
  ASSERT_TRUE(sf_.RemoveAvailableFileOnLookup(3, "some-file"));
  ASSERT_TRUE(sf_.PeerShareFileOnLookup(3, peer1, "some-file", 1000));

  // After 5 Lookup()'s, network is still busy, but the file is not present
  // anymore.
  ASSERT_TRUE(sf_.RemoveAvailableFileOnLookup(5, "some-file"));

  // To ensure test completion (with failure) remove any other file after 10
  // Lookup()'s.
  ASSERT_TRUE(sf_.SetPeerConnectionsOnLookup(10, peer2, 0));
  ASSERT_TRUE(sf_.RemoveAvailableFileOnLookup(10, "other-file"));

  EXPECT_EQ(ps_.GetUrlAndWait("some-file", 1), "");

  EXPECT_EQ(sf_.GetNumLookupCalls(), 5);
  EXPECT_EQ(clock_.GetSleptTime(), base::Seconds(4 * 30));

  // Check the metrics. The Lookup should be kVanished.
  EXPECT_CALL(mock_metrics_lib_,
              SendEnumToUMA("P2P.Client.LookupResult", PeerSelector::kVanished,
                            PeerSelector::kNumLookupResults));
  EXPECT_CALL(mock_metrics_lib_, SendToUMA("P2P.Client.NumPeers", 2, _, _, _));
  EXPECT_CALL(
      mock_metrics_lib_,
      SendToUMA("P2P.Client.Vanished.WaitingTimeSeconds", 4 * 30, _, _, _));

  EXPECT_TRUE(ps_.ReportMetrics(&mock_metrics_lib_));
}

TEST_F(PeerSelectorTest, GetUrlDoesntWaitForSmallFiles) {
  int peer = sf_.NewPeer("10.0.0.1", false, 1111);
  ASSERT_TRUE(sf_.PeerShareFile(peer, "some-file", 500));

  // After 3 Lookup()'s, peer has a bigger file, but GetUrlAndWait() shouldn't
  // wait for it.
  ASSERT_TRUE(sf_.RemoveAvailableFileOnLookup(3, "some-file"));
  ASSERT_TRUE(sf_.PeerShareFileOnLookup(3, peer, "some-file", 2000));

  EXPECT_EQ(ps_.GetUrlAndWait("some-file", 1000), "");

  EXPECT_EQ(sf_.GetNumLookupCalls(), 1);
  EXPECT_EQ(clock_.GetSleptTime(), base::Seconds(0));

  // Check the metrics. The Lookup should be kVanished.
  EXPECT_CALL(mock_metrics_lib_,
              SendEnumToUMA("P2P.Client.LookupResult", PeerSelector::kNotFound,
                            PeerSelector::kNumLookupResults));
  EXPECT_CALL(mock_metrics_lib_, SendToUMA("P2P.Client.NumPeers", 1, _, _, _));

  EXPECT_TRUE(ps_.ReportMetrics(&mock_metrics_lib_));
}

TEST_F(PeerSelectorTest, ReportMetricsFailsWhenNoLookup) {
  // This is to ensure that the check for calling ReportMetrics without calling
  // GetUrlAndWait() before works.
  EXPECT_FALSE(ps_.ReportMetrics(&mock_metrics_lib_));
}

TEST_F(PeerSelectorTest, ReportMetricsOnFilteredNetwork) {
  sf_.SetServiceFiltered(true);

  EXPECT_EQ(ps_.GetUrlAndWait("some-file", 1000), "");

  EXPECT_CALL(mock_metrics_lib_, SendEnumToUMA("P2P.Client.LookupResult",
                                               PeerSelector::kFiltered, _));

  EXPECT_TRUE(ps_.ReportMetrics(&mock_metrics_lib_));
}

TEST_F(PeerSelectorTest, ReportMetricsWhenFound) {
  int peer1 = sf_.NewPeer("10.0.0.1", false, 1111);
  int peer2 = sf_.NewPeer("10.0.0.2", false, 2222);
  int peer3 = sf_.NewPeer("10.0.0.3", false, 3333);
  int peer4 = sf_.NewPeer("10.0.0.4", false, 4444);
  ASSERT_TRUE(sf_.PeerShareFile(peer1, "some-file", 2000));
  ASSERT_TRUE(sf_.PeerShareFile(peer2, "some-file", 500));
  ASSERT_TRUE(sf_.PeerShareFile(peer3, "other-file", 500));
  ASSERT_TRUE(sf_.PeerShareFile(peer4, "some-file", 0));
  ASSERT_TRUE(sf_.SetPeerConnections(peer1, 1));

  EXPECT_EQ(ps_.GetUrlAndWait("some-file", 1),
            "http://10.0.0.1:1111/some-file");

  EXPECT_EQ(sf_.GetNumLookupCalls(), 1);

  // Check the metrics.
  EXPECT_CALL(mock_metrics_lib_,
              SendEnumToUMA("P2P.Client.LookupResult", PeerSelector::kFound,
                            PeerSelector::kNumLookupResults));
  EXPECT_CALL(mock_metrics_lib_, SendToUMA("P2P.Client.NumPeers", 4, _, _, _));
  EXPECT_CALL(mock_metrics_lib_,
              SendToUMA("P2P.Client.Found.ConnectionCount", 1, _, _, _));
  // Only two peers are sharing a non-empty file.
  EXPECT_CALL(mock_metrics_lib_,
              SendToUMA("P2P.Client.Found.CandidateCount", 2, _, _, _));
  EXPECT_CALL(mock_metrics_lib_,
              SendToUMA("P2P.Client.Found.WaitingTimeSeconds", 0, _, _, _));

  EXPECT_TRUE(ps_.ReportMetrics(&mock_metrics_lib_));
}

TEST_F(PeerSelectorTest, ReportMetricsWhenCanceled) {
  // Technically speaking, the call to Abort should be made *while*
  // GetUrlAndWait() is running, but we could also call it right before.
  ps_.Abort();
  EXPECT_EQ(ps_.GetUrlAndWait("some-file", 1), "");

  EXPECT_EQ(sf_.GetNumLookupCalls(), 1);

  // Check the metrics.
  EXPECT_CALL(mock_metrics_lib_,
              SendEnumToUMA("P2P.Client.LookupResult", PeerSelector::kCanceled,
                            PeerSelector::kNumLookupResults));
  EXPECT_CALL(mock_metrics_lib_,
              SendToUMA("P2P.Client.Canceled.WaitingTimeSeconds", 0, _, _, _));

  EXPECT_TRUE(ps_.ReportMetrics(&mock_metrics_lib_));
}

}  // namespace client

}  // namespace p2p
