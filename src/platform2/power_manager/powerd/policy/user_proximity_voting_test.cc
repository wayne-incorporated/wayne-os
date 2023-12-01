// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/policy/user_proximity_voting.h"

#include <gtest/gtest.h>

namespace power_manager::policy {

TEST(UserProximityVotingTest, DefaultStates) {
  bool prefer_far = false;
  UserProximityVoting voting(prefer_far);
  EXPECT_EQ(voting.GetVote(), UserProximity::UNKNOWN);

  EXPECT_TRUE(voting.Vote(1, UserProximity::NEAR));
  EXPECT_EQ(voting.GetVote(), UserProximity::NEAR);
}

TEST(UserProximityVotingTest, DefaultStatesPreferFar) {
  bool prefer_far = true;
  UserProximityVoting voting(prefer_far);
  EXPECT_EQ(voting.GetVote(), UserProximity::UNKNOWN);

  EXPECT_TRUE(voting.Vote(1, UserProximity::NEAR));
  EXPECT_EQ(voting.GetVote(), UserProximity::NEAR);
}

TEST(UserProximityVotingTest, StateChange) {
  bool prefer_far = false;
  UserProximityVoting voting(prefer_far);
  EXPECT_TRUE(voting.Vote(1, UserProximity::NEAR));

  EXPECT_TRUE(voting.Vote(1, UserProximity::FAR));
  EXPECT_EQ(voting.GetVote(), UserProximity::FAR);

  EXPECT_FALSE(voting.Vote(1, UserProximity::FAR));

  EXPECT_TRUE(voting.Vote(1, UserProximity::NEAR));
  EXPECT_EQ(voting.GetVote(), UserProximity::NEAR);
}

TEST(UserProximityVotingTest, StateChangePreferFar) {
  bool prefer_far = true;
  UserProximityVoting voting(prefer_far);
  EXPECT_TRUE(voting.Vote(1, UserProximity::NEAR));

  EXPECT_TRUE(voting.Vote(1, UserProximity::FAR));
  EXPECT_EQ(voting.GetVote(), UserProximity::FAR);

  EXPECT_FALSE(voting.Vote(1, UserProximity::FAR));

  EXPECT_TRUE(voting.Vote(1, UserProximity::NEAR));
  EXPECT_EQ(voting.GetVote(), UserProximity::NEAR);
}

TEST(UserProximityVotingTest, ConsensusChange) {
  bool prefer_far = false;
  UserProximityVoting voting(prefer_far);
  EXPECT_TRUE(voting.Vote(1, UserProximity::NEAR));
  EXPECT_FALSE(voting.Vote(2, UserProximity::NEAR));

  EXPECT_FALSE(voting.Vote(1, UserProximity::FAR));
  EXPECT_EQ(voting.GetVote(), UserProximity::NEAR);

  EXPECT_TRUE(voting.Vote(2, UserProximity::FAR));
  EXPECT_EQ(voting.GetVote(), UserProximity::FAR);

  EXPECT_FALSE(voting.Vote(1, UserProximity::FAR));
  EXPECT_EQ(voting.GetVote(), UserProximity::FAR);

  EXPECT_TRUE(voting.Vote(2, UserProximity::NEAR));
  EXPECT_EQ(voting.GetVote(), UserProximity::NEAR);
}

TEST(UserProximityVotingTest, ConsensusChangePreferFar) {
  bool prefer_far = true;
  UserProximityVoting voting(prefer_far);
  EXPECT_TRUE(voting.Vote(1, UserProximity::NEAR));
  EXPECT_FALSE(voting.Vote(2, UserProximity::NEAR));
  EXPECT_EQ(voting.GetVote(), UserProximity::NEAR);

  EXPECT_TRUE(voting.Vote(1, UserProximity::FAR));
  EXPECT_EQ(voting.GetVote(), UserProximity::FAR);

  EXPECT_FALSE(voting.Vote(2, UserProximity::FAR));
  EXPECT_EQ(voting.GetVote(), UserProximity::FAR);

  EXPECT_FALSE(voting.Vote(2, UserProximity::NEAR));
  EXPECT_EQ(voting.GetVote(), UserProximity::FAR);
}

}  // namespace power_manager::policy
