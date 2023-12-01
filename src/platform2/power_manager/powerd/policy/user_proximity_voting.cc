// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/policy/user_proximity_voting.h"

#include <base/check_op.h>
#include <base/logging.h>

namespace power_manager::policy {

UserProximityVoting::UserProximityVoting(bool prefer_far)
    : prefer_far_(prefer_far) {}

UserProximityVoting::~UserProximityVoting() = default;

bool UserProximityVoting::Vote(int id, UserProximity vote) {
  DCHECK_NE(vote, UserProximity::UNKNOWN);

  auto pos = votes_.find(id);
  if (pos == votes_.end()) {
    votes_.emplace(id, vote);
  } else if (pos->second != vote) {
    pos->second = vote;
  } else {
    // This voter already exists, and its vote is not changing,
    // so no need to write any state or recalculate anything.
    return false;
  }

  auto new_consensus = CalculateVote();
  if (consensus_ == new_consensus)
    return false;

  consensus_ = new_consensus;
  return true;
}

UserProximity UserProximityVoting::GetVote() const {
  return consensus_;
}

UserProximity UserProximityVoting::CalculateVote() const {
  UserProximity vote_type =
      prefer_far_ ? UserProximity::FAR : UserProximity::NEAR;

  if (votes_.empty())
    return UserProximity::UNKNOWN;

  for (const auto& vote : votes_) {
    if (vote.second == vote_type)
      return vote_type;
  }

  return prefer_far_ ? UserProximity::NEAR : UserProximity::FAR;
}

}  // namespace power_manager::policy
