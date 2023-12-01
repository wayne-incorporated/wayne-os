// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_POLICY_USER_PROXIMITY_VOTING_H_
#define POWER_MANAGER_POWERD_POLICY_USER_PROXIMITY_VOTING_H_

#include "power_manager/common/power_constants.h"

#include <unordered_map>

namespace power_manager::policy {

// Aggregates votes from one or more sensors about the user's physical
// proximity to the device.
class UserProximityVoting {
 public:
  explicit UserProximityVoting(bool prefer_far);
  UserProximityVoting(const UserProximityVoting&) = delete;
  UserProximityVoting& operator=(const UserProximityVoting&) = delete;

  ~UserProximityVoting();

  // Sets the vote of sensor |id| to |vote|. The sensor is added
  // to the voting pool if no previous vote for |id| was registered.
  // Returns true if the consensus changes due to |vote|.
  bool Vote(int id, UserProximity vote);

  // Returns the current consensus among all the sensors in this voting pool.
  // If |prefer_far_| is false, then NEAR is returned if at least one sensor is
  // claiming proximity, otherwise FAR is returned. If |prefer_far_| is true,
  // then NEAR is returned when all sensors claim proximity, otherwise FAR is
  // returned. If there are no sensors, then UNKNOWN is returned.
  UserProximity GetVote() const;

 private:
  UserProximity CalculateVote() const;

  std::unordered_map<int, UserProximity> votes_;
  UserProximity consensus_ = UserProximity::UNKNOWN;
  bool prefer_far_ = false;
};

}  // namespace power_manager::policy

#endif  //  POWER_MANAGER_POWERD_POLICY_USER_PROXIMITY_VOTING_H_
