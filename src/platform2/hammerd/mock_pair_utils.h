// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HAMMERD_MOCK_PAIR_UTILS_H_
#define HAMMERD_MOCK_PAIR_UTILS_H_

#include <gmock/gmock.h>

#include "hammerd/pair_utils.h"

namespace hammerd {

// Mock internal method GenerateChallenge() to test PairManager itself.
class MockPairManager : public PairManager {
 public:
  MockPairManager() = default;

  MOCK_METHOD(void,
              GenerateChallenge,
              (PairChallengeRequest*, uint8_t*),
              (override));
};

// Mock public method PairChallenge() used to inject into HammerUpdater.
class MockPairManagerInterface : public PairManagerInterface {
 public:
  MockPairManagerInterface() = default;

  MOCK_METHOD(ChallengeStatus,
              PairChallenge,
              (FirmwareUpdaterInterface*, DBusWrapperInterface*),
              (override));
};

}  // namespace hammerd
#endif  // HAMMERD_MOCK_PAIR_UTILS_H_
