// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLCSERVICE_MOCK_STATE_CHANGE_REPORTER_H_
#define DLCSERVICE_MOCK_STATE_CHANGE_REPORTER_H_

#include "dlcservice/state_change_reporter_interface.h"

namespace dlcservice {

class MockStateChangeReporter : public StateChangeReporterInterface {
 public:
  MockStateChangeReporter() = default;

  MOCK_METHOD(void, DlcStateChanged, (const DlcState& dlc_state), (override));

 private:
  MockStateChangeReporter(const MockStateChangeReporter&) = delete;
  MockStateChangeReporter& operator=(const MockStateChangeReporter&) = delete;
};

}  // namespace dlcservice

#endif  // DLCSERVICE_MOCK_STATE_CHANGE_REPORTER_H_
