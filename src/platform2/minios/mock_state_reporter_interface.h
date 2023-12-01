// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_MOCK_STATE_REPORTER_INTERFACE_H_
#define MINIOS_MOCK_STATE_REPORTER_INTERFACE_H_

#include <string>

#include <brillo/errors/error.h>
#include <gmock/gmock.h>
#include <minios/proto_bindings/minios.pb.h>

#include "minios/state_reporter_interface.h"

namespace minios {

class MockStateReporterInterface : public StateReporterInterface {
 public:
  MockStateReporterInterface() = default;
  ~MockStateReporterInterface() = default;

  MockStateReporterInterface(const MockStateReporterInterface&) = delete;
  MockStateReporterInterface& operator=(const MockStateReporterInterface&) =
      delete;

  MOCK_METHOD(void, StateChanged, (const State& state), (override));
};

}  // namespace minios

#endif  // MINIOS_MOCK_STATE_REPORTER_INTERFACE_H_
