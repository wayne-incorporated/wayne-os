// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_STATE_REPORTER_INTERFACE_H_
#define MINIOS_STATE_REPORTER_INTERFACE_H_

#include <minios/proto_bindings/minios.pb.h>

namespace minios {

class StateReporterInterface {
 public:
  virtual ~StateReporterInterface() = default;

  // Is called whenever minios state changes.
  virtual void StateChanged(const State& state) = 0;

 protected:
  StateReporterInterface() = default;

 private:
  StateReporterInterface(const StateReporterInterface&) = delete;
  StateReporterInterface& operator=(const StateReporterInterface&) = delete;
};

}  // namespace minios

#endif  // MINIOS_STATE_REPORTER_INTERFACE_H_
