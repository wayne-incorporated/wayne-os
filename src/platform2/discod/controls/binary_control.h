// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DISCOD_CONTROLS_BINARY_CONTROL_H_
#define DISCOD_CONTROLS_BINARY_CONTROL_H_

#include "discod/utils/libhwsec_status_import.h"

namespace discod {

class BinaryControl {
 public:
  enum class State {
    kOff,
    kOn,
  };

  BinaryControl() = default;
  virtual ~BinaryControl() = default;

  // XXX status or
  virtual Status Toggle(State state) = 0;
  virtual StatusOr<State> Current() const = 0;
};

}  // namespace discod

#endif  // DISCOD_CONTROLS_BINARY_CONTROL_H_
