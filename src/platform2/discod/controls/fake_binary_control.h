// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DISCOD_CONTROLS_FAKE_BINARY_CONTROL_H_
#define DISCOD_CONTROLS_FAKE_BINARY_CONTROL_H_

#include <string>
#include <utility>

#include "discod/controls/binary_control.h"
#include "discod/utils/libhwsec_status_import.h"

namespace discod {

class FakeBinaryControl : public BinaryControl {
 public:
  FakeBinaryControl() : BinaryControl() {}
  ~FakeBinaryControl() override = default;

  void InjectError(const std::string& error) { error_ = error; }

  Status Toggle(BinaryControl::State value) override {
    if (error_) {
      std::string error = error_.value();
      error_ = std::nullopt;
      return MakeStatus(error);
    }
    value_ = value;
    return OkStatus();
  }

  StatusOr<BinaryControl::State> Current() const override {
    if (error_) {
      std::string error = error_.value();
      error_ = std::nullopt;
      return MakeStatus(error);
    }
    return value_;
  }

 private:
  BinaryControl::State value_ = BinaryControl::State::kOn;
  mutable std::optional<std::string> error_;
};

}  // namespace discod

#endif  // DISCOD_CONTROLS_FAKE_BINARY_CONTROL_H_
