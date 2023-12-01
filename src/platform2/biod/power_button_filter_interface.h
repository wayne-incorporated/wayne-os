// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_POWER_BUTTON_FILTER_INTERFACE_H_
#define BIOD_POWER_BUTTON_FILTER_INTERFACE_H_

namespace biod {

class PowerButtonFilterInterface {
 public:
  PowerButtonFilterInterface() = default;
  PowerButtonFilterInterface(const PowerButtonFilterInterface&) = delete;
  PowerButtonFilterInterface& operator=(const PowerButtonFilterInterface&) =
      delete;

  virtual ~PowerButtonFilterInterface() = default;

  // Returns true if a power Button event is seen in the last
  // |kAuthIgnoreTimeoutmsecs| and if we have not filtered a match after latest
  // power button press.
  virtual bool ShouldFilterFingerprintMatch() = 0;
};

}  // namespace biod

#endif  // BIOD_POWER_BUTTON_FILTER_INTERFACE_H_
