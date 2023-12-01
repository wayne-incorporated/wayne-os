// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/mojom/external/time_mojom_data_generators.h"

namespace diagnostics {

base::Time BaseTimeGenerator::Generate() {
  has_next_ = false;
  return base::Time::UnixEpoch();
}

base::TimeDelta BaseTimeDeltaGenerator::Generate() {
  has_next_ = false;
  return base::Seconds(1);
}

}  // namespace diagnostics
