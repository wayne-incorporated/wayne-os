// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HPS_DAEMON_FILTERS_STATUS_CALLBACK_H_
#define HPS_DAEMON_FILTERS_STATUS_CALLBACK_H_

#include <vector>
#include "base/functional/callback.h"

namespace hps {

// This callback is invoked whenever a filter changes state.
using StatusCallback = base::RepeatingCallback<void(HpsResult)>;

}  // namespace hps

#endif  // HPS_DAEMON_FILTERS_STATUS_CALLBACK_H_
