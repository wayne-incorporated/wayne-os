// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_SYSTEM_POWER_MANAGER_CLIENT_H_
#define RMAD_SYSTEM_POWER_MANAGER_CLIENT_H_

namespace rmad {

class PowerManagerClient {
 public:
  PowerManagerClient() = default;
  virtual ~PowerManagerClient() = default;

  virtual bool Restart() = 0;
  virtual bool Shutdown() = 0;
};

}  // namespace rmad

#endif  // RMAD_SYSTEM_POWER_MANAGER_CLIENT_H_
