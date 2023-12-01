// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_SYSTEM_SHILL_CLIENT_H_
#define RMAD_SYSTEM_SHILL_CLIENT_H_

namespace rmad {

class ShillClient {
 public:
  ShillClient() = default;
  virtual ~ShillClient() = default;

  virtual bool DisableCellular() const = 0;
};

}  // namespace rmad

#endif  // RMAD_SYSTEM_SHILL_CLIENT_H_
