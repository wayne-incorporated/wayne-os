// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_CELLULAR_ERROR_H_
#define SHILL_CELLULAR_CELLULAR_ERROR_H_

#include <brillo/errors/error.h>

#include "shill/error.h"

namespace shill {

class CellularError {
 public:
  CellularError(const CellularError&) = delete;
  CellularError& operator=(const CellularError&) = delete;
  static void FromMM1ChromeosDBusError(brillo::Error* dbus_error, Error* error);
};

}  // namespace shill

#endif  // SHILL_CELLULAR_CELLULAR_ERROR_H_
