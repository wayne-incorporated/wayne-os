// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_DBUS_UTILS_H_
#define RMAD_UTILS_DBUS_UTILS_H_

#include <base/memory/scoped_refptr.h>
#include <dbus/bus.h>

namespace rmad {

scoped_refptr<dbus::Bus> GetSystemBus();

}  // namespace rmad

#endif  // RMAD_UTILS_DBUS_UTILS_H_
