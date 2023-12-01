// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_DBUS_DBUS_PROXY_UTIL_H_
#define LIBBRILLO_BRILLO_DBUS_DBUS_PROXY_UTIL_H_

#include <memory>
#include <string>
#include <tuple>
#include <utility>

#include <brillo/brillo_export.h>
#include <dbus/bus.h>
#include <dbus/exported_object.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>

namespace brillo {
namespace dbus_utils {

// This function calls a dbus method, and gets the response synchronously. It
// can be called from any thread, including the origin thread and dbus thread.
BRILLO_EXPORT std::unique_ptr<dbus::Response> CallDBusMethod(
    scoped_refptr<dbus::Bus> bus,
    dbus::ObjectProxy* proxy,
    dbus::MethodCall* method_call,
    int timeout_ms);

BRILLO_EXPORT std::unique_ptr<dbus::Response> CallDBusMethodWithErrorResponse(
    scoped_refptr<dbus::Bus> bus,
    dbus::ObjectProxy* proxy,
    dbus::MethodCall* method_call,
    int timeout_ms,
    dbus::ScopedDBusError* error);

}  // namespace dbus_utils
}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_DBUS_DBUS_PROXY_UTIL_H_
