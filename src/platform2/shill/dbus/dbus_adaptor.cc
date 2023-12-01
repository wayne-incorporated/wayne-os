// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/dbus_adaptor.h"

#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/logging.h>

#include "shill/error.h"
#include "shill/logging.h"
#include "shill/store/property_store.h"

using brillo::dbus_utils::DBusObject;

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kDBus;
static std::string ObjectID(const DBusAdaptor* d) {
  if (d == nullptr)
    return "(dbus_adaptor)";
  return d->dbus_path().value();
}
}  // namespace Logging

// public static
const char DBusAdaptor::kNullPath[] = "/";

DBusAdaptor::DBusAdaptor(const scoped_refptr<dbus::Bus>& bus,
                         const std::string& object_path)
    : dbus_path_(object_path),
      dbus_object_(new DBusObject(nullptr, bus, dbus_path_)) {
  SLOG(this, 2) << "DBusAdaptor: " << object_path;
}

DBusAdaptor::~DBusAdaptor() = default;

// static
bool DBusAdaptor::SetProperty(PropertyStore* store,
                              const std::string& name,
                              const brillo::Any& value,
                              brillo::ErrorPtr* error) {
  Error e;
  store->SetAnyProperty(name, value, &e);
  return !e.ToChromeosError(error);
}

// static
bool DBusAdaptor::GetProperties(const PropertyStore& store,
                                brillo::VariantDictionary* out_properties,
                                brillo::ErrorPtr* error) {
  Error e;
  store.GetProperties(out_properties, &e);
  return !e.ToChromeosError(error);
}

// static
bool DBusAdaptor::ClearProperty(PropertyStore* store,
                                const std::string& name,
                                brillo::ErrorPtr* error) {
  Error e;
  store->ClearProperty(name, &e);
  return !e.ToChromeosError(error);
}

// static
std::string DBusAdaptor::SanitizePathElement(const std::string& object_path) {
  std::string sanitized_path(object_path);

  for (auto& c : sanitized_path) {
    // The D-Bus specification
    // (http://dbus.freedesktop.org/doc/dbus-specification.html) states:
    // Each element must only contain the ASCII characters "[A-Z][a-z][0-9]_"
    if (!(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z') &&
        !(c >= '0' && c <= '9') && c != '_') {
      c = '_';
    }
  }

  return sanitized_path;
}

ResultCallback DBusAdaptor::GetMethodReplyCallback(
    DBusMethodResponsePtr<> response) {
  return base::BindOnce(&DBusAdaptor::MethodReplyCallback,
                        weak_factory_.GetWeakPtr(), std::move(response));
}

void DBusAdaptor::MethodReplyCallback(DBusMethodResponsePtr<> response,
                                      const Error& error) {
  brillo::ErrorPtr chromeos_error;
  if (error.ToChromeosError(&chromeos_error)) {
    response->ReplyWithError(chromeos_error.get());
  } else {
    response->Return();
  }
}

}  // namespace shill
