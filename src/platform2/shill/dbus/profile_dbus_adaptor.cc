// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/profile_dbus_adaptor.h"

#include "shill/error.h"
#include "shill/logging.h"
#include "shill/profile.h"
#include "shill/service.h"

#include <base/logging.h>

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kDBus;
static std::string ObjectID(const ProfileDBusAdaptor* p) {
  return p->GetRpcIdentifier().value();
}
}  // namespace Logging

// static
const char ProfileDBusAdaptor::kPath[] = "/profile/";

ProfileDBusAdaptor::ProfileDBusAdaptor(const scoped_refptr<dbus::Bus>& bus,
                                       Profile* profile)
    : org::chromium::flimflam::ProfileAdaptor(this),
      DBusAdaptor(bus, kPath + profile->GetFriendlyName()),
      profile_(profile) {
  // Register DBus object.
  RegisterWithDBusObject(dbus_object());
  dbus_object()->RegisterAndBlock();
}

ProfileDBusAdaptor::~ProfileDBusAdaptor() {
  dbus_object()->UnregisterAndBlock();
  profile_ = nullptr;
}

void ProfileDBusAdaptor::EmitBoolChanged(const std::string& name, bool value) {
  SLOG(this, 2) << __func__ << ": " << name;
  SendPropertyChangedSignal(name, brillo::Any(value));
}

void ProfileDBusAdaptor::EmitUintChanged(const std::string& name,
                                         uint32_t value) {
  SLOG(this, 2) << __func__ << ": " << name;
  SendPropertyChangedSignal(name, brillo::Any(value));
}

void ProfileDBusAdaptor::EmitIntChanged(const std::string& name, int value) {
  SLOG(this, 2) << __func__ << ": " << name;
  SendPropertyChangedSignal(name, brillo::Any(value));
}

void ProfileDBusAdaptor::EmitStringChanged(const std::string& name,
                                           const std::string& value) {
  SLOG(this, 2) << __func__ << ": " << name;
  SendPropertyChangedSignal(name, brillo::Any(value));
}

bool ProfileDBusAdaptor::GetProperties(brillo::ErrorPtr* error,
                                       brillo::VariantDictionary* properties) {
  SLOG(this, 2) << __func__;
  return DBusAdaptor::GetProperties(profile_->store(), properties, error);
}

bool ProfileDBusAdaptor::SetProperty(brillo::ErrorPtr* error,
                                     const std::string& name,
                                     const brillo::Any& value) {
  SLOG(this, 2) << __func__ << ": " << name;
  return DBusAdaptor::SetProperty(profile_->mutable_store(), name, value,
                                  error);
}

bool ProfileDBusAdaptor::GetEntry(brillo::ErrorPtr* error,
                                  const std::string& name,
                                  brillo::VariantDictionary* entry_properties) {
  SLOG(this, 2) << __func__ << ": " << name;
  Error e;
  ServiceRefPtr service = profile_->GetServiceFromEntry(name, &e);
  if (!e.IsSuccess()) {
    return !e.ToChromeosError(error);
  }
  return DBusAdaptor::GetProperties(service->store(), entry_properties, error);
}

bool ProfileDBusAdaptor::DeleteEntry(brillo::ErrorPtr* error,
                                     const std::string& name) {
  SLOG(this, 2) << __func__ << ": " << name;
  Error e;
  profile_->DeleteEntry(name, &e);
  return !e.ToChromeosError(error);
}

}  // namespace shill
