// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_PROFILE_DBUS_ADAPTOR_H_
#define SHILL_DBUS_PROFILE_DBUS_ADAPTOR_H_

#include <string>

#include "dbus_bindings/org.chromium.flimflam.Profile.h"
#include "shill/adaptor_interfaces.h"
#include "shill/dbus/dbus_adaptor.h"

namespace shill {

class Profile;

// Subclass of DBusAdaptor for Profile objects
// There is a 1:1 mapping between Profile and ProfileDBusAdaptor
// instances.  Furthermore, the Profile owns the ProfileDBusAdaptor
// and manages its lifetime, so we're OK with ProfileDBusAdaptor
// having a bare pointer to its owner profile.
//
// A Profile is a collection of Entry structures (which we will define later).
class ProfileDBusAdaptor : public org::chromium::flimflam::ProfileAdaptor,
                           public org::chromium::flimflam::ProfileInterface,
                           public DBusAdaptor,
                           public ProfileAdaptorInterface {
 public:
  static const char kPath[];

  ProfileDBusAdaptor(const scoped_refptr<dbus::Bus>& bus, Profile* profile);
  ProfileDBusAdaptor(const ProfileDBusAdaptor&) = delete;
  ProfileDBusAdaptor& operator=(const ProfileDBusAdaptor&) = delete;

  ~ProfileDBusAdaptor() override;

  // Implementation of ProfileAdaptorInterface.
  const RpcIdentifier& GetRpcIdentifier() const override { return dbus_path(); }
  void EmitBoolChanged(const std::string& name, bool value) override;
  void EmitUintChanged(const std::string& name, uint32_t value) override;
  void EmitIntChanged(const std::string& name, int value) override;
  void EmitStringChanged(const std::string& name,
                         const std::string& value) override;

  // Implementation of ProfileAdaptor
  bool GetProperties(brillo::ErrorPtr* error,
                     brillo::VariantDictionary* properties) override;
  bool SetProperty(brillo::ErrorPtr* error,
                   const std::string& name,
                   const brillo::Any& value) override;

  // Gets an "Entry", which is apparently a different set of properties than
  // those returned by GetProperties.
  bool GetEntry(brillo::ErrorPtr* error,
                const std::string& name,
                brillo::VariantDictionary* entry_properties) override;

  // Deletes an Entry.
  bool DeleteEntry(brillo::ErrorPtr* error, const std::string& name) override;

 private:
  Profile* profile_;
};

}  // namespace shill

#endif  // SHILL_DBUS_PROFILE_DBUS_ADAPTOR_H_
