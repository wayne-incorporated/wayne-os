// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_SHILL_PROXY_INTERFACE_H_
#define MINIOS_SHILL_PROXY_INTERFACE_H_

#include <string>

#include <base/functional/callback.h>
#include <brillo/errors/error.h>
#include <brillo/variant_dictionary.h>

namespace minios {

class ShillProxyInterface {
 public:
  virtual ~ShillProxyInterface() = default;

  using OnManagerRequestScanSuccess = base::RepeatingCallback<void()>;
  using OnManagerRequestScanError =
      base::RepeatingCallback<void(brillo::Error*)>;
  virtual void ManagerRequestScan(const std::string& technology,
                                  OnManagerRequestScanSuccess success_callback,
                                  OnManagerRequestScanError error_callback) = 0;

  using OnManagerGetPropertiesSuccess =
      base::RepeatingCallback<void(const brillo::VariantDictionary&)>;
  using OnManagerGetPropertiesError =
      base::RepeatingCallback<void(brillo::Error*)>;
  virtual void ManagerGetProperties(
      OnManagerGetPropertiesSuccess success_callback,
      OnManagerGetPropertiesError error_callback) = 0;

  using OnManagerFindMatchingServiceSuccess =
      base::RepeatingCallback<void(const dbus::ObjectPath&)>;
  using OnManagerFindMatchingServiceError =
      base::RepeatingCallback<void(brillo::Error*)>;
  virtual void ManagerFindMatchingService(
      const brillo::VariantDictionary& dict,
      OnManagerFindMatchingServiceSuccess success_callback,
      OnManagerFindMatchingServiceError error_callback) = 0;

  using OnServiceGetPropertiesSuccess =
      base::RepeatingCallback<void(const brillo::VariantDictionary&)>;
  using OnServiceGetPropertiesError =
      base::RepeatingCallback<void(brillo::Error*)>;
  virtual void ServiceGetProperties(
      const dbus::ObjectPath& service_path,
      OnServiceGetPropertiesSuccess success_callback,
      OnServiceGetPropertiesError error_callback) = 0;

  using OnServiceSetPropertiesSuccess = base::RepeatingCallback<void()>;
  using OnServiceSetPropertiesError =
      base::RepeatingCallback<void(brillo::Error*)>;
  virtual void ServiceSetProperties(
      const dbus::ObjectPath& service_path,
      const brillo::VariantDictionary& dict,
      OnServiceSetPropertiesSuccess success_callback,
      OnServiceSetPropertiesError error_callback) = 0;

  using OnServiceConnectSuccess = base::RepeatingCallback<void()>;
  using OnServiceConnectError = base::RepeatingCallback<void(brillo::Error*)>;
  virtual void ServiceConnect(const dbus::ObjectPath& service_path,
                              OnServiceConnectSuccess success_callback,
                              OnServiceConnectError error_callback) = 0;
};

}  // namespace minios

#endif  // MINIOS_SHILL_PROXY_INTERFACE_H__
