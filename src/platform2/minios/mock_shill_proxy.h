// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_MOCK_SHILL_PROXY_H_
#define MINIOS_MOCK_SHILL_PROXY_H_

#include <string>

#include <gmock/gmock.h>

#include "minios/shill_proxy_interface.h"

namespace minios {

class MockShillProxy : public ShillProxyInterface {
 public:
  MockShillProxy() = default;

  MockShillProxy(const MockShillProxy&) = delete;
  MockShillProxy& operator=(const MockShillProxy&) = delete;

  MOCK_METHOD(void,
              ManagerRequestScan,
              (const std::string& technology,
               OnManagerRequestScanSuccess success_callback,
               OnManagerRequestScanError error_callback),
              (override));

  MOCK_METHOD(void,
              ManagerGetProperties,
              (OnManagerGetPropertiesSuccess success_callback,
               OnManagerGetPropertiesError error_callback),
              (override));

  MOCK_METHOD(void,
              ManagerFindMatchingService,
              (const brillo::VariantDictionary& dict,
               OnManagerFindMatchingServiceSuccess success_callback,
               OnManagerFindMatchingServiceError error_callback),
              (override));

  MOCK_METHOD(void,
              ServiceGetProperties,
              (const dbus::ObjectPath& service_path,
               OnServiceGetPropertiesSuccess success_callback,
               OnServiceGetPropertiesError error_callback),
              (override));

  MOCK_METHOD(void,
              ServiceSetProperties,
              (const dbus::ObjectPath& service_path,
               const brillo::VariantDictionary& dict,
               OnServiceSetPropertiesSuccess success_callback,
               OnServiceSetPropertiesError error_callback),
              (override));

  MOCK_METHOD(void,
              ServiceConnect,
              (const dbus::ObjectPath& service_path,
               OnServiceConnectSuccess success_callback,
               OnServiceConnectError error_callback),
              (override));
};

}  // namespace minios

#endif  // MINIOS_MOCK_SHILL_PROXY_H_
