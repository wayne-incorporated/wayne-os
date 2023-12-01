// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TYPECD_CHROME_FEATURES_SERVICE_CLIENT_H_
#define TYPECD_CHROME_FEATURES_SERVICE_CLIENT_H_

#include <string>

#include <base/memory/weak_ptr.h>
#include <dbus/bus.h>
#include <dbus/object_proxy.h>

namespace typecd {

// Helper to call chrome features dbus service.
class ChromeFeaturesServiceClient {
 public:
  explicit ChromeFeaturesServiceClient(scoped_refptr<dbus::Bus> bus);
  ChromeFeaturesServiceClient(const ChromeFeaturesServiceClient&) = delete;
  ChromeFeaturesServiceClient& operator=(const ChromeFeaturesServiceClient&) =
      delete;

  ~ChromeFeaturesServiceClient() = default;

  // Retrieve the Peripheral Data Access setting state from Chrome.
  void FetchPeripheralDataAccessEnabled();

  bool GetPeripheralDataAccessEnabled() { return peripheral_data_access_en_; }
  void SetPeripheralDataAccessEnabled(bool enabled);

 private:
  // Denotes whether the Data Access Protection for peripherals is disabled or
  // not.
  bool peripheral_data_access_en_;
  dbus::ObjectProxy* proxy_;

  base::WeakPtrFactory<ChromeFeaturesServiceClient> weak_ptr_factory_{this};
};

}  // namespace typecd

#endif  // TYPECD_CHROME_FEATURES_SERVICE_CLIENT_H_
