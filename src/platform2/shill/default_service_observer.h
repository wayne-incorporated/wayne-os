// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DEFAULT_SERVICE_OBSERVER_H_
#define SHILL_DEFAULT_SERVICE_OBSERVER_H_

#include "shill/refptr_types.h"

#include <base/observer_list_types.h>

namespace shill {

// Interface for Observer of default logical and physical service changes. When
// both of the default services changed, OnDefaultLogicalServiceChanged will
// be triggered at first. Registered and unregistered using
// Manager::{Add,Remove}DefaultServiceObserver.
class DefaultServiceObserver : public base::CheckedObserver {
 public:
  virtual ~DefaultServiceObserver() = default;

  // For the default logical service, "changed" means one of the following
  // events: 1) another logical service becomes the default, 2) the connected
  // state of the default logical service (i.e., whether this service is
  // associated with a Connection object) has changed, or 3) the above two
  // events happen at the same time.
  virtual void OnDefaultLogicalServiceChanged(
      const ServiceRefPtr& logical_service) = 0;

  // For the default physical service, "changed" means one of the following
  // events: 1) another physical service becomes the default, 2) the online
  // state of the default physical service has changed, or 3) the above two
  // events happen at the same time.
  virtual void OnDefaultPhysicalServiceChanged(
      const ServiceRefPtr& physical_service) = 0;
};

}  // namespace shill

#endif  // SHILL_DEFAULT_SERVICE_OBSERVER_H_
