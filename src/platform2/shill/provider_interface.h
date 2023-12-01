// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_PROVIDER_INTERFACE_H_
#define SHILL_PROVIDER_INTERFACE_H_

#include <string>

#include "shill/refptr_types.h"

namespace shill {

class Error;
class KeyValueStore;

// This is an interface for objects that creates and manages service objects.
class ProviderInterface {
 public:
  virtual ~ProviderInterface() = default;

  // Creates services from the entries within |profile|.
  virtual void CreateServicesFromProfile(const ProfileRefPtr& profile) = 0;

  // Finds a Service with similar properties to |args|.  The criteria
  // used are specific to the provider subclass.  Returns a reference
  // to a matching service if one exists.  Otherwise it returns a NULL
  // reference and populates |error|.
  virtual ServiceRefPtr FindSimilarService(const KeyValueStore& args,
                                           Error* error) const = 0;

  // Retrieves (see FindSimilarService) or creates a service with the
  // unique attributes in |args|.  The remaining attributes will be
  // populated (by Manager) via a later call to Service::Configure().
  // Returns a NULL reference and populates |error| on failure.
  virtual ServiceRefPtr GetService(const KeyValueStore& args, Error* error) = 0;

  // Creates a temporary service with the identifying properties populated
  // from |args|.  Callers outside of the Provider must never register
  // this service with the Manager or connect it since it was never added
  // to the provider's service list.
  virtual ServiceRefPtr CreateTemporaryService(const KeyValueStore& args,
                                               Error* error) = 0;

  // Create a temporary service for an entry |entry_name| within |profile|.
  // Callers outside of the Provider must never register this service with the
  // Manager or connect it since it was never added to the provider's service
  // list.
  virtual ServiceRefPtr CreateTemporaryServiceFromProfile(
      const ProfileRefPtr& profile,
      const std::string& entry_name,
      Error* error) = 0;

  // Starts the provider.
  virtual void Start() = 0;

  // Stops the provider (will de-register all services).
  virtual void Stop() = 0;
};

}  // namespace shill

#endif  // SHILL_PROVIDER_INTERFACE_H_
