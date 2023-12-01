// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_EPHEMERAL_PROFILE_H_
#define SHILL_EPHEMERAL_PROFILE_H_

#include <string>

#include "shill/profile.h"
#include "shill/refptr_types.h"

namespace shill {

class Manager;

// An in-memory profile that is not persisted to disk, but allows the
// promotion of entries contained herein to the currently active profile.
class EphemeralProfile : public Profile {
 public:
  explicit EphemeralProfile(Manager* manager);
  EphemeralProfile(const EphemeralProfile&) = delete;
  EphemeralProfile& operator=(const EphemeralProfile&) = delete;

  ~EphemeralProfile() override;

  std::string GetFriendlyName() const override;
  bool AdoptService(const ServiceRefPtr& service) override;
  bool AbandonService(const ServiceRefPtr& service) override;

  // Should not be called.
  bool Save() override;
};

}  // namespace shill

#endif  // SHILL_EPHEMERAL_PROFILE_H_
