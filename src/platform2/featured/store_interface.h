// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FEATURED_STORE_INTERFACE_H_
#define FEATURED_STORE_INTERFACE_H_

#include <string>
#include <vector>

#include <featured/proto_bindings/featured.pb.h>

namespace featured {

class StoreInterface {
 public:
  virtual ~StoreInterface() = default;
  virtual uint32_t GetBootAttemptsSinceLastUpdate() = 0;
  virtual bool IncrementBootAttemptsSinceLastUpdate() = 0;
  virtual bool ClearBootAttemptsSinceLastUpdate() = 0;
  virtual SeedDetails GetLastGoodSeed() = 0;
  virtual bool SetLastGoodSeed(const SeedDetails& seed) = 0;
  virtual std::vector<FeatureOverride> GetOverrides() = 0;
  virtual void AddOverride(const featured::FeatureOverride& override) = 0;
  virtual void RemoveOverrideFor(const std::string& name) = 0;
};
}  // namespace featured

#endif  // FEATURED_STORE_INTERFACE_H_
