// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FEATURED_TMP_STORAGE_INTERFACE_H_
#define FEATURED_TMP_STORAGE_INTERFACE_H_

#include <featured/proto_bindings/featured.pb.h>

namespace featured {

class TmpStorageInterface {
 public:
  virtual ~TmpStorageInterface() = default;
  // TODO(b/273341565): Add more methods, as needed.
  // Store and retrieve the seed details for the seed that featured evaluated
  // to determine experiment state.
  virtual void SetUsedSeedDetails(const SeedDetails& seed_details) = 0;
  virtual SeedDetails GetUsedSeedDetails() = 0;
};

}  // namespace featured

#endif  // FEATURED_TMP_STORAGE_INTERFACE_H_
