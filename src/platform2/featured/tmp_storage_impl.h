// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FEATURED_TMP_STORAGE_IMPL_H_
#define FEATURED_TMP_STORAGE_IMPL_H_

#include "featured/feature_export.h"
#include "featured/tmp_storage_interface.h"

namespace featured {

class FEATURE_EXPORT TmpStorageImpl : public TmpStorageInterface {
 public:
  TmpStorageImpl() = default;
  TmpStorageImpl(const TmpStorageImpl&) = delete;
  TmpStorageImpl& operator=(const TmpStorageImpl&) = delete;
  ~TmpStorageImpl() override = default;

  void SetUsedSeedDetails(const SeedDetails& seed_details) override;
  SeedDetails GetUsedSeedDetails() override;
};

}  // namespace featured

#endif  // FEATURED_TMP_STORAGE_IMPL_H_
