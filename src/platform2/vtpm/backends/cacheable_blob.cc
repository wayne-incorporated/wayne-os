// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
#include "vtpm/backends/cacheable_blob.h"

#include <string>

#include <trunks/tpm_generated.h>

namespace vtpm {

CacheableBlob::CacheableBlob(Blob* blob, WritableBlob* cache)
    : blob_(blob), cache_(cache) {
  CHECK(blob_);
  CHECK(cache_);
}

trunks::TPM_RC CacheableBlob::Get(std::string& blob) {
  trunks::TPM_RC rc = cache_->Get(blob);
  if (rc) {
    return rc;
  }

  // If it's empty, consider the cache is invalidated.
  if (!blob.empty()) {
    return trunks::TPM_RC_SUCCESS;
  }
  rc = blob_->Get(blob);
  if (rc) {
    return rc;
  }

  // A failed write is a failure. fort `blob_` could return the different result
  // every single time, and `cache_` is supposed to be the single source of
  // truth once `blob_` gives a valid output.
  return cache_->Write(blob);
}

}  // namespace vtpm
