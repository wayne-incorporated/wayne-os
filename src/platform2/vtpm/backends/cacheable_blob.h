// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_BACKENDS_CACHEABLE_BLOB_H_
#define VTPM_BACKENDS_CACHEABLE_BLOB_H_

#include "vtpm/backends/blob.h"

#include <string>

#include "vtpm/backends/writable_blob.h"

namespace vtpm {

// This class caches the interesting blob in the cache and returns the value
// directly from the cache.
// This class doesn't define the way the data is cached,or the way the
// interesting data is generated/retrieved. Instead, the definitions are
// injected.
class CacheableBlob : public Blob {
 public:
  // Constructs an instance w/ `blob`, which defines what the data is and how
  // the data is generated, and `cache`, which defines where the data from
  // `blob` is memorized, and how the data is cached.
  CacheableBlob(Blob* blob, WritableBlob* cache);
  virtual ~CacheableBlob() = default;

  trunks::TPM_RC Get(std::string& blob) override;

 private:
  // Definition of the blob returned by `this`.
  Blob* const blob_;
  // Implementation of caching logic.
  WritableBlob* const cache_;
};

}  // namespace vtpm

#endif  // VTPM_BACKENDS_CACHEABLE_BLOB_H_
