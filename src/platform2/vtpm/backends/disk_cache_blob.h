// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_BACKENDS_DISK_CACHE_BLOB_H_
#define VTPM_BACKENDS_DISK_CACHE_BLOB_H_

#include "vtpm/backends/writable_blob.h"

#include <string>

#include <base/files/file_path.h>
#include <trunks/tpm_generated.h>

namespace vtpm {

// It is a `WritableCache` that uses a file as its storage.
class DiskCacheBlob : public WritableBlob {
 public:
  explicit DiskCacheBlob(const base::FilePath& path);
  virtual ~DiskCacheBlob() = default;

  // Blob overrides.
  trunks::TPM_RC Get(std::string& blob) override;

  // WritableBlob overrides.
  trunks::TPM_RC Write(const std::string& blob) override;

 private:
  const base::FilePath path_;
};

}  // namespace vtpm

#endif  // VTPM_BACKENDS_DISK_CACHE_BLOB_H_
