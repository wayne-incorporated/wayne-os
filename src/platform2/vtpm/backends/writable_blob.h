// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_BACKENDS_WRITABLE_BLOB_H_
#define VTPM_BACKENDS_WRITABLE_BLOB_H_

#include "vtpm/backends/blob.h"

#include <string>

#include <trunks/tpm_generated.h>

namespace vtpm {

// `WritableBlob` extends `Blob` to enable writing data.
class WritableBlob : public Blob {
 public:
  virtual ~WritableBlob() = default;

  // Write that data for later use. Usually the what `WritableBlob::Write()`
  // stores is the return value of `Blob::Get()`.
  // Note that the term `Write() used for parity with `Get()` is unusual, for
  // an implementation of `Get()`' could also implies the change to the state.
  // For example, lazy evaluation of a certain TPM operation is also possible.
  // Thus, `Read()` is not better than `Get()`. Meanwhile, `Write()` is better
  // than `Set()` because, depending on its implementation, the implication of
  // persisting data is usually the case in this project.
  virtual trunks::TPM_RC Write(const std::string& blob) = 0;
};

}  // namespace vtpm

#endif  // VTPM_BACKENDS_WRITABLE_BLOB_H_
