// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_BACKENDS_BLOB_H_
#define VTPM_BACKENDS_BLOB_H_

#include <string>

#include <trunks/tpm_generated.h>

namespace vtpm {

// A generic interface that gets a implementatin-defined data represented in a
// sequence of bytes.
class Blob {
 public:
  virtual ~Blob() = default;

  // Gets data of definition is implementation-defined.
  virtual trunks::TPM_RC Get(std::string& blob) = 0;
};

}  // namespace vtpm

#endif  // VTPM_BACKENDS_BLOB_H_
