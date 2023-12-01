// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_FUZZERS_BLOB_MUTATOR_H_
#define LIBHWSEC_FOUNDATION_FUZZERS_BLOB_MUTATOR_H_

#include <brillo/secure_blob.h>

#include "libhwsec-foundation/hwsec-foundation_export.h"

class FuzzedDataProvider;

namespace hwsec_foundation {

// Returns the mutated version of the provided |input_blob|.
// The following mutations are applied:
// * Removing chunk(s) from the input blob;
// * Inserting "random" bytes into the input blob.
// The size of the resulting blob is guaranteed to be within
// [min_length; max_length].
brillo::Blob HWSEC_FOUNDATION_EXPORT
MutateBlob(const brillo::Blob& input_blob,
           int min_length,
           int max_length,
           FuzzedDataProvider* fuzzed_data_provider);

}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_FUZZERS_BLOB_MUTATOR_H_
