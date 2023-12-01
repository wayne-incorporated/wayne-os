// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_BACKENDS_MOCK_WRITABLE_BLOB_H_
#define VTPM_BACKENDS_MOCK_WRITABLE_BLOB_H_

#include "vtpm/backends/writable_blob.h"

#include <string>

#include <gmock/gmock.h>
#include <trunks/tpm_generated.h>

namespace vtpm {

class MockWritableBlob : public WritableBlob {
 public:
  virtual ~MockWritableBlob() = default;

  MOCK_METHOD(trunks::TPM_RC, Get, (std::string&), (override));

  MOCK_METHOD(trunks::TPM_RC, Write, (const std::string&), (override));
};

}  // namespace vtpm

#endif  // VTPM_BACKENDS_MOCK_WRITABLE_BLOB_H_
