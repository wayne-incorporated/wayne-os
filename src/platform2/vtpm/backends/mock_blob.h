// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_BACKENDS_MOCK_BLOB_H_
#define VTPM_BACKENDS_MOCK_BLOB_H_

#include "vtpm/backends/blob.h"

#include <string>

#include <gmock/gmock.h>

namespace vtpm {

class MockBlob : public Blob {
 public:
  virtual ~MockBlob() = default;

  MOCK_METHOD(trunks::TPM_RC, Get, (std::string&), (override));
};

}  // namespace vtpm

#endif  // VTPM_BACKENDS_MOCK_BLOB_H_
