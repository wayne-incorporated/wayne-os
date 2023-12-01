// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_BACKENDS_FAKE_BLOB_H_
#define VTPM_BACKENDS_FAKE_BLOB_H_

#include "vtpm/backends/mock_blob.h"

#include <string>

#include <gmock/gmock.h>

namespace vtpm {

// A fake implementation that always returns a constant string defined during
// construction time.
class FakeBlob : public MockBlob {
 public:
  // Constructs an instance w/ `blob as the retruend data for `Get()`.
  explicit FakeBlob(const std::string& blob) : blob_(blob) {
    using ::testing::_;
    using ::testing::DoAll;
    using ::testing::Return;
    using ::testing::SetArgReferee;
    ON_CALL(*this, Get(_))
        .WillByDefault(
            DoAll(SetArgReferee<0>(blob_), Return(trunks::TPM_RC_SUCCESS)));
  }
  ~FakeBlob() override = default;

 private:
  const std::string blob_;
};

}  // namespace vtpm

#endif  // VTPM_BACKENDS_FAKE_BLOB_H_
