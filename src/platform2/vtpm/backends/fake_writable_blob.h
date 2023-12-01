// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_BACKENDS_FAKE_WRITABLE_BLOB_H_
#define VTPM_BACKENDS_FAKE_WRITABLE_BLOB_H_

#include "vtpm/backends/mock_writable_blob.h"

#include <functional>
#include <string>

#include <gmock/gmock.h>

#include <trunks/tpm_generated.h>

namespace vtpm {

// A fake implementation of `WritableBlob` that initially holds empty data.
// When `Write` is called the data is stored in memory and `Get()` will return
// the stored value afterwards.
class FakeWritableBlob : public MockWritableBlob {
 public:
  FakeWritableBlob() {
    using ::testing::_;
    using ::testing::DoAll;
    using ::testing::Return;
    using ::testing::SaveArg;
    using ::testing::SetArgReferee;
    ON_CALL(*this, Get(_))
        .WillByDefault(DoAll(SetArgReferee<0>(std::cref(blob_)),
                             Return(trunks::TPM_RC_SUCCESS)));
    ON_CALL(*this, Write(_))
        .WillByDefault(
            DoAll(SaveArg<0>(&blob_), Return(trunks::TPM_RC_SUCCESS)));
  }
  ~FakeWritableBlob() override = default;

 private:
  // The cached data.
  std::string blob_;
};

}  // namespace vtpm

#endif  // VTPM_BACKENDS_FAKE_WRITABLE_BLOB_H_
