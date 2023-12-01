// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/mock_blob_parser.h"

#include <gmock/gmock.h>

using testing::_;
using testing::Return;

namespace trunks {

MockBlobParser::MockBlobParser() {
  ON_CALL(*this, SerializeKeyBlob(_, _, _)).WillByDefault(Return(true));
  ON_CALL(*this, ParseKeyBlob(_, _, _)).WillByDefault(Return(true));
  ON_CALL(*this, SerializeCreationBlob(_, _, _, _)).WillByDefault(Return(true));
  ON_CALL(*this, ParseCreationBlob(_, _, _, _)).WillByDefault(Return(true));
}

MockBlobParser::~MockBlobParser() {}

}  // namespace trunks
