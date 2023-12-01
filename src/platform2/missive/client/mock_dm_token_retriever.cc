// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/client/mock_dm_token_retriever.h"

#include <string>
#include <utility>

#include <gmock/gmock.h>

#include "missive/client/dm_token_retriever.h"
#include "missive/util/statusor.h"

using ::testing::_;

namespace reporting {

MockDMTokenRetriever::MockDMTokenRetriever() = default;

MockDMTokenRetriever::~MockDMTokenRetriever() = default;

void MockDMTokenRetriever::ExpectRetrieveDMTokenAndReturnResult(
    size_t times, StatusOr<std::string> dm_token_result) {
  EXPECT_CALL(*this, RetrieveDMToken(_))
      .Times(times)
      .WillRepeatedly([&dm_token_result](
                          DMTokenRetriever::CompletionCallback completion_cb) {
        std::move(completion_cb).Run(std::move(dm_token_result));
      })
      .RetiresOnSaturation();
}

}  // namespace reporting
