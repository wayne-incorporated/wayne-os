// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_CLIENT_MOCK_DM_TOKEN_RETRIEVER_H_
#define MISSIVE_CLIENT_MOCK_DM_TOKEN_RETRIEVER_H_

#include <cstddef>
#include <string>

#include <gmock/gmock.h>

#include "missive/client/dm_token_retriever.h"
#include "missive/util/statusor.h"

namespace reporting {

// A mock |DMTokenRetriever| that stubs out functionality that retrieves the
// DM token for testing purposes.
class MockDMTokenRetriever : public DMTokenRetriever {
 public:
  MockDMTokenRetriever();
  MockDMTokenRetriever(const MockDMTokenRetriever&) = delete;
  MockDMTokenRetriever& operator=(const MockDMTokenRetriever&) = delete;
  ~MockDMTokenRetriever() override;

  // Ensures by mocking that RetrieveDMToken is expected to be triggered a
  // specific number of times and runs the completion callback with the
  // specified result on trigger.
  void ExpectRetrieveDMTokenAndReturnResult(
      size_t times, StatusOr<std::string> dm_token_result);

  // Mocked stub that retrieves the DM token and triggers the specified callback
  MOCK_METHOD(void,
              RetrieveDMToken,
              (DMTokenRetriever::CompletionCallback completion_cb),
              (override));
};

}  // namespace reporting

#endif  // MISSIVE_CLIENT_MOCK_DM_TOKEN_RETRIEVER_H_
