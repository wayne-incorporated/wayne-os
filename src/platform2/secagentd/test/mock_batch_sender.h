// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SECAGENTD_TEST_MOCK_BATCH_SENDER_H_
#define SECAGENTD_TEST_MOCK_BATCH_SENDER_H_

#include <memory>

#include "gmock/gmock.h"  // IWYU pragma: keep
#include "missive/proto/record_constants.pb.h"
#include "secagentd/batch_sender.h"
#include "secagentd/proto/security_xdr_events.pb.h"

namespace secagentd::testing {

template <typename KeyType, typename XdrMessage, typename AtomicVariantMessage>
class MockBatchSender
    : public BatchSenderInterface<KeyType, XdrMessage, AtomicVariantMessage> {
 public:
  using VisitCallback =
      typename BatchSenderInterface<KeyType, XdrMessage, AtomicVariantMessage>::
          VisitCallback;
  MOCK_METHOD(void, Start, (), (override));
  MOCK_METHOD(void,
              Enqueue,
              (std::unique_ptr<AtomicVariantMessage>),
              (override));
  MOCK_METHOD(bool,
              Visit,
              (typename AtomicVariantMessage::VariantTypeCase,
               const KeyType&,
               VisitCallback),
              (override));
};

}  // namespace secagentd::testing
#endif  // SECAGENTD_TEST_MOCK_BATCH_SENDER_H_
