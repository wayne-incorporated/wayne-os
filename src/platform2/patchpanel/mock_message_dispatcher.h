// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_MOCK_MESSAGE_DISPATCHER_H_
#define PATCHPANEL_MOCK_MESSAGE_DISPATCHER_H_

#include <brillo/brillo_export.h>
#include <gmock/gmock.h>
#include <google/protobuf/message_lite.h>

#include "patchpanel/message_dispatcher.h"

namespace patchpanel {

template <typename ProtoMessage>
class BRILLO_EXPORT MockMessageDispatcher
    : public MessageDispatcher<ProtoMessage> {
 public:
  MockMessageDispatcher() : MessageDispatcher<ProtoMessage>(base::ScopedFD()) {}
  MockMessageDispatcher(const MockMessageDispatcher&) = delete;
  MockMessageDispatcher& operator=(const MockMessageDispatcher&) = delete;

  ~MockMessageDispatcher() override = default;

  MOCK_METHOD(void,
              RegisterFailureHandler,
              (base::RepeatingCallback<void()>),
              (override));
  MOCK_METHOD(void,
              RegisterMessageHandler,
              (base::RepeatingCallback<void(const ProtoMessage&)>),
              (override));
  MOCK_METHOD(bool, SendMessage, (const ProtoMessage&), (const, override));
};

}  // namespace patchpanel

#endif  // PATCHPANEL_MOCK_MESSAGE_DISPATCHER_H_
