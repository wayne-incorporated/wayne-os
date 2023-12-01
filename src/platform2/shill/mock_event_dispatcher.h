// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOCK_EVENT_DISPATCHER_H_
#define SHILL_MOCK_EVENT_DISPATCHER_H_

#include <base/location.h>
#include <base/time/time.h>
#include <gmock/gmock.h>

#include "shill/event_dispatcher.h"

namespace shill {

class MockEventDispatcher : public EventDispatcher {
 public:
  MockEventDispatcher();
  MockEventDispatcher(const MockEventDispatcher&) = delete;
  MockEventDispatcher& operator=(const MockEventDispatcher&) = delete;

  ~MockEventDispatcher() override;

  MOCK_METHOD(void, DispatchForever, (), (override));
  MOCK_METHOD(void, DispatchPendingEvents, (), (override));
  MOCK_METHOD(void,
              PostDelayedTask,
              (const base::Location&, base::OnceClosure, base::TimeDelta),
              (override));
};

}  // namespace shill

#endif  // SHILL_MOCK_EVENT_DISPATCHER_H_
