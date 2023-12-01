// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_TEST_EVENT_DISPATCHER_H_
#define SHILL_TEST_EVENT_DISPATCHER_H_

#include <base/test/task_environment.h>
#include <brillo/message_loops/base_message_loop.h>

#include "shill/event_dispatcher.h"

namespace shill {

// Event dispatcher with base::test::TaskEnvironment for testing.
class EventDispatcherForTest : public EventDispatcher {
 public:
  EventDispatcherForTest() = default;
  EventDispatcherForTest(const EventDispatcherForTest&) = delete;
  EventDispatcherForTest& operator=(const EventDispatcherForTest&) = delete;

  ~EventDispatcherForTest() override = default;

  base::test::TaskEnvironment& task_environment() { return task_environment_; }

 private:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME,
      base::test::TaskEnvironment::MainThreadType::IO};
};

}  // namespace shill

#endif  // SHILL_TEST_EVENT_DISPATCHER_H_
