// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "backend/test/backend_test.h"

#include <algorithm>
#include <glib.h>

#include "backend/test/backend_test_utils.h"

namespace cros_im {
namespace test {

namespace {

int OnIdle(void* data) {
  static_cast<BackendTest*>(data)->RunNextEvent();
  // Disconnect this signal.
  return G_SOURCE_REMOVE;
}

}  // namespace

std::map<std::string, BackendTest::TestInitializer>
    BackendTest::test_initializers_;

std::ostream& operator<<(std::ostream& stream, const Action& action) {
  if (action.is_request_) {
    stream << *action.request_;
  } else {
    stream << *action.event_;
  }
  return stream;
}

BackendTest::~BackendTest() {
  while (!actions_.empty()) {
    FAILED() << "Exited without running action: " << actions_.front();
    actions_.pop();
  }
}

BackendTest* BackendTest::GetInstance() {
  static BackendTest instance;

  if (!instance.initialized_) {
    instance.initialized_ = true;
    std::string test_name = getenv("CROS_TEST_FULL_NAME");
    auto it = test_initializers_.find(test_name);
    if (it == test_initializers_.end()) {
      FAILED() << "Could not find test spec for test '" << test_name << "'.";
    } else {
      // Call the matched SetUpExpectations().
      (instance.*(it->second))();
    }
  }

  return &instance;
}

void BackendTest::ProcessRequest(const Request& request) {
  if (FindIgnore(request) != ignored_requests_.end())
    return;

  if (actions_.empty()) {
    FAILED() << "Received request " << request
             << " but no expectations were left";
    return;
  }

  if (!actions_.front().is_request_ ||
      !actions_.front().request_->RequestMatches(request)) {
    FAILED() << "Received request " << request << " did not match next action "
             << actions_.front();
    return;
  }
  actions_.pop();

  PostEventIfNeeded();
}

void BackendTest::RunNextEvent() {
  if (actions_.empty()) {
    FAILED() << "Tried to run next event but queue is empty.";
    return;
  }
  if (actions_.front().is_request_) {
    FAILED() << "Tried to run next event but next action is a request.";
    return;
  }
  std::unique_ptr<Event> event(std::move(actions_.front().event_));

  // Running the event may synchronously fire a request.
  actions_.pop();
  PostEventIfNeeded();

  event->Run();
}

void BackendTest::PostEventIfNeeded() {
  if (actions_.empty() || actions_.front().is_request_)
    return;
  // This only applies when running with a GTK frontend and we'll need different
  // logic when we add a XIM server.
  g_idle_add(OnIdle, this);
}

std::vector<std::unique_ptr<Request>>::iterator BackendTest::FindIgnore(
    const Request& request) {
  return std::find_if(ignored_requests_.begin(), ignored_requests_.end(),
                      [&request](const auto& ignore) {
                        return ignore->RequestMatches(request);
                      });
}

}  // namespace test
}  // namespace cros_im
