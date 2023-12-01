// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CROS_IM_BACKEND_TEST_BACKEND_TEST_H_
#define VM_TOOLS_CROS_IM_BACKEND_TEST_BACKEND_TEST_H_

#include <map>
#include <memory>
#include <queue>
#include <string>
#include <utility>
#include <vector>

#include "backend/test/backend_test_utils.h"
#include "backend/test/event.h"
#include "backend/test/request.h"

namespace cros_im {
namespace test {

// BACKEND_TEST(Group, Name) { .. } defines a function to initialize a
// BackendTest object with Requests to expect and Events to fire when running
// the matching test. The environment variable CROS_TEST_FULL_NAME should be
// set to Group.Name.

// In creating a backend test specification, it may be helpful to use the
// non-test IM module with WAYLAND_DEBUG=1, for example:
// $ export GTK_IM_MODULE=cros
// $ WAYLAND_DEBUG=1 ./cros_im_tests --gtest_filter=Group.Name 2>&1 | grep zwp

#define BACKEND_TEST(Group, Name)                                          \
  struct _##Group##_##Name {};                                             \
  template <>                                                              \
  void BackendTest::SetUpExpectations<_##Group##_##Name>();                \
  static int _ignore_##Group##_##Name =                                    \
      (BackendTest::RegisterTest<_##Group##_##Name>(#Group "." #Name), 0); \
  template <>                                                              \
  void BackendTest::SetUpExpectations<_##Group##_##Name>()

struct Action {
  explicit Action(std::unique_ptr<Request> request)
      : is_request_(true), request_(std::move(request)) {}
  explicit Action(std::unique_ptr<Event> event)
      : is_request_(false), event_(std::move(event)) {}

  const bool is_request_;
  std::unique_ptr<Request> request_;
  std::unique_ptr<Event> event_;
};

std::ostream& operator<<(std::ostream& stream, const Action& action);

class BackendTest {
 public:
  BackendTest() = default;
  ~BackendTest();

  static BackendTest* GetInstance();
  void ProcessRequest(const Request& request);

  // Called by BACKEND_TEST().
  template <class T>
  static void RegisterTest(const char* name) {
    test_initializers_[name] = &BackendTest::SetUpExpectations<T>;
  }

  void RunNextEvent();

 private:
  // Each BACKEND_TEST() macro invocation defines a specialization.
  template <class T>
  void SetUpExpectations();

  // Expectations and responses for use in BACKEND_TEST().

  template <int text_input_id = 0>
  void Ignore(Request::RequestType type) {
    auto request = std::make_unique<Request>(text_input_id, type);
    if (FindIgnore(*request) != ignored_requests_.end()) {
      FAILED() << "Tried to ignore already-ignored request: " << *request;
      return;
    }
    ignored_requests_.push_back(std::move(request));
  }

  template <int text_input_id = 0>
  void Unignore(Request::RequestType type) {
    Request request(text_input_id, type);
    auto it = FindIgnore(request);
    if (it == ignored_requests_.end()) {
      FAILED() << "Couldn't find request to unignore: " << request;
      return;
    }
    ignored_requests_.erase(it);
  }

  template <int text_input_id = 0>
  void Expect(Request::RequestType type) {
    actions_.emplace(std::make_unique<Request>(text_input_id, type));
  }

  // This sets up ignores for various requests for the given id. If these need
  // to be tested, Unignore() can be used.
  template <int text_input_id = 0>
  void ExpectCreateTextInput() {
    Expect<text_input_id>(Request::kCreateTextInput);

    Ignore<text_input_id>(Request::kSetCursorRectangle);
    Ignore<text_input_id>(Request::kSetSurroundingText);
    Ignore<text_input_id>(Request::kSetContentType);
    Ignore<text_input_id>(Request::kSetInputType);
    Ignore<text_input_id>(Request::kShowInputPanel);
    Ignore<text_input_id>(Request::kHideInputPanel);
    Ignore<text_input_id>(Request::kDestroy);
    Ignore<text_input_id>(Request::kExtensionDestroy);
    Ignore<text_input_id>(Request::kSetSurroundingTextSupport);
  }

  template <int text_input_id = 0>
  void ExpectSetContentType(uint32_t hints, uint32_t purpose) {
    actions_.emplace(
        std::make_unique<SetContentTypeRequest>(text_input_id, hints, purpose));
  }

  template <int text_input_id = 0>
  void ExpectSetInputType(uint32_t input_type,
                          uint32_t input_mode,
                          uint32_t input_flags,
                          uint32_t learning_mode,
                          uint32_t inline_composition_support) {
    actions_.emplace(std::make_unique<SetInputTypeRequest>(
        text_input_id, input_type, input_mode, input_flags, learning_mode,
        input_flags));
  }

  template <int text_input_id = 0>
  void ExpectSetSurroundingText(const std::string& text,
                                uint32_t cursor,
                                uint32_t anchor) {
#ifndef DISABLE_SURROUNDING
    actions_.emplace(std::make_unique<SetSurroundingTextRequest>(
        text_input_id, text, cursor, anchor));
#endif
  }

  template <int text_input_id = 0>
  void ExpectSetSurroundingTextSupport(bool is_supported_) {
    actions_.emplace(std::make_unique<SetSurroundingTextSupportRequest>(
        text_input_id, is_supported_));
  }

  template <int text_input_id = 0>
  void SendCommitString(const std::string& string) {
    actions_.emplace(
        std::make_unique<CommitStringEvent>(text_input_id, string));
  }

  template <int text_input_id = 0>
  void SendKeySym(int keysym, uint32_t modifiers = 0) {
    actions_.emplace(
        std::make_unique<KeySymEvent>(text_input_id, keysym, modifiers));
  }

  template <int text_input_id = 0>
  void SendDeleteSurroundingText(int index, int length) {
    actions_.emplace(std::make_unique<DeleteSurroundingTextEvent>(
        text_input_id, index, length));
  }

  template <int text_input_id = 0>
  void SendSetPreeditRegion(int index, int length) {
    actions_.emplace(
        std::make_unique<SetPreeditRegionEvent>(text_input_id, index, length));
  }

  // If the next action is an event, run it asynchronously.
  void PostEventIfNeeded();

  // Returns an entry in ignored_requests_ matching the request if any.
  std::vector<std::unique_ptr<Request>>::iterator FindIgnore(
      const Request& request);

  bool initialized_ = false;
  std::vector<std::unique_ptr<Request>> ignored_requests_;
  std::queue<Action> actions_;

  using TestInitializer = void (BackendTest::*)();
  static std::map<std::string, TestInitializer> test_initializers_;
};

}  // namespace test
}  // namespace cros_im

#endif  // VM_TOOLS_CROS_IM_BACKEND_TEST_BACKEND_TEST_H_
