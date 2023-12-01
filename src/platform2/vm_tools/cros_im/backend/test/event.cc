// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "backend/test/event.h"

#include <iostream>

#include "backend/test/backend_test.h"
#include "backend/test/backend_test_utils.h"
#include "backend/test/mock_text_input.h"

namespace cros_im {
namespace test {

std::ostream& operator<<(std::ostream& stream, const Event& event) {
  stream << "[Event: ";
  event.Print(stream);
  stream << "]";
  return stream;
}

CommitStringEvent::~CommitStringEvent() = default;

void CommitStringEvent::Run() const {
  auto* text_input = GetTextInput(text_input_id_);
  if (!text_input) {
    FAILED() << "Failed to find text_input object";
    return;
  }
  text_input->listener->commit_string(text_input->listener_data, text_input,
                                      /*serial=*/0, text_.c_str());
}

void CommitStringEvent::Print(std::ostream& stream) const {
  stream << "commit_string(" << text_ << ")";
}

DeleteSurroundingTextEvent::~DeleteSurroundingTextEvent() = default;

void DeleteSurroundingTextEvent::Run() const {
  auto* text_input = GetTextInput(text_input_id_);
  if (!text_input) {
    FAILED() << "Failed to find text_input object";
    return;
  }
  text_input->listener->delete_surrounding_text(text_input->listener_data,
                                                text_input, index_, length_);
}

void DeleteSurroundingTextEvent::Print(std::ostream& stream) const {
  stream << "delete_surrounding_text(" << index_ << ", " << length_ << ")";
}

KeySymEvent::~KeySymEvent() = default;

void KeySymEvent::Run() const {
  auto* text_input = GetTextInput(text_input_id_);
  if (!text_input) {
    FAILED() << "Failed to find text_input object";
    return;
  }
  bool pressed = true;
  text_input->listener->keysym(text_input->listener_data, text_input,
                               /*serial=*/0, /*time=*/0, keysym_,
                               /*state=*/pressed, modifiers_);
}

void KeySymEvent::Print(std::ostream& stream) const {
  stream << "key_sym(" << keysym_ << ", " << modifiers_ << ")";
}

SetPreeditRegionEvent::~SetPreeditRegionEvent() = default;

void SetPreeditRegionEvent::Run() const {
  auto* extended_text_input = GetExtendedTextInput(text_input_id_);
  if (!extended_text_input) {
    FAILED() << "Failed to find text_input object";
    return;
  }
  extended_text_input->listener->set_preedit_region(
      extended_text_input->listener_data, extended_text_input, index_, length_);
}

void SetPreeditRegionEvent::Print(std::ostream& stream) const {
  stream << "set_preedit_region(" << index_ << ", " << length_ << ")";
}

}  // namespace test
}  // namespace cros_im
