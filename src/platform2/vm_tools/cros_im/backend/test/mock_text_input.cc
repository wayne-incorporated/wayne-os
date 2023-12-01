// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "backend/test/mock_text_input.h"

#include "backend/test/backend_test.h"
#include "backend/test/backend_test_utils.h"
#include "backend/test/request.h"

#include <memory>
#include <vector>

using cros_im::test::Request;

const wl_interface zwp_text_input_manager_v1_interface = {};
const wl_interface zcr_text_input_extension_v1_interface = {};
const wl_interface zcr_text_input_x11_v1_interface = {};

namespace {

std::vector<std::unique_ptr<zwp_text_input_v1>>& GetTextInputs() {
  static std::vector<std::unique_ptr<zwp_text_input_v1>> text_inputs;
  return text_inputs;
}

std::vector<std::unique_ptr<zcr_extended_text_input_v1>>&
GetExtendedTextInputs() {
  static std::vector<std::unique_ptr<zcr_extended_text_input_v1>>
      extended_text_inputs;
  return extended_text_inputs;
}

void HandleRequest(const Request& request) {
  cros_im::test::BackendTest::GetInstance()->ProcessRequest(request);
}

void HandleRequest(zwp_text_input_v1* text_input, Request::RequestType type) {
  HandleRequest(Request(text_input->id, type));
}

void HandleRequest(zcr_extended_text_input_v1* extended_text_input,
                   Request::RequestType type) {
  HandleRequest(Request(extended_text_input->id, type));
}

}  // namespace

zwp_text_input_v1* zwp_text_input_manager_v1_create_text_input(
    zwp_text_input_manager_v1*) {
  auto& text_inputs = GetTextInputs();
  int id = text_inputs.size();
  text_inputs.emplace_back(new zwp_text_input_v1({nullptr, nullptr, id}));
  HandleRequest(text_inputs.back().get(), Request::kCreateTextInput);
  return text_inputs.back().get();
}

void zwp_text_input_v1_add_listener(zwp_text_input_v1* text_input,
                                    const zwp_text_input_v1_listener* listener,
                                    void* listener_data) {
  text_input->listener = listener;
  text_input->listener_data = listener_data;
}

void zwp_text_input_v1_destroy(zwp_text_input_v1* text_input) {
  // As per b/254386833, text_input::destroy() is not a destructor so the
  // actual object does not get destroyed by the server.
  HandleRequest(text_input, Request::kDestroy);
}

void zwp_text_input_v1_activate(zwp_text_input_v1* text_input,
                                wl_seat*,
                                wl_surface*) {
  HandleRequest(text_input, Request::kActivate);
}

void zwp_text_input_v1_deactivate(zwp_text_input_v1* text_input, wl_seat*) {
  HandleRequest(text_input, Request::kDeactivate);
}

void zwp_text_input_v1_hide_input_panel(zwp_text_input_v1* text_input) {
  HandleRequest(text_input, Request::kHideInputPanel);
}

void zwp_text_input_v1_show_input_panel(zwp_text_input_v1* text_input) {
  HandleRequest(text_input, Request::kShowInputPanel);
}

void zwp_text_input_v1_reset(zwp_text_input_v1* text_input) {
  HandleRequest(text_input, Request::kReset);
}

void zwp_text_input_v1_set_surrounding_text(zwp_text_input_v1* text_input,
                                            const char* text,
                                            uint32_t cursor,
                                            uint32_t anchor) {
  HandleRequest(cros_im::test::SetSurroundingTextRequest(text_input->id, text,
                                                         cursor, anchor));
}

void zwp_text_input_v1_set_content_type(zwp_text_input_v1* text_input,
                                        uint32_t hints,
                                        uint32_t purpose) {
  HandleRequest(
      cros_im::test::SetContentTypeRequest(text_input->id, hints, purpose));
}

void zwp_text_input_v1_set_cursor_rectangle(zwp_text_input_v1* text_input,
                                            int32_t x,
                                            int32_t y,
                                            int32_t width,
                                            int32_t height) {
  HandleRequest(text_input, Request::kSetCursorRectangle);
}

zcr_extended_text_input_v1* zcr_text_input_extension_v1_get_extended_text_input(
    zcr_text_input_extension_v1* text_input_extension,
    zwp_text_input_v1* text_input) {
  auto& extended_text_inputs = GetExtendedTextInputs();
  int id = extended_text_inputs.size();
  // text_input creation is always paired with extended_text_input creation.
  EXPECT_TRUE(text_input && text_input->id == id);
  extended_text_inputs.emplace_back(
      new zcr_extended_text_input_v1({nullptr, nullptr, id}));
  return extended_text_inputs.back().get();
}

void zcr_extended_text_input_v1_add_listener(
    zcr_extended_text_input_v1* extended_text_input,
    const zcr_extended_text_input_v1_listener* listener,
    void* listener_data) {
  extended_text_input->listener = listener;
  extended_text_input->listener_data = listener_data;
}

void zcr_extended_text_input_v1_set_input_type(
    zcr_extended_text_input_v1* extended_text_input,
    uint32_t input_type,
    uint32_t input_mode,
    uint32_t input_flags,
    uint32_t learning_mode,
    uint32_t inline_composition_support) {
  HandleRequest(cros_im::test::SetInputTypeRequest(
      extended_text_input->id, input_type, input_mode, input_flags,
      learning_mode, input_flags));
}

void zcr_extended_text_input_v1_destroy(
    zcr_extended_text_input_v1* extended_text_input) {
  HandleRequest(extended_text_input, Request::kExtensionDestroy);
  GetExtendedTextInputs().at(extended_text_input->id).reset();
}

void zcr_extended_text_input_v1_set_surrounding_text_support(
    zcr_extended_text_input_v1* extended_text_input, uint32_t support) {
  HandleRequest(cros_im::test::SetSurroundingTextSupportRequest(
      extended_text_input->id, support));
}

void zcr_text_input_x11_v1_activate(zcr_text_input_x11_v1* text_input_x11,
                                    zwp_text_input_v1* text_input,
                                    wl_seat*,
                                    uint32_t x11_id) {
  HandleRequest(text_input, Request::kActivate);
}

namespace cros_im {
namespace test {

zwp_text_input_v1* GetTextInput(int text_input_id) {
  return GetTextInputs().at(text_input_id).get();
}

zcr_extended_text_input_v1* GetExtendedTextInput(int extended_text_input_id) {
  return GetExtendedTextInputs().at(extended_text_input_id).get();
}

}  // namespace test
}  // namespace cros_im
