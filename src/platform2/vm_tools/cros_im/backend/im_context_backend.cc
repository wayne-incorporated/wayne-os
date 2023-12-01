// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "backend/im_context_backend.h"

#include <cassert>
#include <cstring>
#include <utility>

#include "backend/text_input.h"
#include "backend/wayland_client.h"
#include "backend/wayland_manager.h"

namespace cros_im {

namespace {

constexpr char kVirtualKeyboardEnv[] = "CROS_IM_VIRTUAL_KEYBOARD";
constexpr char kVirtualKeyboardEnabled[] = "1";

template <auto F, typename... Args>
auto Fwd(void* data, zwp_text_input_v1* text_input, Args... args) {
  // The backend object should still be alive as libwayland-client drops events
  // sent to destroyed objects.
  return (reinterpret_cast<IMContextBackend*>(data)->*F)(args...);
}

template <typename... Args>
auto DoNothing(void* data, zwp_text_input_v1* text_input, Args... args) {}

template <auto F, typename... Args>
auto FwdExtended(void* data,
                 zcr_extended_text_input_v1* extendedtext_input,
                 Args... args) {
  return (reinterpret_cast<IMContextBackend*>(data)->*F)(args...);
}

template <typename... Args>
auto DoNothingExtended(void* data,
                       zcr_extended_text_input_v1* text_input,
                       Args... args) {}

}  // namespace

const zwp_text_input_v1_listener IMContextBackend::text_input_listener_ = {
    .enter = DoNothing,
    .leave = DoNothing,
    .modifiers_map = DoNothing,
    .input_panel_state = DoNothing,
    .preedit_string = Fwd<&IMContextBackend::SetPreedit>,
    .preedit_styling = Fwd<&IMContextBackend::SetPreeditStyling>,
    .preedit_cursor = Fwd<&IMContextBackend::SetPreeditCursor>,
    .commit_string = Fwd<&IMContextBackend::Commit>,
    .cursor_position = DoNothing,
    .delete_surrounding_text = Fwd<&IMContextBackend::DeleteSurroundingText>,
    .keysym = Fwd<&IMContextBackend::KeySym>,
    .language = DoNothing,
    .text_direction = DoNothing,
};

const zcr_extended_text_input_v1_listener
    IMContextBackend::extended_text_input_listener_ = {
        .set_preedit_region = FwdExtended<&IMContextBackend::SetPreeditRegion>,
        .clear_grammar_fragments = DoNothingExtended,
        .add_grammar_fragment = DoNothingExtended,
        .set_autocorrect_range = DoNothingExtended,
        .set_virtual_keyboard_occluded_bounds = DoNothingExtended,
};

IMContextBackend::IMContextBackend(Observer* observer) : observer_(observer) {
  assert(WaylandManager::HasInstance());

  const char* env = std::getenv(kVirtualKeyboardEnv);
  virtual_keyboard_enabled_ =
      env && std::string(env) == kVirtualKeyboardEnabled;

  MaybeInitialize();
}

IMContextBackend::~IMContextBackend() {
  if (extended_text_input_)
    zcr_extended_text_input_v1_destroy(extended_text_input_);
  if (text_input_)
    zwp_text_input_v1_destroy(text_input_);
}

void IMContextBackend::Activate(wl_surface* surface) {
  MaybeInitialize();

  if (!text_input_) {
    printf("The text input manager is not ready yet or not available.\n");
    return;
  }

  is_active_ = true;
  zwp_text_input_v1_activate(text_input_, WaylandManager::Get()->GetSeat(),
                             surface);
}

void IMContextBackend::ActivateX11(uint32_t x11_id) {
  MaybeInitialize();

  if (!text_input_) {
    printf("The text input manager is not ready yet or not available.\n");
    return;
  }

  is_active_ = true;
  auto* wayland_manager = WaylandManager::Get();
  zcr_text_input_x11_v1_activate(wayland_manager->GetTextInputX11(),
                                 text_input_, wayland_manager->GetSeat(),
                                 x11_id);
}

void IMContextBackend::Deactivate() {
  if (!text_input_)
    return;
  if (!is_active_) {
    printf("Attempted to deactivate text input which was not activated.\n");
    return;
  }

  if (virtual_keyboard_enabled_)
    zwp_text_input_v1_hide_input_panel(text_input_);
  zwp_text_input_v1_deactivate(text_input_, WaylandManager::Get()->GetSeat());
  is_active_ = false;
}

void IMContextBackend::ShowInputPanel() {
  if (!text_input_ || !virtual_keyboard_enabled_)
    return;
  zwp_text_input_v1_show_input_panel(text_input_);
}

void IMContextBackend::Reset() {
  if (!text_input_)
    return;
  zwp_text_input_v1_reset(text_input_);
}

void IMContextBackend::SetSurrounding(const char* text, int cursor_index) {
  if (!text_input_)
    return;
  surrounding_cursor_index_ = cursor_index;
  zwp_text_input_v1_set_surrounding_text(text_input_, text, cursor_index,
                                         cursor_index);
}

void IMContextBackend::SetContentTypeOld(ContentTypeOld content_type) {
  if (!text_input_)
    return;
  zwp_text_input_v1_set_content_type(text_input_, content_type.hints,
                                     content_type.purpose);
}

void IMContextBackend::SetContentType(ContentType content_type) {
  if (!text_input_)
    return;
  zcr_extended_text_input_v1_set_input_type(
      extended_text_input_, content_type.input_type, content_type.input_mode,
      content_type.input_flags, content_type.learning_mode,
      content_type.inline_composition_support);
}

void IMContextBackend::SetCursorLocation(int x, int y, int width, int height) {
  if (!text_input_)
    return;
  zwp_text_input_v1_set_cursor_rectangle(text_input_, x, y, width, height);
}

void IMContextBackend::SetSupportsSurrounding(bool is_supported) {
  if (!text_input_)
    return;
  if (WaylandManager::Get()->GetTextInputExtensionVersion() <
      ZCR_EXTENDED_TEXT_INPUT_V1_SET_SURROUNDING_TEXT_SUPPORT_SINCE_VERSION)
    return;
  zcr_extended_text_input_v1_set_surrounding_text_support(extended_text_input_,
                                                          is_supported);
}

void IMContextBackend::MaybeInitialize() {
  if (text_input_)
    return;

  text_input_ =
      WaylandManager::Get()->CreateTextInput(&text_input_listener_, this);
  if (text_input_) {
    extended_text_input_ = WaylandManager::Get()->CreateExtendedTextInput(
        text_input_, &extended_text_input_listener_, this);
    assert(extended_text_input_);
  }
}

void IMContextBackend::SetPreeditStyling(uint32_t index,
                                         uint32_t length,
                                         uint32_t style) {
  styles_.push_back(
      {.index = index,
       .length = length,
       .style = static_cast<zwp_text_input_v1_preedit_style>(style)});
}

void IMContextBackend::SetPreeditCursor(uint32_t cursor) {
  cursor_pos_ = cursor;
}

// TODO(timloh): Work out what we need to do with serials.

void IMContextBackend::SetPreedit(uint32_t serial,
                                  const char* text,
                                  const char* commit) {
  observer_->SetPreedit(text, cursor_pos_, styles_);
  cursor_pos_ = 0;
  styles_.clear();
}

void IMContextBackend::Commit(uint32_t serial, const char* text) {
  styles_.clear();
  observer_->Commit(text);
}

void IMContextBackend::DeleteSurroundingText(int32_t index,
                                             uint32_t length_unsigned) {
  // TODO(b/252955997): Unlike what is written in the protocol, Chrome's
  // implementation gives a value relative to it's understanding of the
  // surrounding text. The API is not conducive to a correct implementation, so
  // for now we just do something that works in simple cases.

  // Convert from an index relative to the surrounding text to an offset
  // relative to the cursor.
  int start = index - surrounding_cursor_index_;
  int length = length_unsigned;

  // Only support deleting text adjacent to the cursor for now.
  if (start > 0 || start + length < 0 || length == 0)
    return;

  observer_->DeleteSurroundingText(start, length);

  // This handles if Chrome sends multiple delete_surrounding_text events
  // without receiving set_surrounding_text requests. The indices it gives us
  // assume previous delete_surrounding_text requests have been handled already.
  // TODO(timloh): Add automated tests for this case. We currently don't support
  // sending multiple events without running the event loop.
  if (start < 0)
    surrounding_cursor_index_ += start;
}

void IMContextBackend::KeySym(uint32_t serial,
                              uint32_t time,
                              uint32_t sym,
                              uint32_t state,
                              uint32_t modifiers) {
  // TODO(timloh): Handle remaining arguments.
  observer_->KeySym(sym,
                    state == WL_KEYBOARD_KEY_STATE_PRESSED
                        ? KeyState::kPressed
                        : KeyState::kReleased,
                    modifiers);
}

void IMContextBackend::SetPreeditRegion(int32_t index,
                                        uint32_t length_unsigned) {
  int length = length_unsigned;
  if (index > 0 || index + length < 0 || length <= 0) {
    printf("SetPreeditRegion(%d, %u) is for unsupported range.\n", index,
           length);
  } else {
    observer_->SetPreeditRegion(index, length, styles_);
  }
  cursor_pos_ = 0;
  styles_.clear();
}

}  // namespace cros_im
