// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CROS_IM_BACKEND_IM_CONTEXT_BACKEND_H_
#define VM_TOOLS_CROS_IM_BACKEND_IM_CONTEXT_BACKEND_H_

#include <cstdint>
#include <string>
#include <vector>

#include "backend/text_input_enums.h"

struct wl_array;
struct wl_surface;
struct zwp_text_input_v1;
struct zwp_text_input_v1_listener;
struct zcr_extended_text_input_v1;
struct zcr_extended_text_input_v1_listener;

namespace cros_im {

// As per the preedit_styling event, index and length provide the range to
// style in bytes.
struct PreeditStyle {
  uint32_t index;
  uint32_t length;
  zwp_text_input_v1_preedit_style style;
};

enum class KeyState { kPressed, kReleased };

// IMContextBackend wraps a text_input_v1 object.
class IMContextBackend {
 public:
  class Observer {
   public:
    virtual ~Observer() {}
    // |preedit| is UTF-8, |cursor| is in bytes.
    virtual void SetPreedit(const std::string& preedit,
                            int cursor,
                            const std::vector<PreeditStyle>& styles) = 0;
    // |start_offset| is relative to the cursor as a UTF-8 byte offset.
    // |length| is a strictly positive UTF-8 byte count.
    // The current cursor position will inside or on the boundary of the
    // specified range.
    virtual void SetPreeditRegion(int start_offset,
                                  int length,
                                  const std::vector<PreeditStyle>& styles) = 0;
    virtual void Commit(const std::string& text) = 0;

    // Both values are in bytes. |start_offset| is relative to the cursor.
    virtual void DeleteSurroundingText(int start_offset, int length) = 0;

    virtual void KeySym(uint32_t keysym,
                        KeyState state,
                        uint32_t modifiers) = 0;
  };

  struct ContentTypeOld {
    uint32_t hints;    // zwp_text_input_v1_content_hint
    uint32_t purpose;  // zwp_text_input_v1_content_purpose
  };

  struct ContentType {
    zcr_extended_text_input_v1_input_type input_type;
    zcr_extended_text_input_v1_input_mode input_mode;
    uint32_t input_flags;  // zcr_extended_text_input_v1_input_flags
    zcr_extended_text_input_v1_learning_mode learning_mode;
    zcr_extended_text_input_v1_inline_composition_support
        inline_composition_support;
  };

  explicit IMContextBackend(Observer* observer);
  ~IMContextBackend();

  void Activate(wl_surface* surface);
  void ActivateX11(uint32_t x11_id);
  void Deactivate();
  void ShowInputPanel();
  void Reset();
  void SetSurrounding(const char* text, int cursor_index);
  void SetContentTypeOld(ContentTypeOld content_type);
  void SetContentType(ContentType content_type);
  void SetCursorLocation(int x, int y, int width, int height);
  void SetSupportsSurrounding(bool is_supported);

 private:
  // We usually initialize in the constructor, but if the Wayland connection
  // isn't ready yet we retry in Activate().
  // TODO(timloh): We should queue up requests from the front-end and send them
  // once the connection is ready.
  void MaybeInitialize();

  // Wayland text_input_v1 event handlers.
  void SetPreedit(uint32_t serial, const char* text, const char* commit);
  void SetPreeditStyling(uint32_t index, uint32_t length, uint32_t style);
  void SetPreeditCursor(uint32_t cursor);
  void Commit(uint32_t serial, const char* text);
  void DeleteSurroundingText(int32_t index, uint32_t length);
  void KeySym(uint32_t serial,
              uint32_t time,
              uint32_t sym,
              uint32_t state,
              uint32_t modifiers);
  // extended_text_input_v1 event handlers.
  void SetPreeditRegion(int32_t index, uint32_t length);

  static const zwp_text_input_v1_listener text_input_listener_;
  zwp_text_input_v1* text_input_ = nullptr;
  static const zcr_extended_text_input_v1_listener
      extended_text_input_listener_;
  zcr_extended_text_input_v1* extended_text_input_ = nullptr;

  // Set/cleared when we call `activate`/`deactivate`. We currently ignore the
  // `enter` event so this may be true even if activation fails.
  bool is_active_ = false;

  Observer* observer_ = nullptr;

  // Pre-edit updates are split across several events.
  int cursor_pos_ = 0;
  std::vector<PreeditStyle> styles_;

  // What we think Chrome considers the index of the cursor is within its
  // belief of the surrounding text, in bytes. Used to resolve
  // indices from delete_surrounding_text.
  int surrounding_cursor_index_ = 0;

  bool virtual_keyboard_enabled_;
};

}  // namespace cros_im

#endif  // VM_TOOLS_CROS_IM_BACKEND_IM_CONTEXT_BACKEND_H_
