// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CROS_IM_BACKEND_TEST_MOCK_TEXT_INPUT_H_
#define VM_TOOLS_CROS_IM_BACKEND_TEST_MOCK_TEXT_INPUT_H_

#include <cstddef>
#include <cstdint>

#include "backend/test/mock_wayland_client.h"
#include "backend/text_input_enums.h"

// This file provides mock implementations of the APIs normally defined and
// implemented in text-input-unstable-v1-client-protocol.h.

// Mocks for zwp_text_input_v1

struct wl_array;
struct wl_seat;
struct wl_surface;
struct zwp_text_input_v1_listener;
struct zwp_text_input_manager_v1;

extern const wl_interface zwp_text_input_manager_v1_interface;

struct zwp_text_input_v1 {
  const zwp_text_input_v1_listener* listener;
  void* listener_data;
  // The n'th (0-indexed) mock object created has an id of n.
  int id;
};

struct zwp_text_input_v1_listener {
  void (*enter)(void*, zwp_text_input_v1*, wl_surface*);
  void (*leave)(void*, zwp_text_input_v1*);
  void (*modifiers_map)(void*, zwp_text_input_v1*, wl_array*);
  void (*input_panel_state)(void*, zwp_text_input_v1*, uint32_t state);
  void (*preedit_string)(void*,
                         zwp_text_input_v1*,
                         uint32_t serial,
                         const char* text,
                         const char* commit);
  void (*preedit_styling)(void*,
                          zwp_text_input_v1*,
                          uint32_t index,
                          uint32_t length,
                          uint32_t style);
  void (*preedit_cursor)(void*, zwp_text_input_v1*, int32_t index);
  void (*commit_string)(void*,
                        zwp_text_input_v1*,
                        uint32_t serial,
                        const char* text);
  void (*cursor_position)(void*,
                          zwp_text_input_v1*,
                          int32_t index,
                          int32_t anchor);
  void (*delete_surrounding_text)(void*,
                                  zwp_text_input_v1*,
                                  int32_t index,
                                  uint32_t length);
  void (*keysym)(void*,
                 zwp_text_input_v1*,
                 uint32_t serial,
                 uint32_t time,
                 uint32_t sym,
                 uint32_t state,
                 uint32_t modifiers);
  void (*language)(void*,
                   zwp_text_input_v1*,
                   uint32_t serial,
                   const char* language);
  void (*text_direction)(void*,
                         zwp_text_input_v1*,
                         uint32_t serial,
                         uint32_t direction);
};

zwp_text_input_v1* zwp_text_input_manager_v1_create_text_input(
    zwp_text_input_manager_v1* text_input_manager);

void zwp_text_input_v1_add_listener(zwp_text_input_v1*,
                                    const zwp_text_input_v1_listener*,
                                    void* listener_data);

void zwp_text_input_v1_destroy(zwp_text_input_v1*);
void zwp_text_input_v1_activate(zwp_text_input_v1*, wl_seat*, wl_surface*);
void zwp_text_input_v1_deactivate(zwp_text_input_v1*, wl_seat*);
void zwp_text_input_v1_show_input_panel(zwp_text_input_v1*);
void zwp_text_input_v1_hide_input_panel(zwp_text_input_v1*);
void zwp_text_input_v1_reset(zwp_text_input_v1*);
void zwp_text_input_v1_set_surrounding_text(zwp_text_input_v1*,
                                            const char* text,
                                            uint32_t cursor,
                                            uint32_t anchor);
void zwp_text_input_v1_set_content_type(zwp_text_input_v1*,
                                        uint32_t hint,
                                        uint32_t purpose);
void zwp_text_input_v1_set_cursor_rectangle(
    zwp_text_input_v1*, int32_t x, int32_t y, int32_t width, int32_t height);

// Mocks for zcr_extended_text_input_v1

struct zcr_extended_text_input_v1_listener;
struct zcr_text_input_extension_v1;

extern const wl_interface zcr_text_input_extension_v1_interface;

struct zcr_extended_text_input_v1 {
  const zcr_extended_text_input_v1_listener* listener;
  void* listener_data;
  // The n'th (0-indexed) mock object created has an id of n.
  int id;
};

zcr_extended_text_input_v1* zcr_text_input_extension_v1_get_extended_text_input(
    zcr_text_input_extension_v1* text_input_extension,
    zwp_text_input_v1* text_input);

struct zcr_extended_text_input_v1_listener {
  void (*set_preedit_region)(void* data,
                             struct zcr_extended_text_input_v1*,
                             int32_t index,
                             uint32_t length);
  void (*clear_grammar_fragments)(void* data,
                                  struct zcr_extended_text_input_v1*,
                                  uint32_t start,
                                  uint32_t end);
  void (*add_grammar_fragment)(void* data,
                               struct zcr_extended_text_input_v1*,
                               uint32_t start,
                               uint32_t end,
                               const char* suggestion);
  void (*set_autocorrect_range)(void* data,
                                struct zcr_extended_text_input_v1*,
                                uint32_t start,
                                uint32_t end);
  void (*set_virtual_keyboard_occluded_bounds)(
      void* data,
      struct zcr_extended_text_input_v1*,
      int32_t x,
      int32_t y,
      int32_t width,
      int32_t height);
};

void zcr_extended_text_input_v1_add_listener(
    zcr_extended_text_input_v1*,
    const zcr_extended_text_input_v1_listener*,
    void* listener_data);

void zcr_extended_text_input_v1_destroy(zcr_extended_text_input_v1*);

void zcr_extended_text_input_v1_set_input_type(
    zcr_extended_text_input_v1*,
    uint32_t input_type,
    uint32_t input_mode,
    uint32_t input_flags,
    uint32_t learning_mode,
    uint32_t inline_composition_support);

#define ZCR_EXTENDED_TEXT_INPUT_V1_SET_SURROUNDING_TEXT_SUPPORT_SINCE_VERSION 9

// |support| is a enum of type
// |zcr_extended_text_input_v1_surrounding_text_support|.
void zcr_extended_text_input_v1_set_surrounding_text_support(
    zcr_extended_text_input_v1*, uint32_t support);

// Mocks for zcr_text_input_x11_v1

struct zcr_text_input_x11_v1_listener;
struct zcr_text_input_x11_v1;

extern const wl_interface zcr_text_input_x11_v1_interface;

void zcr_text_input_x11_v1_activate(zcr_text_input_x11_v1*,
                                    zwp_text_input_v1*,
                                    wl_seat*,
                                    uint32_t x11_id);

namespace cros_im {
namespace test {

zwp_text_input_v1* GetTextInput(int text_input_id);
zcr_extended_text_input_v1* GetExtendedTextInput(int extended_text_input_id);

}  // namespace test
}  // namespace cros_im

#endif  // VM_TOOLS_CROS_IM_BACKEND_TEST_MOCK_TEXT_INPUT_H_
