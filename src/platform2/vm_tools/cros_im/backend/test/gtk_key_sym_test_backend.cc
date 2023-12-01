// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "backend/test/backend_test.h"

#include <xkbcommon/xkbcommon-keysyms.h>

namespace cros_im {
namespace test {

// GtkTextView triggers reset() at a few places (e.g. gtk_text_view_backspace
// gtk_text_view_key_press_event or if gtktextview.c). The expectations here
// are just documenting the behaviour but we could maybe just ignore the
// requests instead.

BACKEND_TEST(GtkKeySymTextViewTest, TextInput) {
  ExpectCreateTextInput();

  Expect(Request::kActivate);
  SendKeySym(XKB_KEY_d);
  SendKeySym(XKB_KEY_o);
  SendKeySym(XKB_KEY_g);
  SendKeySym(XKB_KEY_asciitilde);

  Expect(Request::kDeactivate);
}

BACKEND_TEST(GtkKeySymTextViewTest, NonAscii) {
  ExpectCreateTextInput();

  Expect(Request::kActivate);

  SendKeySym(XKB_KEY_sterling);
  SendKeySym(XKB_KEY_Udiaeresis);
  SendKeySym(XKB_KEY_Ncedilla);
  SendKeySym(XKB_KEY_kana_a);
  SendKeySym(XKB_KEY_Arabic_jeh);
  SendKeySym(XKB_KEY_Georgian_nar);
  SendKeySym(XKB_KEY_Greek_omicron);

  Expect(Request::kDeactivate);
}

BACKEND_TEST(GtkKeySymTextViewTest, Whitespace) {
  ExpectCreateTextInput();

  Expect(Request::kActivate);

  SendKeySym(XKB_KEY_Return);
  Expect(Request::kReset);
  SendKeySym(XKB_KEY_Tab);
  SendKeySym(XKB_KEY_space);
  SendKeySym(XKB_KEY_Return);
  Expect(Request::kReset);
  SendKeySym(XKB_KEY_space);
  SendKeySym(XKB_KEY_Tab);

  Expect(Request::kReset);
  Expect(Request::kDeactivate);
}

BACKEND_TEST(GtkKeySymTextViewTest, Backspace) {
  ExpectCreateTextInput();

  Expect(Request::kActivate);

  SendKeySym(XKB_KEY_a);
  SendKeySym(XKB_KEY_BackSpace);
  Expect(Request::kReset);
  SendKeySym(XKB_KEY_Return);
  SendKeySym(XKB_KEY_b);
  SendKeySym(XKB_KEY_BackSpace);
  Expect(Request::kReset);
  SendKeySym(XKB_KEY_c);
  SendKeySym(XKB_KEY_BackSpace);
  Expect(Request::kReset);
  SendKeySym(XKB_KEY_BackSpace);

  Expect(Request::kDeactivate);
}

BACKEND_TEST(GtkKeySymEntryTest, Enter) {
  ExpectCreateTextInput();

  Expect(Request::kActivate);

  SendKeySym(XKB_KEY_e);
  SendKeySym(XKB_KEY_Return);
  // As per gtk_entry_key_press in gtkentry.c
  Expect(Request::kReset);

  Expect(Request::kDeactivate);
  Expect(Request::kReset);
}

BACKEND_TEST(GtkKeySymEntryTest, Tab) {
  ExpectCreateTextInput();

  Expect(Request::kActivate);

  SendKeySym(XKB_KEY_t);
  SendKeySym(XKB_KEY_Tab);

  Expect(Request::kDeactivate);
  Expect(Request::kReset);
}

// This test verifies that FilterKeypress isn't consuming events like Ctrl-A.
// It's doesn't entirely match real-world behaviour as Chrome would currently
// send these events as wl_keyboard::key instead of text_input::keysym, but we
// don't have a way to fake the former and our handling for keysym events
// generates fake key events which end up in the FilterKeypress code path
// anyway.
BACKEND_TEST(GtkKeySymTextViewTest, Modifiers) {
  ExpectCreateTextInput();

  constexpr uint32_t kControlMask = 4;

  Expect(Request::kActivate);
  SendKeySym(XKB_KEY_e);
  SendKeySym(XKB_KEY_a, kControlMask);
  Expect(Request::kReset);
  SendKeySym(XKB_KEY_x, kControlMask);
  SendKeySym(XKB_KEY_f);
  SendKeySym(XKB_KEY_v, kControlMask);

  Expect(Request::kDeactivate);
}

}  // namespace test
}  // namespace cros_im
