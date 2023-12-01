// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "test/gtk_test_base.h"

#include <gtkmm/box.h>
#include <gtkmm/button.h>
#include <gtkmm/entry.h>
#include <gtkmm/window.h>

namespace cros_im {
namespace test {

namespace {

using GtkKeySymTextViewTest = GtkSimpleTextViewTest;

// Test for enter and tab.
class GtkKeySymEntryTest : public GtkTestBase {
 public:
  GtkKeySymEntryTest() {
    box_.add(entry_);
    entry_.show();
    box_.add(button_);
    button_.show();
    box_.show();
    window_.add(box_);
    window_.show();
    // Activate button when enter key is pressed.
    button_.set_can_default(true);
    button_.grab_default();
    entry_.property_activates_default() = true;
  }

 protected:
  Gtk::Window window_;
  Gtk::Box box_;
  Gtk::Button button_;
  Gtk::Entry entry_;
};

}  // namespace

TEST_F(GtkKeySymTextViewTest, TextInput) {
  RunAndExpectTextChangeTo("d");
  RunAndExpectTextChangeTo("do");
  RunAndExpectTextChangeTo("dog");
  RunAndExpectTextChangeTo("dog~");
}

TEST_F(GtkKeySymTextViewTest, NonAscii) {
  RunAndExpectTextChangeTo(u8"£");
  RunAndExpectTextChangeTo(u8"£Ü");
  RunAndExpectTextChangeTo(u8"£ÜŅ");
  RunAndExpectTextChangeTo(u8"£ÜŅァ");
  RunAndExpectTextChangeTo(u8"£ÜŅァژ");
  RunAndExpectTextChangeTo(u8"£ÜŅァژნ");
  RunAndExpectTextChangeTo(u8"£ÜŅァژნο");
}

TEST_F(GtkKeySymTextViewTest, Whitespace) {
  RunAndExpectTextChangeTo("\n");
  RunAndExpectTextChangeTo("\n\t");
  RunAndExpectTextChangeTo("\n\t ");
  RunAndExpectTextChangeTo("\n\t \n");
  RunAndExpectTextChangeTo("\n\t \n ");
  RunAndExpectTextChangeTo("\n\t \n \t");
}

TEST_F(GtkKeySymTextViewTest, Backspace) {
  RunAndExpectTextChangeTo("a");
  RunAndExpectTextChangeTo("");
  RunAndExpectTextChangeTo("\n");
  RunAndExpectTextChangeTo("\nb");
  RunAndExpectTextChangeTo("\n");
  RunAndExpectTextChangeTo("\nc");
  RunAndExpectTextChangeTo("\n");
  RunAndExpectTextChangeTo("");
}

TEST_F(GtkKeySymEntryTest, Enter) {
  RunUntilSignal(button_.signal_clicked());
  EXPECT_EQ(entry_.get_buffer()->get_text(), "e");
}

TEST_F(GtkKeySymEntryTest, Tab) {
  RunUntilSignal(button_.property_has_focus().signal_changed());
  EXPECT_EQ(entry_.get_buffer()->get_text(), "t");
}

TEST_F(GtkKeySymTextViewTest, Modifiers) {
  RunAndExpectTextChangeTo("e");
  RunAndExpectTextChangeTo("");
  RunAndExpectTextChangeTo("f");
  RunAndExpectTextChangeTo("fe");
}

}  // namespace test
}  // namespace cros_im
