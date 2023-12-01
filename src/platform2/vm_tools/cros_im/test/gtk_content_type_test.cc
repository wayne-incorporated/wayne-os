// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "test/gtk_test_base.h"

#include <gtkmm/box.h>
#include <gtkmm/entry.h>
#include <gtkmm/enums.h>
#include <gtkmm/textview.h>

namespace cros_im {
namespace test {

namespace {

// Live changes to content type are not detected, test by switching focus
// between two text fields.
class GtkContentTypeTest : public GtkTestBase {
 public:
  GtkContentTypeTest() {
    box_.add(text_view_);
    window_.add(box_);

    text_view_.show();
    box_.show();
    window_.show();
  }

 protected:
  Gtk::Window window_;
  Gtk::Box box_;
  Gtk::TextView text_view_;
  Gtk::Entry entry_;
};

}  // namespace

TEST_F(GtkContentTypeTest, ContentHints) {
  text_view_.set_input_hints(Gtk::INPUT_HINT_SPELLCHECK |
                             Gtk::INPUT_HINT_UPPERCASE_CHARS);
  RunAndExpectBufferChangeTo(&text_view_, "a");

  // Delay adding entry_ so text_input creation order is obvious.
  box_.add(entry_);
  entry_.show();
  entry_.set_input_hints(Gtk::INPUT_HINT_WORD_COMPLETION |
                         Gtk::INPUT_HINT_NO_SPELLCHECK |
                         Gtk::INPUT_HINT_LOWERCASE);
  entry_.grab_focus();
  RunAndExpectBufferChangeTo(&entry_, "b");

  // NO_EMOJI is ignored.
  text_view_.set_input_hints(Gtk::INPUT_HINT_UPPERCASE_WORDS |
                             Gtk::INPUT_HINT_NO_EMOJI);
  text_view_.grab_focus();
  RunAndExpectBufferChangeTo(&text_view_, "ac");

  // VERTICAL_WRITING and EMOJI are ignored.
  entry_.set_input_hints(Gtk::INPUT_HINT_UPPERCASE_SENTENCES |
                         Gtk::INPUT_HINT_VERTICAL_WRITING |
                         Gtk::INPUT_HINT_EMOJI);
  entry_.grab_focus_without_selecting();
  RunAndExpectBufferChangeTo(&entry_, "bd");

  text_view_.set_input_hints(Gtk::INPUT_HINT_INHIBIT_OSK);
  text_view_.grab_focus();
  RunAndExpectBufferChangeTo(&text_view_, "ace");
}

TEST_F(GtkContentTypeTest, ContentPurpose) {
  text_view_.set_input_purpose(Gtk::INPUT_PURPOSE_ALPHA);
  RunAndExpectBufferChangeTo(&text_view_, "a");

  // Delay adding entry_ so text_input creation order is obvious.
  box_.add(entry_);
  entry_.show();
  entry_.set_input_purpose(Gtk::INPUT_PURPOSE_DIGITS);
  // Like a password field but does not actually set hint or purpose.
  entry_.set_visibility(false);
  entry_.grab_focus();
  RunAndExpectBufferChangeTo(&entry_, "1");
  entry_.set_visibility(true);

  text_view_.set_input_purpose(Gtk::INPUT_PURPOSE_EMAIL);
  text_view_.grab_focus();
  RunAndExpectBufferChangeTo(&text_view_, "ac");

  entry_.set_input_purpose(Gtk::INPUT_PURPOSE_PIN);
  entry_.grab_focus_without_selecting();
  RunAndExpectBufferChangeTo(&entry_, "10");

  text_view_.set_input_purpose(Gtk::INPUT_PURPOSE_PASSWORD);
  text_view_.grab_focus();
  RunAndExpectBufferChangeTo(&text_view_, "ace");
}

}  // namespace test
}  // namespace cros_im
