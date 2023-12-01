// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "test/gtk_test_base.h"

#include <gtkmm/box.h>
#include <gtkmm/textview.h>
#include <gtkmm/window.h>

// Basic tests for focus/blur of GTK's TextView. These tests verify all the
// Wayland requests as other tests generally ignore requests unrelated to the
// functionality they try test.

namespace cros_im {
namespace test {

namespace {

class GtkBasicTest : public GtkTestBase {
 public:
  GtkBasicTest() {
    window_.add(box_);
    box_.show();
    box_.add(text_view_0_);
    text_view_0_.show();
    window_.show();
  }

 protected:
  Gtk::Window window_;
  Gtk::Box box_;
  Gtk::TextView text_view_0_;
  Gtk::TextView text_view_1_;
};

}  // namespace

TEST_F(GtkBasicTest, TextViewShownImmediately) {
  RunUntilWidgetFocused(&text_view_0_);
}

TEST_F(GtkBasicTest, SwitchFocus) {
  RunUntilWidgetFocused(&text_view_0_);
  RunUntilIdle();

  box_.add(text_view_1_);
  text_view_1_.show();
  // This immediately triggers the focus-in-event.
  text_view_1_.grab_focus();
  RunUntilIdle();
}

}  // namespace test
}  // namespace cros_im
