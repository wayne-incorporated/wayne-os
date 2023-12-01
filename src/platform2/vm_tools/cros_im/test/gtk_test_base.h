// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CROS_IM_TEST_GTK_TEST_BASE_H_
#define VM_TOOLS_CROS_IM_TEST_GTK_TEST_BASE_H_

#include <gtest/gtest.h>
#include <gtkmm/main.h>
#include <gtkmm/textview.h>
#include <gtkmm/window.h>
#include <string>

namespace cros_im {
namespace test {

// Test fixture base class for initializing GTK and settings environment
// variables for the backend. The test runner test/run_tests.py should be used
// to run these tests to capture backend failures and allow running multiple
// tests.
class GtkTestBase : public ::testing::Test {
 public:
  GtkTestBase() {
    auto test_info = ::testing::UnitTest::GetInstance()->current_test_info();
    std::string full_name =
        std::string(test_info->test_case_name()) + "." + test_info->name();
    setenv("CROS_TEST_FULL_NAME", full_name.c_str(), true);
  }

  ~GtkTestBase() override = default;

 protected:
  // e.g. Glib::SignalProxyProperty or Glib::SignalProxy<void()>.
  template <typename Signal>
  void RunUntilSignal(Signal signal) {
    ASSERT_FALSE(connection_);
    connection_ = signal.connect(sigc::mem_fun(*this, &GtkTestBase::OnSignal));
    Gtk::Main::run();
  }

  void OnSignal() {
    connection_.disconnect();
    Gtk::Main::quit();
  }

  // Gtk::TextView or Gtk::Entry
  template <typename T>
  void ExpectBufferIs(T* text_widget_, const std::string& expect) {
    EXPECT_EQ(text_widget_->get_buffer()->get_text(), expect);
  }

  // This does not include pre-edit text if present.
  template <typename T>
  void RunAndExpectBufferChangeTo(T* text_widget_, const std::string& expect) {
    RunUntilSignal(
        text_widget_->get_buffer()->property_text().signal_changed());
    ExpectBufferIs(text_widget_, expect);
  }

  template <typename T>
  static void RunAndExpectWidgetPreeditChangeTo(T* text_widget_,
                                                const std::string& expect) {
    // preedit-changed isn't hooked up to gtkmm, so manually set up the signal.
    std::string result;
    gulong handler_id =
        g_signal_connect(text_widget_->gobj(), "preedit-changed",
                         G_CALLBACK(OnPreeditChanged), &result);
    Gtk::Main::run();
    g_signal_handler_disconnect(text_widget_->gobj(), handler_id);

    EXPECT_EQ(result, expect);
  }

  static void OnPreeditChanged(GtkTextView* self,
                               char* preedit,
                               gpointer user_data) {
    *static_cast<std::string*>(user_data) = preedit;
    Gtk::Main::quit();
  }

  template <typename T>
  static void RunUntilWidgetFocused(T* widget) {
    // focus-in-event isn't hooked up to gtkmm, so manually set up the signal.
    gulong handler_id = g_signal_connect(widget->gobj(), "focus-in-event",
                                         G_CALLBACK(OnFocusInEvent), nullptr);
    Gtk::Main::run();
    g_signal_handler_disconnect(widget->gobj(), handler_id);
  }

  static gboolean OnFocusInEvent(GtkTextView* self,
                                 GdkEventFocus event,
                                 gpointer user_data) {
    Gtk::Main::quit();
    // Don't consume the event.
    return false;
  }

  template <typename T>
  void MoveBufferCursor(T* text_widget_, int index) {
    auto buffer = text_widget_->get_buffer();
    buffer->place_cursor(buffer->get_iter_at_offset(index));
  }

  void RunUntilIdle() {
    while (main_.events_pending())
      main_.iteration();
  }

  Gtk::Main main_;

  sigc::connection connection_;
};

// Test fixture for using a single TextView widget.
class GtkSimpleTextViewTest : public GtkTestBase {
 public:
  GtkSimpleTextViewTest() {
    window_.add(text_view_);
    text_view_.show();
    window_.show();
  }

  ~GtkSimpleTextViewTest() override = default;

 protected:
  void RunAndExpectTextChangeTo(const std::string& expect) {
    RunAndExpectBufferChangeTo(&text_view_, expect);
  }

  void ExpectTextIs(const std::string& expect) {
    ExpectBufferIs(&text_view_, expect);
  }

  void RunAndExpectPreeditChangeTo(const std::string& expect) {
    RunAndExpectWidgetPreeditChangeTo(&text_view_, expect);
  }

  void RunUntilFocused() { RunUntilWidgetFocused(&text_view_); }

  // `index` is in characters, not bytes.
  void MoveCursor(int index) { MoveBufferCursor(&text_view_, index); }

  void SetText(const std::string& text) {
    text_view_.get_buffer()->set_text(text);
  }

  Gtk::Window window_;
  Gtk::TextView text_view_;
};

}  // namespace test
}  // namespace cros_im

#endif  // VM_TOOLS_CROS_IM_TEST_GTK_TEST_BASE_H_
