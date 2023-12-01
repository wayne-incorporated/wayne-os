// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CROS_IM_BACKEND_TEST_EVENT_H_
#define VM_TOOLS_CROS_IM_BACKEND_TEST_EVENT_H_

#include <iostream>
#include <string>

namespace cros_im {
namespace test {

// Represents a Wayland event, i.e. a call from the compositor.
class Event {
 public:
  explicit Event(int text_input_id) : text_input_id_(text_input_id) {}
  virtual ~Event() {}
  virtual void Run() const = 0;
  virtual void Print(std::ostream& stream) const = 0;

 protected:
  int text_input_id_;
};

std::ostream& operator<<(std::ostream& stream, const Event& event);

class CommitStringEvent : public Event {
 public:
  CommitStringEvent(int text_input_id, const std::string& text)
      : Event(text_input_id), text_(text) {}
  ~CommitStringEvent() override;
  void Run() const override;
  void Print(std::ostream& stream) const override;

 private:
  std::string text_;
};

class DeleteSurroundingTextEvent : public Event {
 public:
  DeleteSurroundingTextEvent(int text_input_id, int index, int length)
      : Event(text_input_id), index_(index), length_(length) {}
  ~DeleteSurroundingTextEvent() override;
  void Run() const override;
  void Print(std::ostream& stream) const override;

 private:
  int index_;
  int length_;
};

class KeySymEvent : public Event {
 public:
  KeySymEvent(int text_input_id, int keysym, uint32_t modifiers)
      : Event(text_input_id), keysym_(keysym), modifiers_(modifiers) {}
  ~KeySymEvent() override;
  void Run() const override;
  void Print(std::ostream& stream) const override;

 private:
  int keysym_;
  uint32_t modifiers_;
};

class SetPreeditRegionEvent : public Event {
 public:
  SetPreeditRegionEvent(int text_input_id, int index, int length)
      : Event(text_input_id), index_(index), length_(length) {}
  ~SetPreeditRegionEvent() override;
  void Run() const override;
  void Print(std::ostream& stream) const override;

 private:
  int index_;
  int length_;
};

}  // namespace test
}  // namespace cros_im

#endif  // VM_TOOLS_CROS_IM_BACKEND_TEST_EVENT_H_
