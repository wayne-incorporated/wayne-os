// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CROS_IM_BACKEND_TEST_REQUEST_H_
#define VM_TOOLS_CROS_IM_BACKEND_TEST_REQUEST_H_

#include <iostream>
#include <string>

#include "backend/text_input_enums.h"

namespace cros_im {
namespace test {

// Represents a Wayland request, i.e. a call to the compositor.
class Request {
 public:
  enum RequestType {
    // Requests on the text_input_manager
    kCreateTextInput,
    // Requests on a text_input object
    kDestroy,
    kActivate,
    kDeactivate,
    kShowInputPanel,
    kHideInputPanel,
    kReset,
    kSetSurroundingText,
    kSetContentType,
    kSetInputType,
    kSetCursorRectangle,
    // Requests on a text_input_extension object
    kExtensionDestroy,
    kSetSurroundingTextSupport,
  };

  Request(int text_input_id, RequestType type)
      : text_input_id_(text_input_id), type_(type) {}
  virtual ~Request();
  virtual bool RequestMatches(const Request& actual) const;
  virtual void Print(std::ostream& stream) const;

 private:
  friend std::ostream& operator<<(std::ostream& stream, const Request& request);
  int text_input_id_;
  RequestType type_;
};

std::ostream& operator<<(std::ostream& stream, const Request& request);

class SetContentTypeRequest : public Request {
 public:
  SetContentTypeRequest(int text_input_id, uint32_t hints, uint32_t purpose);
  ~SetContentTypeRequest() override;
  bool RequestMatches(const Request& actual) const override;
  void Print(std::ostream& stream) const override;

 private:
  uint32_t hints_;
  uint32_t purpose_;
};

class SetInputTypeRequest : public Request {
 public:
  SetInputTypeRequest(int text_input_id,
                      uint32_t input_type,
                      uint32_t input_mode,
                      uint32_t input_flags,
                      uint32_t learning_mode,
                      uint32_t inline_composition_support);
  ~SetInputTypeRequest() override;
  bool RequestMatches(const Request& actual) const override;
  void Print(std::ostream& stream) const override;

 private:
  uint32_t input_type_;
  uint32_t input_mode_;
  uint32_t input_flags_;
  uint32_t learning_mode_;
  uint32_t inline_composition_support_;
};

class SetSurroundingTextRequest : public Request {
 public:
  SetSurroundingTextRequest(int text_input_id,
                            const std::string& text,
                            uint32_t cursor,
                            uint32_t anchor);
  ~SetSurroundingTextRequest() override;
  bool RequestMatches(const Request& actual) const override;
  void Print(std::ostream& stream) const override;

 private:
  std::string text_;
  uint32_t cursor_;
  uint32_t anchor_;
};

class SetSurroundingTextSupportRequest : public Request {
 public:
  SetSurroundingTextSupportRequest(int text_input_id, uint32_t support);
  ~SetSurroundingTextSupportRequest() override;
  bool RequestMatches(const Request& actual) const override;
  void Print(std::ostream& stream) const override;

 private:
  uint32_t support_;
};

}  // namespace test
}  // namespace cros_im

#endif  // VM_TOOLS_CROS_IM_BACKEND_TEST_REQUEST_H_
