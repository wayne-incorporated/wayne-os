// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_MOCK_SCREEN_INTERFACE_H_
#define MINIOS_MOCK_SCREEN_INTERFACE_H_

#include <string>

#include <brillo/errors/error.h>
#include <gmock/gmock.h>
#include <minios/proto_bindings/minios.pb.h>

#include "minios/screen_interface.h"
#include "minios/screen_types.h"

namespace minios {

class MockScreenInterface : public ScreenInterface {
 public:
  MockScreenInterface() = default;
  ~MockScreenInterface() = default;

  MockScreenInterface(const MockScreenInterface&) = delete;
  MockScreenInterface& operator=(const MockScreenInterface&) = delete;

  MOCK_METHOD(void, Show, ());
  MOCK_METHOD(void, OnKeyPress, (int key_changed));
  MOCK_METHOD(void, Reset, ());
  MOCK_METHOD(ScreenType, GetType, ());
  MOCK_METHOD(std::string, GetName, ());
  MOCK_METHOD(State, GetState, ());
  MOCK_METHOD(bool, MoveForward, (brillo::ErrorPtr * err));
  MOCK_METHOD(bool, MoveBackward, (brillo::ErrorPtr * err));
};

}  // namespace minios

#endif  // MINIOS_MOCK_SCREEN_INTERFACE_H_
