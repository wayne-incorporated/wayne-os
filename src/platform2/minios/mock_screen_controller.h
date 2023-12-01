// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_MOCK_SCREEN_CONTROLLER_H_
#define MINIOS_MOCK_SCREEN_CONTROLLER_H_

#include <gmock/gmock.h>
#include <minios/proto_bindings/minios.pb.h>

#include "minios/screen_controller_interface.h"
#include "minios/screen_interface.h"
#include "minios/screen_types.h"

namespace minios {

class MockScreenControllerInterface : public ScreenControllerInterface {
 public:
  MockScreenControllerInterface() = default;
  ~MockScreenControllerInterface() = default;

  MockScreenControllerInterface(const MockScreenControllerInterface&) = delete;
  MockScreenControllerInterface& operator=(
      const MockScreenControllerInterface&) = delete;

  MOCK_METHOD(void, SwitchLocale, (ScreenInterface * screen));
  MOCK_METHOD(void, UpdateLocale, (ScreenInterface * screen, int locale_index));
  MOCK_METHOD(void, OnForward, (ScreenInterface * screen));
  MOCK_METHOD(void, OnBackward, (ScreenInterface * screen));
  MOCK_METHOD(void, OnError, (ScreenType error_screen));
  MOCK_METHOD(void, OnStateChanged, (State state));
  MOCK_METHOD(ScreenType, GetCurrentScreen, ());
};

}  // namespace minios

#endif  // MINIOS_MOCK_SCREEN_CONTROLLER_H_
