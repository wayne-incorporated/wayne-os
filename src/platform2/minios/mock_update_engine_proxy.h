// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_MOCK_UPDATE_ENGINE_PROXY_H_
#define MINIOS_MOCK_UPDATE_ENGINE_PROXY_H_

#include <gmock/gmock.h>

#include "minios/update_engine_proxy.h"

namespace minios {

class MockUpdateEngineProxy : public UpdateEngineProxy {
 public:
  MockUpdateEngineProxy() : UpdateEngineProxy(nullptr) {}

  MockUpdateEngineProxy(const MockUpdateEngineProxy&) = delete;
  MockUpdateEngineProxy& operator=(const MockUpdateEngineProxy&) = delete;

  MOCK_METHOD(void, Init, (), (override));
  MOCK_METHOD(void, SetDelegate, (UpdaterDelegate * delegate), (override));
  MOCK_METHOD(void, TriggerReboot, (), (override));
  MOCK_METHOD(bool, StartUpdate, (), (override));
};

}  // namespace minios

#endif  // MINIOS_MOCK_UPDATE_ENGINE_PROXY_H_
