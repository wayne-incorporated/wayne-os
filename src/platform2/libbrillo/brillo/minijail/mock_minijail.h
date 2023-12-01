// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_MINIJAIL_MOCK_MINIJAIL_H_
#define LIBBRILLO_BRILLO_MINIJAIL_MOCK_MINIJAIL_H_

#include <vector>

#include <gmock/gmock.h>

#include "brillo/minijail/minijail.h"

namespace brillo {

class MockMinijail : public brillo::Minijail {
 public:
  MockMinijail() {}
  MockMinijail(const MockMinijail&) = delete;
  MockMinijail& operator=(const MockMinijail&) = delete;

  virtual ~MockMinijail() {}

  MOCK_METHOD(struct minijail*, New, (), (override));
  MOCK_METHOD(void, Destroy, (struct minijail*), (override));

  MOCK_METHOD(bool,
              DropRoot,
              (struct minijail*, const char*, const char*),
              (override));
  MOCK_METHOD(void,
              UseSeccompFilter,
              (struct minijail*, const char*),
              (override));
  MOCK_METHOD(void, UseCapabilities, (struct minijail*, uint64_t), (override));
  MOCK_METHOD(void, ResetSignalMask, (struct minijail*), (override));
  MOCK_METHOD(void, CloseOpenFds, (struct minijail*), (override));
  MOCK_METHOD(void, PreserveFd, (struct minijail*, int, int), (override));
  MOCK_METHOD(void, Enter, (struct minijail*), (override));
  MOCK_METHOD(bool,
              Run,
              (struct minijail*, std::vector<char*>, pid_t*),
              (override));
  MOCK_METHOD(bool,
              RunSync,
              (struct minijail*, std::vector<char*>, int*),
              (override));
  MOCK_METHOD(bool,
              RunPipes,
              (struct minijail*, std::vector<char*>, pid_t*, int*, int*, int*),
              (override));
  MOCK_METHOD(bool,
              RunEnvPipes,
              (struct minijail*,
               std::vector<char*>,
               std::vector<char*>,
               pid_t*,
               int*,
               int*,
               int*),
              (override));
  MOCK_METHOD(bool,
              RunAndDestroy,
              (struct minijail*, std::vector<char*>, pid_t*),
              (override));
  MOCK_METHOD(bool,
              RunSyncAndDestroy,
              (struct minijail*, std::vector<char*>, int*),
              (override));
  MOCK_METHOD(bool,
              RunPipeAndDestroy,
              (struct minijail*, std::vector<char*>, pid_t*, int*),
              (override));
  MOCK_METHOD(bool,
              RunPipesAndDestroy,
              (struct minijail*, std::vector<char*>, pid_t*, int*, int*, int*),
              (override));
  MOCK_METHOD(bool,
              RunEnvPipesAndDestroy,
              (struct minijail*,
               std::vector<char*>,
               std::vector<char*>,
               pid_t*,
               int*,
               int*,
               int*),
              (override));
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_MINIJAIL_MOCK_MINIJAIL_H_
