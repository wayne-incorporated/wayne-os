// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SECANOMALYD_SYSTEM_CONTEXT_MOCK_H_
#define SECANOMALYD_SYSTEM_CONTEXT_MOCK_H_

#include "secanomalyd/system_context.h"

#include <set>

#include <base/files/file_path.h>

#include <gmock/gmock.h>

class SystemContextMock : public SystemContext {
 public:
  explicit SystemContextMock(bool logged_in,
                             std::set<base::FilePath> known_mounts) {
    set_logged_in(logged_in);
    set_previous_known_mounts(known_mounts);
  }

  MOCK_METHOD(void, Refresh, (), (override));
};

#endif  // SECANOMALYD_SYSTEM_CONTEXT_MOCK_H_
