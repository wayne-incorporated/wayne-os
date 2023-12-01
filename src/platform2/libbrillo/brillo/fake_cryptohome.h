// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_FAKE_CRYPTOHOME_H_
#define LIBBRILLO_BRILLO_FAKE_CRYPTOHOME_H_

#include <string>

#include <base/files/file_path.h>

#include "brillo/cryptohome.h"

namespace brillo::cryptohome::home {

// Allows to inject fake system salt in tests. On creation, initializes the
// global singleton returned by `SystemSaltLoader::GetInstance()`.
class BRILLO_EXPORT FakeSystemSaltLoader : public SystemSaltLoader {
 public:
  // Creates a loader with the specified injected salt. No file operations are
  // performed by the loader in this case.
  explicit FakeSystemSaltLoader(std::string value);
  // Creates a loader with the specified overridden file path.
  explicit FakeSystemSaltLoader(base::FilePath file_path);

  ~FakeSystemSaltLoader() override;
};

}  // namespace brillo::cryptohome::home

#endif  // LIBBRILLO_BRILLO_FAKE_CRYPTOHOME_H_
