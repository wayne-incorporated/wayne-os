// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/fake_cryptohome.h"

#include <string>
#include <utility>

#include <base/files/file_path.h>

#include "brillo/cryptohome.h"

namespace brillo::cryptohome::home {

FakeSystemSaltLoader::FakeSystemSaltLoader(std::string value) {
  value_ = std::move(value);
}

FakeSystemSaltLoader::FakeSystemSaltLoader(base::FilePath file_path)
    : SystemSaltLoader(std::move(file_path)) {}

FakeSystemSaltLoader::~FakeSystemSaltLoader() = default;

}  // namespace brillo::cryptohome::home
