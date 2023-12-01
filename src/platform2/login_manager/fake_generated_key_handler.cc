// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/fake_generated_key_handler.h"

#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <gtest/gtest.h>

namespace login_manager {

FakeGeneratedKeyHandler::FakeGeneratedKeyHandler() {}

FakeGeneratedKeyHandler::~FakeGeneratedKeyHandler() {}

void FakeGeneratedKeyHandler::OnKeyGenerated(
    const std::string& username, const base::FilePath& temp_key_file) {
  key_username_ = username;
  if (!base::ReadFileToString(temp_key_file, &key_contents_))
    ADD_FAILURE() << temp_key_file.value() << " could not be read.";
}

}  // namespace login_manager
