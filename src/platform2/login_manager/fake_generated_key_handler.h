// Copyright (c) 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_FAKE_GENERATED_KEY_HANDLER_H_
#define LOGIN_MANAGER_FAKE_GENERATED_KEY_HANDLER_H_

#include "login_manager/key_generator.h"

#include <string>

#include <base/files/file_path.h>

namespace login_manager {

class FakeGeneratedKeyHandler : public KeyGenerator::Delegate {
 public:
  FakeGeneratedKeyHandler();
  FakeGeneratedKeyHandler(const FakeGeneratedKeyHandler&) = delete;
  FakeGeneratedKeyHandler& operator=(const FakeGeneratedKeyHandler&) = delete;

  ~FakeGeneratedKeyHandler() override;

  const std::string& key_username() { return key_username_; }
  const std::string& key_contents() { return key_contents_; }

  // Overridden from KeyGenerator::Delegate
  void OnKeyGenerated(const std::string& username,
                      const base::FilePath& temp_key_file) override;

 private:
  std::string key_username_;
  std::string key_contents_;
};
}  // namespace login_manager

#endif  // LOGIN_MANAGER_FAKE_GENERATED_KEY_HANDLER_H_
