// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/fake_platform/fake_fake_mount_mapping_redirect_factory.h"

#include <list>

#include <base/files/file_path.h>

namespace cryptohome {

FakeFakeMountMappingRedirectFactory::FakeFakeMountMappingRedirectFactory(
    std::list<base::FilePath> redirects)
    : redirects_(redirects) {}

base::FilePath FakeFakeMountMappingRedirectFactory::Create() {
  base::FilePath result;
  if (redirects_.size() > 0) {
    result = redirects_.front();
    redirects_.pop_front();
  } else {
    result = base::FilePath("SETMEUP");
  }
  return result;
}

}  // namespace cryptohome
