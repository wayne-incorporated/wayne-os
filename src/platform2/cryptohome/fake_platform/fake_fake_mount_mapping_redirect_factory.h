// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_FAKE_PLATFORM_FAKE_FAKE_MOUNT_MAPPING_REDIRECT_FACTORY_H_
#define CRYPTOHOME_FAKE_PLATFORM_FAKE_FAKE_MOUNT_MAPPING_REDIRECT_FACTORY_H_

#include <list>

#include <base/files/file_path.h>

#include "cryptohome/fake_platform/fake_mount_mapping_redirect_factory.h"

namespace cryptohome {

// Fake implementation of the factory, which returns the items out of the list
// it was constructed with.
class FakeFakeMountMappingRedirectFactory final
    : public FakeMountMappingRedirectFactory {
 public:
  explicit FakeFakeMountMappingRedirectFactory(std::list<base::FilePath>);
  ~FakeFakeMountMappingRedirectFactory() override = default;

  base::FilePath Create() override;

 private:
  std::list<base::FilePath> redirects_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_FAKE_PLATFORM_FAKE_FAKE_MOUNT_MAPPING_REDIRECT_FACTORY_H_
