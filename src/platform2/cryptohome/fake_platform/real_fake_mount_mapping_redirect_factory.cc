// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/fake_platform/real_fake_mount_mapping_redirect_factory.h"

#include <base/files/file_path.h>
#include <base/files/file_util.h>

#include "cryptohome/util/get_random_suffix.h"

namespace cryptohome {

base::FilePath RealFakeMountMappingRedirectFactory::Create() {
  base::FilePath redirect;
  base::GetTempDir(&redirect);
  redirect = redirect.Append(GetRandomSuffix());
  CHECK(base::CreateDirectory(redirect));
  return redirect;
}

}  // namespace cryptohome
