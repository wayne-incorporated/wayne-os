// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/soda.h"

#include <base/files/file_path.h>
#include <gtest/gtest.h>

TEST(SodaLibraryTest, CannotLoadLibraryAndLookupFunction) {
  // By default, the default instance shouldn't be instantiable since we're in a
  // test and the file shouldn't exist, etc.
  auto* const instance =
      ml::SodaLibrary::GetInstanceAt(base::FilePath("/invalid/path"));
  EXPECT_EQ(instance->GetStatus(), ml::SodaLibrary::Status::kLoadLibraryFailed);
}
