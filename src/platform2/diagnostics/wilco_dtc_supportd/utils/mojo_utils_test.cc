// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/utils/mojo_utils.h"

#include <memory>
#include <utility>

#include <base/strings/string_piece.h>
#include <gtest/gtest.h>
#include <mojo/core/embedder/embedder.h>
#include <mojo/public/cpp/system/handle.h>

namespace diagnostics {
namespace wilco {
namespace {

TEST(MojoUtilsTest, CreateMojoHandleAndRetrieveContent) {
  const base::StringPiece content("{\"key\": \"value\"}");

  mojo::ScopedHandle handle =
      CreateReadOnlySharedMemoryRegionMojoHandle(content);
  EXPECT_TRUE(handle.is_valid());

  auto shm_mapping =
      GetReadOnlySharedMemoryMappingFromMojoHandle(std::move(handle));
  ASSERT_TRUE(shm_mapping.IsValid());

  base::StringPiece actual(shm_mapping.GetMemoryAs<char>(),
                           shm_mapping.mapped_size());
  EXPECT_EQ(content, actual);
}

TEST(MojoUtilsTest, GetReadOnlySharedMemoryRegionFromMojoInvalidHandle) {
  mojo::ScopedHandle handle;
  EXPECT_FALSE(handle.is_valid());

  auto shm_mapping =
      GetReadOnlySharedMemoryMappingFromMojoHandle(std::move(handle));
  EXPECT_FALSE(shm_mapping.IsValid());
}

TEST(MojoUtilsTest, CreateReadOnlySharedMemoryFromEmptyContent) {
  mojo::ScopedHandle handle = CreateReadOnlySharedMemoryRegionMojoHandle("");
  // Cannot create valid handle using empty content line.
  EXPECT_FALSE(handle.is_valid());
}

}  // namespace
}  // namespace wilco
}  // namespace diagnostics
