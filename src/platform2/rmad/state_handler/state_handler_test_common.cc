// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/state_handler/state_handler_test_common.h"

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/memory/scoped_refptr.h>

#include "rmad/utils/json_store.h"

namespace rmad {

namespace {

constexpr char kTestJsonStoreFileName[] = "test_json_store_file";
constexpr char kTestEmptyJsonStore[] = "{}";

scoped_refptr<JsonStore> CreateTestEmptyJsonStore(
    const base::FilePath& file_path) {
  base::WriteFile(file_path, kTestEmptyJsonStore,
                  std::size(kTestEmptyJsonStore) - 1);
  return base::MakeRefCounted<JsonStore>(file_path);
}

}  // namespace

void StateHandlerTest::SetUp() {
  ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
  file_path_ = temp_dir_.GetPath().AppendASCII(kTestJsonStoreFileName);
  json_store_ = CreateTestEmptyJsonStore(file_path_);
  daemon_callback_ = base::MakeRefCounted<DaemonCallback>();
}

}  // namespace rmad
