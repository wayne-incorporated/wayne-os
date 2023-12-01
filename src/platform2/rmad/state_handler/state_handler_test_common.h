// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_STATE_HANDLER_STATE_HANDLER_TEST_COMMON_H_
#define RMAD_STATE_HANDLER_STATE_HANDLER_TEST_COMMON_H_

#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <base/memory/scoped_refptr.h>
#include <gtest/gtest.h>

#include "rmad/daemon/daemon_callback.h"
#include "rmad/utils/json_store.h"

namespace rmad {

class StateHandlerTest : public testing::Test {
 public:
  const base::FilePath& GetTempDirPath() const { return temp_dir_.GetPath(); }
  const base::FilePath& GetStateFilePath() const { return file_path_; }

 protected:
  void SetUp() override;

  base::ScopedTempDir temp_dir_;
  base::FilePath file_path_;
  scoped_refptr<JsonStore> json_store_;
  scoped_refptr<DaemonCallback> daemon_callback_;
};

}  // namespace rmad

#endif  // RMAD_STATE_HANDLER_STATE_HANDLER_TEST_COMMON_H_
