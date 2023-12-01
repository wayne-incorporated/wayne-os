// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "discod/controls/file_based_binary_control.h"

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

#include "discod/controls/binary_control.h"
#include "discod/utils/libhwsec_status_import.h"

namespace discod {
namespace {

class FileBasedBinaryControlTest : public ::testing::Test {
 public:
  FileBasedBinaryControlTest() {
    std::ignore = tmp_dir_.CreateUniqueTempDir();
    control_node_ = tmp_dir_.GetPath().Append("control_node");
  }
  ~FileBasedBinaryControlTest() override {
    std::ignore = base::DeleteFile(control_node_);
  }

 protected:
  base::ScopedTempDir tmp_dir_;
  base::FilePath control_node_;
};

}  // namespace

TEST_F(FileBasedBinaryControlTest, ToggleFails) {
  FileBasedBinaryControl control(base::FilePath("/tmp"));
  EXPECT_THAT(control.Toggle(BinaryControl::State::kOn), NotOk());
  EXPECT_THAT(control.Toggle(BinaryControl::State::kOff), NotOk());
}

TEST_F(FileBasedBinaryControlTest, CurrentFails) {
  FileBasedBinaryControl control(control_node_);
  EXPECT_THAT(control.Current(), NotOk());
}

TEST_F(FileBasedBinaryControlTest, Ok) {
  FileBasedBinaryControl control(control_node_);
  EXPECT_THAT(control.Toggle(BinaryControl::State::kOn), IsOk());
  EXPECT_THAT(control.Current().value(), BinaryControl::State::kOn);
  EXPECT_THAT(control.Toggle(BinaryControl::State::kOff), IsOk());
  EXPECT_THAT(control.Current().value(), BinaryControl::State::kOff);
}

}  // namespace discod
