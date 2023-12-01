/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hardware_verifier/test_utils.h"

#include <cstdlib>
#include <string>

#include <base/check_op.h>
#include <base/logging.h>
#include <base/files/file_util.h>
#include <google/protobuf/text_format.h>
#include <gtest/gtest.h>

#include "hardware_verifier/hardware_verifier.pb.h"

namespace hardware_verifier {

base::FilePath GetTestDataPath() {
  char* src_env = std::getenv("SRC");
  CHECK_NE(src_env, nullptr)
      << "Expect to have the envvar |SRC| set when testing.";
  return base::FilePath(src_env).Append("testdata");
}

HwVerificationReport LoadHwVerificationReport(const base::FilePath& file_path) {
  std::string content;
  EXPECT_TRUE(base::ReadFileToString(file_path, &content));

  HwVerificationReport ret;
  EXPECT_TRUE(google::protobuf::TextFormat::ParseFromString(content, &ret));
  return ret;
}

}  // namespace hardware_verifier
