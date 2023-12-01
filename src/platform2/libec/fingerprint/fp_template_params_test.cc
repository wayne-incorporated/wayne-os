// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>
#include "libec/fingerprint/fp_template_params.h"

namespace ec {
namespace {

TEST(FpTemplateParams, HeaderSize) {
  EXPECT_EQ(sizeof(fp_template::Header), sizeof(ec_params_fp_template));
}

TEST(FpTemplateParams, ParamsSize) {
  EXPECT_EQ(sizeof(fp_template::Params), kMaxPacketSize);
}

}  // namespace
}  // namespace ec
