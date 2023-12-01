// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/util/lease.h"

#include <memory>
#include <string>

#include <absl/status/status.h>
#include <base/test/bind.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace faced {

TEST(Lease, TestOnDestroy) {
  std::string something("hello");

  bool destroyed = false;
  std::unique_ptr<Lease<std::string>> lease =
      std::make_unique<Lease<std::string>>(
          &something, base::BindLambdaForTesting([&] { destroyed = true; }));

  lease.reset();

  EXPECT_TRUE(destroyed);
}

}  // namespace faced
