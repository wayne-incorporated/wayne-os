// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "init/process_killer/process.h"

#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <re2/re2.h>

namespace init {

std::vector<ActiveMount> GetSampleMounts() {
  return {
      {base::FilePath("/a"), base::FilePath("/b"), "foo1"},
      {base::FilePath("/c"), base::FilePath("/d"), "bar"},
      {base::FilePath("/e"), base::FilePath("/f"), "foobar"},
      {base::FilePath("/x"), base::FilePath("/y"), "baz"},
  };
}

std::vector<OpenFileDescriptor> GetSampleFds() {
  return {
      {base::FilePath("/a/b/c")},
      {base::FilePath("/a/b")},
      {base::FilePath("/e/f/g")},
      {base::FilePath("/x")},
  };
}

TEST(Process, ProcessOpenFileOnMountTest) {
  ActiveProcess p(1, true, "foo", GetSampleMounts(), GetSampleFds());
  EXPECT_TRUE(p.HasFileOpenOnMount(re2::RE2("/a")));
  EXPECT_TRUE(p.HasFileOpenOnMount(re2::RE2("/e")));
  EXPECT_FALSE(p.HasFileOpenOnMount(re2::RE2("/d")));
}

TEST(Process, ProcessOpenMountFromDeviceTest) {
  ActiveProcess p(1, true, "foo", GetSampleMounts(), GetSampleFds());
  EXPECT_TRUE(p.HasMountOpenFromDevice(re2::RE2("foo")));
  EXPECT_TRUE(p.HasMountOpenFromDevice(re2::RE2("bar")));
  EXPECT_TRUE(p.HasMountOpenFromDevice(re2::RE2("baz")));
  EXPECT_FALSE(p.HasMountOpenFromDevice(re2::RE2("abcd")));
}

}  // namespace init
