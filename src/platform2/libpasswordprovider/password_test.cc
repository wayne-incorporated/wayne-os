// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libpasswordprovider/password.h"

#include <string>

#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <gtest/gtest.h>

namespace password_provider {

namespace {

// Write the given data to a pipe. Returns the read end of the pipe.
base::ScopedFD WriteSizeAndDataToPipe(const std::string& data) {
  int pipe[2];
  EXPECT_TRUE(base::CreateLocalNonBlockingPipe(pipe));
  base::ScopedFD read_pipe(pipe[0]);
  base::ScopedFD write_pipe(pipe[1]);
  EXPECT_TRUE(base::WriteFileDescriptor(write_pipe.get(), data));
  return read_pipe;
}

}  // namespace

// Basic memory allocation should succeed.
TEST(Password, CreatePasswordWithMemoryAllocation) {
  Password password;
  EXPECT_TRUE(password.Init());

  // Expect Password buffer size to be 1 page minus 1 byte reserved for the null
  // terminator
  size_t page_size = sysconf(_SC_PAGESIZE);
  EXPECT_EQ(page_size - 1, password.max_size());

  EXPECT_EQ(0, password.size());

  EXPECT_TRUE(password.GetRaw());
}

// Creating a Password object without memory allocation should do nothing.
TEST(Password, CreatePasswordWithNoMemoryAllocation) {
  Password password;
  EXPECT_EQ(0, password.size());
  EXPECT_EQ(0, password.max_size());
  // Should not segfault due to freeing memory not allocated.
}

TEST(Password, CreatePasswordFromFileDescriptor) {
  const std::string kTestStringPassword("mypassword");
  auto fd = WriteSizeAndDataToPipe(kTestStringPassword);
  EXPECT_NE(-1, fd);

  auto password =
      Password::CreateFromFileDescriptor(fd.get(), kTestStringPassword.size());
  ASSERT_TRUE(password);
  EXPECT_EQ(kTestStringPassword.size(), password->size());
  EXPECT_EQ(0, strncmp(kTestStringPassword.c_str(), password->GetRaw(),
                       password->size()));
}

TEST(Password, CreatePasswordGreaterThanMaxSize) {
  const std::string kTestStringPassword("mypassword");
  auto fd = WriteSizeAndDataToPipe(kTestStringPassword);
  EXPECT_NE(-1, fd);

  // (page size - 1) is the max size of the Password buffer.
  size_t page_size = sysconf(_SC_PAGESIZE);
  auto password = Password::CreateFromFileDescriptor(fd.get(), page_size);
  EXPECT_EQ(nullptr, password);
}

}  // namespace password_provider
