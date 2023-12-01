// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include <base/json/json_reader.h>
#include <gtest/gtest.h>

#include "runtime_probe/utils/function_test_utils.h"
#include "runtime_probe/utils/pipe_utils.h"

namespace runtime_probe {
namespace {

using ::testing::_;
using ::testing::ElementsAre;
using ::testing::Return;

class PipeUtilsTest : public BaseFunctionTest {};

TEST_F(PipeUtilsTest, ReadNonblockingPipeToString_Success) {
  const int kFd1 = 3;
  const int kFd2 = 5;
  std::vector<int> fds = {kFd1, kFd2};
  std::vector<std::string> out;

  auto syscaller = mock_context()->mock_syscaller();
  EXPECT_CALL(*syscaller, Select)
      .WillOnce([&kFd1, &kFd2](int nfds, fd_set* read_fds, auto, auto, auto) {
        EXPECT_EQ(nfds, std::max(kFd1, kFd2) + 1);
        EXPECT_TRUE(FD_ISSET(kFd1, read_fds));
        EXPECT_TRUE(FD_ISSET(kFd2, read_fds));
        // Set The file descriptor |kFd1| not ready.
        FD_CLR(kFd1, read_fds);
        return 1;
      })
      .WillOnce([&kFd1, &kFd2](int nfds, fd_set* read_fds, auto, auto, auto) {
        EXPECT_EQ(nfds, std::max(kFd1, kFd2) + 1);
        EXPECT_TRUE(FD_ISSET(kFd1, read_fds));
        EXPECT_TRUE(FD_ISSET(kFd2, read_fds));
        // Both the file descriptors are ready.
        return 2;
      })
      .WillOnce([&kFd1, &kFd2](int nfds, fd_set* read_fds, auto, auto, auto) {
        EXPECT_EQ(nfds, std::max(kFd1, kFd2) + 1);
        EXPECT_TRUE(FD_ISSET(kFd1, read_fds));
        EXPECT_TRUE(FD_ISSET(kFd2, read_fds));
        // Both the file descriptors are ready.
        return 2;
      })
      .WillOnce([](int nfds, fd_set* read_fds, auto, auto, auto) {
        // |kFd2| was not set because it has already been read completely.
        EXPECT_EQ(nfds, kFd1 + 1);
        EXPECT_TRUE(FD_ISSET(kFd1, read_fds));
        EXPECT_FALSE(FD_ISSET(kFd2, read_fds));
        return 1;
      });

  // Read from file descriptor |kFd1|.
  EXPECT_CALL(*syscaller, Read(kFd1, _, _))
      .WillOnce([](int fd, void* buffer, auto) {
        char res[] = {'1', '2', '3', '4'};
        std::copy(res, res + sizeof(res), reinterpret_cast<char*>(buffer));
        return sizeof(res);
      })
      .WillOnce([](int fd, void* buffer, auto) {
        char res[] = {'5', '6', '7', '8'};
        std::copy(res, res + sizeof(res), reinterpret_cast<char*>(buffer));
        return sizeof(res);
      })
      .WillOnce(Return(0));

  // Read from file descriptor |kFd2|.
  EXPECT_CALL(*syscaller, Read(kFd2, _, _))
      .WillOnce([](int fd, void* buffer, auto) {
        char res[] = {'a', 'b', 'c'};
        std::copy(res, res + sizeof(res), reinterpret_cast<char*>(buffer));
        return sizeof(res);
      })
      .WillOnce([](int fd, void* buffer, auto) {
        char res[] = {'d', 'e', 'f'};
        std::copy(res, res + sizeof(res), reinterpret_cast<char*>(buffer));
        return sizeof(res);
      })
      .WillOnce(Return(0));

  EXPECT_TRUE(ReadNonblockingPipeToString(fds, &out));
  EXPECT_THAT(out, ElementsAre("12345678", "abcdef"));
}

TEST_F(PipeUtilsTest, ReadNonblockingPipeToString_ReadFailed) {
  const int kFd1 = 3;
  const int kFd2 = 5;
  std::vector<int> fds = {kFd1, kFd2};
  std::vector<std::string> out;

  auto syscaller = mock_context()->mock_syscaller();
  EXPECT_CALL(*syscaller, Select).WillOnce(Return(2));
  // Return -1 on read() failure.
  EXPECT_CALL(*syscaller, Read).WillOnce(Return(-1));

  EXPECT_FALSE(ReadNonblockingPipeToString(fds, &out));
  EXPECT_THAT(out, ElementsAre("", ""));
}

TEST_F(PipeUtilsTest, ReadNonblockingPipeToString_SelectTimeOut) {
  const int kFd1 = 3;
  const int kFd2 = 5;
  std::vector<int> fds = {kFd1, kFd2};
  std::vector<std::string> out;

  auto syscaller = mock_context()->mock_syscaller();
  // Return 0 on select() timeout.
  EXPECT_CALL(*syscaller, Select).WillOnce(Return(0));

  EXPECT_FALSE(ReadNonblockingPipeToString(fds, &out));
  EXPECT_THAT(out, ElementsAre("", ""));
}

TEST_F(PipeUtilsTest, ReadNonblockingPipeToString_SelectFailed) {
  const int kFd1 = 3;
  const int kFd2 = 5;
  std::vector<int> fds = {kFd1, kFd2};
  std::vector<std::string> out;

  auto syscaller = mock_context()->mock_syscaller();
  // Return -1 on select() failure.
  EXPECT_CALL(*syscaller, Select).WillOnce(Return(-1));

  EXPECT_FALSE(ReadNonblockingPipeToString(fds, &out));
  EXPECT_THAT(out, ElementsAre("", ""));
}

}  // namespace
}  // namespace runtime_probe
