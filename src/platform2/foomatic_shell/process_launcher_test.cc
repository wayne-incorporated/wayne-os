// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "foomatic_shell/process_launcher.h"
#include "foomatic_shell/parser.h"
#include "foomatic_shell/scanner.h"
#include <gtest/gtest.h>
#include <string>
#include <utility>
#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

namespace foomatic_shell {

TEST(ProcessLauncher, RunScript) {
  const std::string command =
      "somevar=somevalue cat /dev/stdin | (cat | cat) | cat";
  const std::string data = "it is working";
  const size_t data_size = data.size();

  std::vector<Token> tokens;
  Scanner scanner(command);
  ASSERT_TRUE(scanner.ParseWholeInput(&tokens));
  Parser parser(std::move(tokens));
  Script script;
  EXPECT_TRUE(parser.ParseWholeInput(&script));

  ProcessLauncher launcher(command, true);
  int stdin_fd = memfd_create("foomatic-shell-stdin", 0);
  ASSERT_NE(stdin_fd, -1);
  int stdout_fd = memfd_create("foomatic-shell-stdout", 0);
  ASSERT_NE(stdout_fd, -1);
  EXPECT_EQ(write(stdin_fd, data.c_str(), data_size), data_size);
  EXPECT_EQ(lseek(stdin_fd, 0, SEEK_SET), 0);

  EXPECT_EQ(launcher.RunScript(script, stdin_fd, stdout_fd), 0);

  FILE* stdout_fp = fdopen(stdout_fd, "rb");
  ASSERT_NE(stdout_fp, nullptr);
  fseek(stdout_fp, 0, SEEK_SET);
  for (size_t i = 0; i < data_size; i++) {
    EXPECT_EQ(fgetc(stdout_fp), (int)data[i]);
  }
  EXPECT_EQ(fgetc(stdout_fp), EOF);
  fclose(stdout_fp);  // this also closes stdout_fd
  close(stdin_fd);
}

}  // namespace foomatic_shell
