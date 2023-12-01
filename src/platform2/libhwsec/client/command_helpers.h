// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_CLIENT_COMMAND_HELPERS_H_
#define LIBHWSEC_CLIENT_COMMAND_HELPERS_H_

#include <cstdio>
#include <string>
#include <vector>

#include <base/containers/span.h>

// This file contains some helper functions to create command line tool.
//
// Below is an example command struct:
//
// struct CommandName {
//   static constexpr char name[] = "command_name";
//   static constexpr char args[] = "<Arg1> <Arg2>";
//   static constexpr char desc[] = R"(
//       Some descriptions.
// )";
//   static int Run(const ClientArgs& args) {
//     return EXIT_SUCCESS;
//   }
// };

namespace hwsec {

using ClientArgs = base::span<std::string>;

template <typename Cmd>
inline void PrintCommandUsage() {
  printf("  |%s| %s", Cmd::kName, Cmd::kArgs);
  printf("      %s", Cmd::kDesc);
}

template <typename...>
struct MatchCommands {};

template <typename Usage, typename Cmd, typename... Args>
struct MatchCommands<Usage, Cmd, Args...> {
  static int Run(const ClientArgs& args) {
    if (args[0] == Cmd::kName) {
      return Cmd::Run(args.subspan<1>());
    }
    return MatchCommands<Usage, Args...>::Run(args);
  }
};

template <typename Usage>
struct MatchCommands<Usage> {
  static int Run(const ClientArgs& args) {
    // None of the command matches; print the usage.
    return Usage::Run(args.subspan<1>());
  }
};

}  // namespace hwsec

#endif  // LIBHWSEC_CLIENT_COMMAND_HELPERS_H_
