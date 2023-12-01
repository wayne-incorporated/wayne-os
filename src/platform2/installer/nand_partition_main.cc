// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A simple utility to remove and add partitions to an MTD device.

#define PROGRAM_NAME "nand_partition"

#include <base/command_line.h>
#include <base/strings/string_number_conversions.h>

#include "installer/nand_partition.h"

using std::string;

namespace {

const char kHelpMessage[] = (PROGRAM_NAME
                             ":\n"
                             "  add <dev> <part_no> <start> <length>\n"
                             "  del <dev> <part_no>\n"
                             "\n"
                             "  both start and length are in bytes.\n");
const char kCommandAdd[] = "add";
const char kCommandDel[] = "del";

int ShowHelp() {
  printf("%s\n", kHelpMessage);
  return 1;
}

}  // namespace

int main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  base::CommandLine* cmdline = base::CommandLine::ForCurrentProcess();

  base::CommandLine::StringVector args = cmdline->GetArgs();
  if (args.size() > 2) {
    int optind = 0;
    string command = args[optind++];
    base::FilePath dev = base::FilePath(args[optind++]);
    string s_part_no = args[optind++];
    int part_no = 0;
    if (!base::StringToInt(s_part_no, &part_no)) {
      return ShowHelp();
    }

    if (command == kCommandDel && args.size() == 3) {
      return (brillo::installer::RemoveNandPartition(dev, part_no)
                  ? EXIT_SUCCESS
                  : EXIT_FAILURE);
    } else if (command == kCommandAdd && args.size() == 5) {
      string s_offset = args[optind++];
      string s_length = args[optind++];

      uint64_t offset, length;
      if (!base::StringToUint64(s_offset, &offset) ||
          !base::StringToUint64(s_length, &length)) {
        return ShowHelp();
      }

      return brillo::installer::AddNandPartition(dev, part_no, offset, length)
                 ? EXIT_SUCCESS
                 : EXIT_FAILURE;
    }
  }

  return ShowHelp();
}
