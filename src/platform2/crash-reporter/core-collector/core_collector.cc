// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sysexits.h>
#include <unistd.h>

#include <iomanip>
#include <iostream>
#include <map>
#include <string>

#include <client/linux/minidump_writer/linux_core_dumper.h>
#include <client/linux/minidump_writer/minidump_writer.h>

#include "crash-reporter/core-collector/coredump_writer.h"
#include "crash-reporter/core-collector/logging.h"

namespace {

struct Flag {
  std::string description;
  std::string value;
};

using Flags = std::map<std::string, Flag>;

const char kCoreSwitch[] = "--coredump";
const char kDumpSwitch[] = "--minidump";
const char kHelpSwitch[] = "--help";
const char kPrefixSwitch[] = "--prefix";
const char kProcSwitch[] = "--proc";

void PrintUsage(const Flags& flags);
bool ParseFlags(int argc, char* argv[], Flags* flags);

}  // namespace

const char* g_exec_name;

int main(int argc, char* argv[]) {
  g_exec_name = argv[0];

  Flags flags = {
      {kCoreSwitch, {"Stripped core dump", "core"}},
      {kDumpSwitch, {"Output minidump", "dump"}},
      {kPrefixSwitch, {"Root directory to which .so paths are relative", ""}},
      {kProcSwitch, {"Temporary directory for generated proc files", "/tmp"}},
  };

  if (argc == 2 && std::string(argv[1]) == kHelpSwitch) {
    PrintUsage(flags);
    return EX_OK;
  }

  if (!ParseFlags(argc, argv, &flags)) {
    LOG_ERROR << "See '" << g_exec_name << ' ' << kHelpSwitch << "' for usage";
    return EX_USAGE;
  }

  if (isatty(STDIN_FILENO)) {
    LOG_ERROR << "Core dump must be piped to standard input";
    return EX_USAGE;
  }

  const char *const core = flags.find(kCoreSwitch)->second.value.c_str(),
                    *const proc = flags.find(kProcSwitch)->second.value.c_str();

  CoredumpWriter writer(STDIN_FILENO, core, proc);
  const int error = writer.WriteCoredump();
  if (error != EX_OK) {
    LOG_ERROR << "Failed to write stripped core dump";
    return error;
  }

  const char *const dump = flags.find(kDumpSwitch)->second.value.c_str(),
                    *const prefix =
                        flags.find(kPrefixSwitch)->second.value.c_str();

  google_breakpad::MappingList mappings;
  google_breakpad::AppMemoryList memory_list;
  google_breakpad::LinuxCoreDumper dumper(/* unused */ -1, core, proc, prefix);
  if (!WriteMinidump(dump, mappings, memory_list, &dumper)) {
    LOG_ERROR << "Failed to convert core dump to minidump";
    return EX_SOFTWARE;
  }

  return EX_OK;
}

namespace {

void PrintUsage(const Flags& flags) {
  std::cout << "Generate minidump from core dump piped to standard input.\n"
            << std::endl;

  for (const auto& flag : flags)
    std::cout << std::setw(12) << flag.first << "  " << flag.second.description
              << " (default: \"" << flag.second.value << "\")" << std::endl;
}

bool ParseFlags(int argc, char* argv[], Flags* flags) {
  for (int i = 1; i < argc; ++i) {
    const char* const flag = argv[i];
    const auto it = flags->find(flag);

    if (it == flags->end()) {
      LOG_ERROR << "Invalid flag '" << flag << "'";
      return false;
    }

    if (++i == argc) {
      LOG_ERROR << "Missing value for flag '" << flag << "'";
      return false;
    }

    it->second.value = argv[i];
  }

  return true;
}

}  // namespace
