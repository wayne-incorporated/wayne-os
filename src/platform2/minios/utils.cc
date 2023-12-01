// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "minios/utils.h"

#include <cstdio>
#include <memory>
#include <tuple>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_split.h>

#include "minios/minios.h"
#include "minios/process_manager.h"

namespace {
constexpr char kLogConsole[] = "/run/frecon/vt1";
const char kMountStatefulCommand[] = "/usr/bin/stateful_partition_for_recovery";
const char kMountFlag[] = "--mount";
const char kStatefulPath[] = "/stateful";

const char kTarCommand[] = "/usr/bin/tar";
// Compress and archive. Also resolve symlinks.
// Using `gzip` as it's the only installed compress utility on MiniOS.
const char kTarCompressFlags[] = "-czhf";

const std::vector<std::string> kFilesToCompress{
    "/var/log/update_engine.log", "/var/log/upstart.log", "/var/log/messages"};
}  // namespace

namespace minios {

const char kCategoryInit[] = "init";
const char kCategoryReboot[] = "reboot";
const char kCategoryUpdate[] = "update";

const base::FilePath kDefaultArchivePath{"/tmp/logs.tar"};

std::tuple<bool, std::string> ReadFileContentWithinRange(
    const base::FilePath& file_path,
    int64_t start_offset,
    int64_t end_offset,
    int max_columns) {
  base::File f(file_path, base::File::FLAG_OPEN | base::File::FLAG_READ);
  if (!f.IsValid()) {
    PLOG(ERROR) << "Failed to open file " << file_path.value();
    return {false, {}};
  }

  if (f.Seek(base::File::Whence::FROM_BEGIN, start_offset) != start_offset) {
    PLOG(ERROR) << "Failed to seek file " << file_path.value() << " at offset "
                << start_offset;
    return {false, {}};
  }

  int64_t bytes_to_read = end_offset - start_offset;
  std::string content;
  content.reserve(bytes_to_read);

  int current_col = 0;
  while (bytes_to_read-- > 0) {
    char c;
    switch (f.ReadAtCurrentPos(&c, 1)) {
      case -1:
        PLOG(ERROR) << "Failed to read file " << file_path.value();
        return {false, {}};
      case 0:
        // Equivalent of EOF.
        return {true, content};
      default:
        break;
    }
    if (c == '\n') {
      if (content.empty() || content.back() != '\n')
        content.push_back(c);
      current_col = 0;
      continue;
    }
    if (current_col < max_columns) {
      content.push_back(c);
      if (++current_col >= max_columns) {
        content.push_back('\n');
        current_col = 0;
      }
    }
  }
  return {true, content};
}

std::tuple<bool, std::string, int64_t> ReadFileContent(
    const base::FilePath& file_path,
    int64_t offset,
    int num_lines,
    int num_cols) {
  base::File f(file_path, base::File::FLAG_OPEN | base::File::FLAG_READ);
  if (!f.IsValid())
    return {false, {}, 0};

  if (f.Seek(base::File::Whence::FROM_BEGIN, offset) == -1)
    return {false, {}, 0};

  char c;
  std::string content;
  content.reserve(num_lines * num_cols);
  int64_t bytes_read = 0;
  int current_line = 0, current_col = 0, read_buffer_lines = 0;
  while (f.ReadAtCurrentPos(&c, 1) > 0 && read_buffer_lines < num_lines) {
    ++bytes_read;
    if (c == '\n') {
      // Skip double newlining.
      if (content.back() != '\n') {
        content.push_back(c);
        ++read_buffer_lines;
      }
      current_col = 0;
      ++current_line;
      continue;
    }
    if (current_col < num_cols) {
      content.push_back(c);
      if (++current_col >= num_cols) {
        content.push_back('\n');
        current_col = 0;
        ++read_buffer_lines;
      }
    }
  }
  return {true, content, bytes_read};
}

bool GetCrosRegionData(ProcessManagerInterface* process_manager,
                       std::string key,
                       std::string* value) {
  int exit_code = 0;
  std::string error, xkb_keyboard;
  // Get the first item in the keyboard list for a given region.
  if (!process_manager->RunCommandWithOutput(
          {"/usr/bin/cros_region_data", "-s", key}, &exit_code, value,
          &error) ||
      exit_code) {
    LOG(ERROR) << "Could not get " << key << " region data. Exit code "
               << exit_code << " with error " << error;
    *value = "";
    return false;
  }
  return true;
}

bool TriggerShutdown() {
  ProcessManager process_manager;
  base::FilePath console = GetLogConsole();
  if (process_manager.RunCommand({"/sbin/poweroff", "-f"},
                                 ProcessManager::IORedirection{
                                     .input = console.value(),
                                     .output = console.value(),
                                 })) {
    LOG(ERROR) << "Could not trigger shutdown";
    return false;
  }
  LOG(INFO) << "Shutdown requested.";
  return true;
}

std::string GetKeyboardLayout(ProcessManagerInterface* process_manager) {
  std::string keyboard_layout;
  if (!GetCrosRegionData(process_manager, "keyboards", &keyboard_layout)) {
    LOG(WARNING) << "Could not get region data. Defaulting to 'us'.";
    return "us";
  }
  // Get the country code from the full keyboard string (i.e xkb:us::eng).
  const auto& keyboard_parts = base::SplitString(
      keyboard_layout, ":", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  if (keyboard_parts.size() < 2 || keyboard_parts[1].size() < 2) {
    LOG(WARNING) << "Could not get country code from " << keyboard_layout
                 << " Defaulting to 'us'.";
    return "us";
  }
  return keyboard_parts[1];
}

base::FilePath GetLogConsole() {
  static base::FilePath target;

  if (target.empty()) {
    base::FilePath log_console(kLogConsole);
    if (!base::ReadSymbolicLink(log_console, &target)) {
      target = log_console;
    }
  }

  return target;
}

bool MountStatefulPartition(ProcessManagerInterface* process_manager) {
  if (base::PathExists(base::FilePath{kStatefulPath})) {
    LOG(INFO) << "Stateful already mounted";
    return true;
  }
  if (!process_manager) {
    PLOG(WARNING) << "Invalid process manager";
    return false;
  }
  base::FilePath console = GetLogConsole();
  if (process_manager->RunCommand({kMountStatefulCommand, kMountFlag},
                                  ProcessManager::IORedirection{
                                      .input = console.value(),
                                      .output = console.value(),
                                  }) != 0) {
    PLOG(WARNING) << "Failed to mount stateful partition";
    return false;
  }
  return true;
}
int CompressLogs(std::unique_ptr<ProcessManagerInterface> process_manager,
                 const base::FilePath& archive_path) {
  // Note: These are the explicit set of logs that are approved by privacy team.
  // Adding files to this list would require clearance from Privacy team.
  std::vector<std::string> compress_command = {kTarCommand, kTarCompressFlags,
                                               archive_path.value()};
  compress_command.insert(compress_command.end(), kFilesToCompress.begin(),
                          kFilesToCompress.end());
  base::FilePath console = GetLogConsole();
  return process_manager->RunCommand(compress_command,
                                     ProcessManager::IORedirection{
                                         .input = console.value(),
                                         .output = console.value(),
                                     });
}

}  // namespace minios
