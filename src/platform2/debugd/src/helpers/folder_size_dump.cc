// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// The folder_size_dump helper dumps the size of various system folders.

#include <algorithm>
#include <functional>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include <brillo/flag_helper.h>
#include <base/bits.h>
#include <base/logging.h>
#include <base/files/dir_reader_posix.h>
#include <base/files/file_util.h>
#include <base/process/launch.h>
#include <re2/re2.h>

namespace {

constexpr char kShadowPath[] = "/home/.shadow/";

typedef bool (*FilterFunction)(const std::string& path);

class DirAdder {
 public:
  DirAdder(const char* path, FilterFunction filter, bool include_self)
      : path_(path), filter_(filter), include_self_(include_self) {}

  bool AppendDirEntries(std::vector<std::string>* output) const {
    base::DirReaderPosix dir_reader(path_);

    if (!dir_reader.IsValid()) {
      return false;
    }

    while (dir_reader.Next()) {
      std::string name(dir_reader.name());

      if (name == "." || name == "..") {
        continue;
      }

      auto entry = path_ + name;
      if (filter_(entry))
        output->push_back(entry);
    }

    if (!dir_reader.IsValid()) {
      return false;
    }

    return true;
  }

  void AppendSelf(std::vector<std::string>* output) const {
    if (include_self_) {
      output->push_back(path_);
    }
  }

  const char* GetPath() const { return path_; }

 private:
  const char* path_;
  FilterFunction filter_;
  bool include_self_;
};

constexpr char kUserRegex[] = "[a-z0-9]{40}";
bool FilterUserDirs(const std::string& entry) {
  return !RE2::PartialMatch(entry, kUserRegex);
}

bool FilterNonUserDirs(const std::string& entry) {
  return RE2::PartialMatch(entry, kUserRegex);
}

bool FilterStateful(const std::string& entry) {
  base::FilePath path(entry);

  if (path.BaseName().value() == "dev_image")
    return false;

  if (path.BaseName().value() == "encrypted")
    return false;

  if (path.BaseName().value() == "home")
    return false;

  return true;
}

bool FilterEncrypted(const std::string& entry) {
  base::FilePath path(entry);

  if (path.BaseName().value() == "chronos")
    return false;

  return true;
}

bool FilterNone(const std::string&) {
  return true;
}

bool DumpDirectory(const DirAdder& entry, bool one_filesystem) {
  std::vector<std::string> du_argv{"du", "--human-readable", "--total",
                                   "--summarize"};

  if (one_filesystem)
    du_argv.push_back("--one-file-system");

  auto arg_count = du_argv.size();

  if (!entry.AppendDirEntries(&du_argv)) {
    DLOG(ERROR) << "Failed to generate directory list for: " << entry.GetPath();
    return false;
  }

  // Sort directory entries.
  std::sort(du_argv.begin() + arg_count, du_argv.end());

  entry.AppendSelf(&du_argv);

  // Get the output of du.
  std::string output;
  if (!base::GetAppOutputAndError(base::CommandLine(du_argv), &output)) {
    DLOG(ERROR) << "Failed to generate directory dump for: " << entry.GetPath();
    return false;
  }

  // Filter out 0 sized entries to reduce size.
  // Matches "0 <dir>" lines in the output and remove them.
  RE2::GlobalReplace(&output, R"((?m:^0\s+.*$))", "");
  // Remove extra newlines.
  RE2::GlobalReplace(&output, R"(^\n+)", "");
  RE2::GlobalReplace(&output, R"(\n{2,})", "\n");

  // Filter out user avatar filenames as they leak who used the device.
  RE2::GlobalReplace(&output, R"(\S+@\S+[.](jpe?g|png|webp))",
                     "<user avatar>.<format>");

  std::cout << "--- " << entry.GetPath() << " ---" << std::endl;
  std::cout << output;

  return true;
}

bool DumpDaemonStore() {
  const std::string kDaemonSubPath = "/mount/root/";

  base::DirReaderPosix dir_reader(kShadowPath);

  if (!dir_reader.IsValid()) {
    return false;
  }

  std::vector<std::string> daemon_paths;
  while (dir_reader.Next()) {
    std::string name(dir_reader.name());

    if (name == "." || name == "..") {
      continue;
    }

    // Skip non user directories.
    if (!RE2::FullMatch(name, kUserRegex)) {
      continue;
    }

    auto entry = std::string(kShadowPath) + name + kDaemonSubPath;
    daemon_paths.push_back(entry);
  }

  bool result = true;
  if (!dir_reader.IsValid()) {
    return false;
  }

  for (const auto& entry : daemon_paths) {
    // Ignore errors for unmounted users.
    DumpDirectory(DirAdder(entry.c_str(), FilterNone, true),
                  /* one_filesystem=*/false);
  }

  return result;
}

// Reduce the precision of the size (in bytes).
// Returns value in MiB.
uint64_t ObfuscateSize(uint64_t size) {
  uint64_t result = size;

  // Count the number of bits set.
  auto ct = 64 - base::bits::CountLeadingZeroBits(size);

  // Only keep the 2 most significant bits.
  if (ct > 2) {
    result &= (1 << (ct - 1)) | (1 << (ct - 2));
  }

  // Convert to MiB.
  result /= 1024 * 1024;

  return result;
}

// Dump the sizes of all user folders (individual and summed).
// Only prints information at the MiB level.
// For individual user directories only the 2 most significant bits of the
// value are kept. We are only interested in the distribution of data.
bool DumpUserFolders(bool aggregate_only) {
  const DirAdder shadow_adder(kShadowPath, FilterNonUserDirs, true);

  std::vector<std::string> paths;
  if (!shadow_adder.AppendDirEntries(&paths)) {
    return false;
  }

  std::vector<uint64_t> results;
  uint64_t sum = 0;
  for (const auto& path : paths) {
    auto size = ComputeDirectorySize(base::FilePath(path));

    if (size < 0) {
      LOG(ERROR) << "Failed to determine the size of " << path;
      // Continuing despite the error.
    }

    sum += size;

    results.push_back(ObfuscateSize(size));
  }

  std::sort(results.begin(), results.end());

  // Convert to MiB.
  sum /= 1024 * 1024;

  if (!aggregate_only) {
    for (int i = 0; i < results.size(); i++) {
      std::cout << i << ": " << results[i] << " MiB" << std::endl;
    }
  }

  std::cout << "Sum: " << sum << " MiB" << std::endl;

  return true;
}

const DirAdder kSystemDirs[]{
    {"/home/chronos/", FilterUserDirs, false},
    {"/home/chronos/Default/", FilterNone, false},
    {"/home/.shadow/", FilterUserDirs, false},
    {"/mnt/stateful_partition/", FilterStateful, false},
    {"/mnt/stateful_partition/encrypted/", FilterEncrypted, false},
    {"/run/", FilterNone, true},
    {"/tmp/", FilterNone, true},
    {"/var/", FilterNone, true},
};

bool DumpSystemDirectories() {
  bool result = true;
  for (const auto& entry : kSystemDirs) {
    if (!DumpDirectory(entry, /* one_filesystem=*/true)) {
      result = false;
    }
  }

  std::cout << "--- Daemon store ---" << std::endl;
  if (!DumpDaemonStore()) {
    result = false;
  }

  std::cout << "--- All users(aggregate) ---" << std::endl;
  if (!DumpUserFolders(/* aggregate_only=*/true)) {
    result = false;
  }

  return result;
}

const DirAdder kUserDir("/home/chronos/user/", FilterNone, true);

bool DumpUserDirectories() {
  bool result = true;

  std::cout << "--- Daemon store ---" << std::endl;
  if (!DumpDaemonStore()) {
    result = false;
  }

  std::cout << "--- User directory ---" << std::endl;
  if (!DumpDirectory(kUserDir, /* one_filesystem=*/false)) {
    result = false;
  }

  std::cout << "--- Other users ---" << std::endl;
  if (!DumpUserFolders(/* aggregate_only=*/false)) {
    result = false;
  }

  return result;
}

}  // namespace

int main(int argc, char* argv[]) {
  DEFINE_bool(user, 0, "Dump user directories' sizes");
  DEFINE_bool(system, 0, "Dump system directories' sizes");
  brillo::FlagHelper::Init(argc, argv,
                           "Dump user and system directories' sizes");

  if (FLAGS_system) {
    if (!DumpSystemDirectories()) {
      LOG(ERROR) << "Failed system directory dump";
    }
  }

  if (FLAGS_user) {
    if (!DumpUserDirectories()) {
      LOG(ERROR) << "Failed user directory dump";
    }
  }

  return 0;
}
