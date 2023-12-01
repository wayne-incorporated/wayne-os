// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Stub implementation of Samba net. Does not talk to server, but simply returns
// fixed responses to predefined input.

#include <string>
#include <vector>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>

#include "authpolicy/samba_helper.h"
#include "authpolicy/stub_common.h"

namespace authpolicy {
namespace {

// smbclient sub-commands.
constexpr char kLcdCommand[] = "lcd ";
constexpr char kCdCommand[] = "cd ";
constexpr char kGetCommand[] = "get ";

// Expected host and share in smbclient command. First part should match domain
// controller name in kStubLookup (see stub_net_main.cc).
constexpr char kHostAndShare[] = "//DCNAME.EXAMPLE.COM/SysVol";

// Error printed when a "remote" GPO fails to download.
constexpr char kGpoDownloadError[] =
    "NT_STATUS_ACCESS_DENIED opening remote file ";

// Error printed when a "remote" GPO file does not exist.
constexpr char kGpoDoesNotExistError[] =
    "NT_STATUS_OBJECT_NAME_NOT_FOUND opening remote file ";

// Error printed smbclient cannot connect to a host/share.
constexpr char kConnectionFailedError[] =
    "Connection to //<SERVER_NAME>/sysvol failed (Error "
    "NT_STATUS_UNSUCCESSFUL)";

struct DownloadItem {
  std::string remote_path_;
  std::string local_path_;
};

// Finds all 'cd <remote_dir>;lcd <local_dir>;get <filename>' triplets in an
// smbclient command and returns a list the concatenated local and remote file
// paths found.
std::vector<DownloadItem> GetDownloadItems(const std::string& command_line) {
  std::string remote_dir, local_dir;
  std::vector<DownloadItem> items;
  std::vector<std::string> subcommands = base::SplitString(
      command_line, ";", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  for (const std::string& subcommand : subcommands) {
    if (StartsWithCaseSensitive(subcommand, kCdCommand)) {
      remote_dir = subcommand.substr(strlen(kCdCommand));
    } else if (StartsWithCaseSensitive(subcommand, kLcdCommand)) {
      local_dir = subcommand.substr(strlen(kLcdCommand));
    } else if (StartsWithCaseSensitive(subcommand, kGetCommand)) {
      const std::string filename = subcommand.substr(strlen(kGetCommand));
      DownloadItem item;
      item.remote_path_ = remote_dir + "\\" + filename;
      item.local_path_ = base::FilePath(local_dir).Append(filename).value();
      items.push_back(item);
    }
  }
  return items;
}

int HandleCommandLine(const std::string& command_line) {
  // Make sure the caller adds the debug level.
  CHECK(Contains(command_line, kDebugParam));

  if (!Contains(command_line, kHostAndShare)) {
    WriteOutput(kConnectionFailedError, "");
    return kExitCodeError;
  }

  // Stub GPO files are written to krb5.conf's directory because it's hard to
  // pass a full file path from a unit test to a stub binary. Note that
  // environment variables are NOT passed through ProcessExecutor.
  const base::FilePath krb5_conf_path(GetKrb5ConfFilePath());
  const base::FilePath gpo_dir = krb5_conf_path.DirName();

  std::vector<DownloadItem> items = GetDownloadItems(command_line);
  for (const DownloadItem& item : items) {
    base::FilePath source_path;
    bool download_error = false;
    if (Contains(item.local_path_, kGpo1Guid))
      source_path = gpo_dir.Append(kGpo1Filename);
    else if (Contains(item.local_path_, kGpo2Guid))
      source_path = gpo_dir.Append(kGpo2Filename);
    else if (Contains(item.local_path_, kErrorGpoGuid))
      download_error = true;
    else if (Contains(item.local_path_, kSeccompGpoGuid))
      TriggerSeccompFailure();
    else
      NOTREACHED() << "UNHANDLED DOWNLOAD ITEM '" << item.local_path_ << "'";

    if (download_error) {
      // Print "download error" warning.
      WriteOutput(kGpoDownloadError + item.remote_path_, "");
    } else if (!base::PathExists(source_path)) {
      // Print "file does not exist" warning.
      WriteOutput(kGpoDoesNotExistError + item.remote_path_, "");
    } else {
      // "Download" the file.
      base::FilePath target_path(item.local_path_);
      CHECK(base::CopyFile(source_path, target_path));
    }
  }

  // The command should always end with 'exit;'. This makes sure smbclient
  // always exits with code 0.
  CHECK(base::EndsWith(command_line, "exit;", base::CompareCase::SENSITIVE));
  return kExitCodeOk;
}

}  // namespace
}  // namespace authpolicy

int main(int argc, char* argv[]) {
  const std::string command_line = authpolicy::GetCommandLine(argc, argv);
  return authpolicy::HandleCommandLine(command_line);
}
