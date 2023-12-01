// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/helpers/dev_features_password_utils.h"

#include <fcntl.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <base/files/file_util.h>
#include <base/files/important_file_writer.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <brillo/file_utils.h>

#include "debugd/src/process_with_output.h"

namespace debugd {

bool DevFeaturesPasswordUtils::IsUsernameValid(const std::string& username) {
  regex_t regex;
  if (regcomp(&regex, "^[a-z_][a-z0-9._-]*$",
              REG_EXTENDED | REG_ICASE | REG_NOSUB) != 0) {
    return false;
  }
  int result = regexec(&regex, username.c_str(), 0, nullptr, 0);
  regfree(&regex);
  return result == 0;
}

bool DevFeaturesPasswordUtils::IsPasswordSet(
    const std::string& username, const base::FilePath& password_file) {
  std::string file_contents;
  if (!base::ReadFileToString(password_file, &file_contents)) {
    return false;
  }

  // Usernames are allowed alphanumerics and ._- characters. For use in a regex,
  // '_' and '-' don't have any special meaning (since [] aren't allowed) but
  // '.' needs to be escaped.
  std::string escaped_username;
  base::ReplaceChars(username, ".", "\\.", &escaped_username);

  regex_t regex;
  std::string regex_string('^' + escaped_username + ":[^!*:]");
  if (regcomp(&regex, regex_string.c_str(),
              REG_EXTENDED | REG_NOSUB | REG_NEWLINE) != 0) {
    return false;
  }
  int result = regexec(&regex, file_contents.c_str(), 0, nullptr, 0);
  regfree(&regex);
  return result == 0;
}

bool DevFeaturesPasswordUtils::SetPassword(
    const std::string& username,
    const std::string& password,
    const base::FilePath& password_file) {
  std::string hashed_password;
  if (!HashPassword(password, &hashed_password) ||
      !brillo::TouchFile(password_file)) {
    return false;
  }

  std::string file_contents;
  if (!base::ReadFileToString(password_file, &file_contents)) {
    PLOG(WARNING) << "Error reading from \"" << password_file.value() << '"';
    return false;
  }

  // Split the file into lines to handle each user entry individually, set the
  // new user password, and join the lines again.
  std::vector<std::string> lines = base::SplitString(
      file_contents, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
  SetPasswordInEntries(username, hashed_password, &lines);
  file_contents = base::JoinString(lines, "\n");

  // Since we're dealing with password files we need to be as safe as possible
  // when writing to the file, so use ImportantFileWriter and attempt to
  // fsync() the directory afterwards. See
  // groups.google.com/a/chromium.org/forum/#!topic/chromium-os-dev/Qaphhzbei6I
  // for details.
  if (!base::ImportantFileWriter::WriteFileAtomically(password_file,
                                                      file_contents)) {
    return false;
  }
  // TODO(dpursell): once ImportantFileWriter has support for directory fsync()
  // use that instead of doing it manually here.
  int fd = HANDLE_EINTR(open(password_file.DirName().value().c_str(),
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  if (fd != -1) {
    fsync(fd);
    close(fd);
  }
  return true;
}

bool DevFeaturesPasswordUtils::HashPassword(const std::string& password,
                                            std::string* hashed_password) {
  // Run openssl to hash the password.
  std::string error;
  int result = ProcessWithOutput::RunProcessFromHelper(
      "openssl", {"passwd", "-1", "-stdin"},
      &password,        // stdin.
      hashed_password,  // stdout.
      &error);          // stderr.
  if (result != EXIT_SUCCESS) {
    LOG(WARNING) << "openssl failed with exit code " << result << ": " << error;
    return false;
  }

  // Remove any trailing newline.
  base::TrimWhitespaceASCII(*hashed_password, base::TRIM_TRAILING,
                            hashed_password);
  return true;
}

bool DevFeaturesPasswordUtils::SetPasswordInEntries(
    const std::string& username,
    const std::string& hashed_password,
    std::vector<std::string>* entries) {
  bool user_found = false;
  std::string user_line_start = username + ':';

  for (auto& line : *entries) {
    if (line.compare(0, user_line_start.length(), user_line_start) == 0) {
      user_found = true;
      // Break the entry into fields and replace the password field.
      std::vector<std::string> fields = base::SplitString(
          line, ":", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
      if (fields.size() < 2) {
        fields.resize(2);
      }
      fields[1] = hashed_password;
      line.assign(base::JoinString(fields, ":"));
      break;
    }
  }

  if (!user_found) {
    // Get rid of trailing empty lines so the new entry is in the right place.
    while (!entries->empty() && entries->back().empty()) {
      entries->pop_back();
    }
    entries->push_back(username + ':' + hashed_password + ":::::::");
    // Add in a single trailing line at the end.
    entries->push_back("");
  }

  return true;
}

}  // namespace debugd
