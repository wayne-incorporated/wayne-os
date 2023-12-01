// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdio.h>
#include <string>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sysexits.h>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <brillo/flag_helper.h>

int main(int argc, char* argv[]) {
  brillo::FlagHelper::Init(
      argc, argv,
      "Chromium OS Static Node Tool\n\n"
      "  Parses through the kernel's modules.devname file and creates any\n"
      "  necessary static nodes.");

  std::string modules;

  // Populate uname struct, to get the kernel version number.
  struct utsname unameData;
  if (uname(&unameData)) {
    PLOG(FATAL) << "Error when reading in uname data";
  }

  // Read in the modules.devname file to a string.
  std::string modulesPath =
      base::StringPrintf("/lib/modules/%s/modules.devname", unameData.release);
  if (!base::ReadFileToString(base::FilePath(modulesPath), &modules)) {
    PLOG(FATAL) << "Could not read in list of modules";
  }

  umask(0);

  std::vector<std::string> lines = base::SplitString(
      modules, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
  for (const std::string& line : lines) {
    // If the line isn't empty, and isn't a comment, parse it as a static node.
    if (!line.empty() &&
        !base::StartsWith(line, "#", base::CompareCase::SENSITIVE)) {
      std::vector<std::string> tokens = base::SplitString(
          line, " ", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);

      // Static node descriptions in the file should be of the form:
      //   <name> <node> <type><major_id>:<minor_id>
      // where name is the name of the module, node is the path of the node
      // within /dev, type is a single character specifying the type of node,
      // and major_id and minor_id specify the device number.  Type can take
      // the values of 'p' for a FIFO, 'b' for a buffered block special file,
      // and 'c' or 'u' for an unbuffered character special file.
      if (tokens.size() == 3) {
        base::FilePath path(base::StringPrintf("/dev/%s", tokens[1].c_str()));
        std::string type = tokens[2].substr(0, 1);
        std::vector<std::string> device_id =
            base::SplitString(tokens[2].substr(1, std::string::npos), ":",
                              base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);

        int major_id = 0;
        int minor_id = 0;
        if (device_id.size() != 2) {
          PLOG(ERROR) << "Couldn't parse device id correctly from: " << line;
          continue;
        }
        base::StringToInt(device_id[0], &major_id);
        base::StringToInt(device_id[1], &minor_id);

        // If the directory where the node is to be created doesn't exist
        // yet, create it with permissions 755.
        base::File::Error error;
        base::FilePath directory = path.DirName();

        if (base::CreateDirectoryAndGetError(directory, &error)) {
          base::SetPosixFilePermissions(
              directory, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
        } else if (error != base::File::FILE_ERROR_EXISTS) {
          LOG(ERROR) << "Failed creating directory.  Error code: " << error;
          continue;
        }

        // Create the node with permission 660.
        if (!base::PathExists(path)) {
          if (type.compare("c") == 0) {
            if (mknod(path.value().c_str(),
                      S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP,
                      makedev(major_id, minor_id))) {
              PLOG(ERROR) << "Error creating node " << path.value();
            }
          } else {
            LOG(WARNING) << "Special file type " << type
                         << " is not supported.";
          }
        }
      } else {
        LOG(WARNING) << "Incorrect number of parameters as input: " << line;
      }
    }
  }

  return EX_OK;
}
