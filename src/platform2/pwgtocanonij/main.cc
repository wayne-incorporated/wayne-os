// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <signal.h>
#include <stdio.h>

#include <iostream>
#include <utility>

#include <base/files/scoped_temp_dir.h>
#include <brillo/files/safe_fd.h>
#include "pwgtocanonij/canon_filter.h"

int main(int argc, char* argv[]) {
  // Need to have exactly 6 or 7 args.
  if (argc < 6 || argc > 7) {
    std::cerr << "Usage: " << argv[0]
              << " job-id user title copies options [filename]" << std::endl;
    return 1;
  }

  // Make sure status messages are not buffered.
  setbuf(stderr, nullptr);

  // Ignore broken pipe signals.
  signal(SIGPIPE, SIG_IGN);

  // TMPDIR should be setup by the CUPS environment.  Temporary files will get
  // written under this dir.  If this isn't set, fail.
  char* tmpdir = getenv("TMPDIR");
  if ((tmpdir == nullptr) || (*tmpdir == '\0')) {
    std::cerr << "ERROR: Need TMPDIR env var set." << std::endl;
    return 1;
  }

  base::ScopedTempDir baseDir;
  if (!baseDir.CreateUniqueTempDirUnderPath(base::FilePath(tmpdir))) {
    std::cerr << "ERROR: Unable to create temporary directory." << std::endl;
    return 1;
  }

  // We are either going to read from stdin or from the file listed in argv.
  brillo::SafeFD input;
  if (argc == 7) {
    if (argv[6][0] != '/') {
      std::cerr << "ERROR: Need to provide an absolute path.";
      return 1;
    }
    auto result = brillo::SafeFD::Root().first.OpenExistingFile(
        base::FilePath(argv[6]), O_RDONLY | O_CLOEXEC);
    if (brillo::SafeFD::IsError(result.second)) {
      std::cerr << "ERROR: Unable to open file " << argv[6] << ": "
                << static_cast<int>(result.second) << "." << std::endl;
      return 1;
    }
    input = std::move(result.first);
  } else {
    input.UnsafeReset(STDIN_FILENO);
  }

  canonij::CanonFilter filter(argv[1], std::move(input), std::move(baseDir));

  if (!filter.Run(argv[5])) {
    std::cerr << "ERROR: " << argv[0] << " did not run successfully."
              << std::endl;
    return 1;
  }

  return 0;
}
