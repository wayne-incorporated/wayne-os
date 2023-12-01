// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by the GPL v2 license that can
// be found in the LICENSE file.
//
// Driver program for creating verity hash images.

#include <stdio.h>
#include <stdlib.h>

#include <memory>
#include <string>

#include <base/files/file.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/strings/string_utils.h>

#include "verity/file_hasher.h"

namespace {
void print_usage(const char* name) {
  // We used to advertise more algorithms, but they've never been implemented:
  // sha512 sha384 sha mdc2 ripemd160 md4 md2
  fprintf(
      stderr,
      "Usage:\n"
      "  %s <arg>=<value>...\n"
      "Options:\n"
      "  mode              One of 'create' or 'verify'\n"
      "  alg               Hash algorithm to use. Only sha256 for now\n"
      "  payload           Path to the image to hash\n"
      "  payload_blocks    Size of the image, in blocks (4096 bytes)\n"
      "  hashtree          Path to a hash tree to create or read from\n"
      "  root_hexdigest    Digest of the root node (in hex) for verification\n"
      "  salt              Salt (in hex)\n"
      "\n",
      name);
}

typedef enum { VERITY_NONE = 0, VERITY_CREATE, VERITY_VERIFY } verity_mode_t;

int verity_create(const std::string& alg,
                  const std::string& image_path,
                  unsigned int image_blocks,
                  const std::string& hash_path,
                  const std::string& salt) {
  auto source = std::make_unique<base::File>(
      base::FilePath(image_path),
      base::File::FLAG_OPEN | base::File::FLAG_READ);
  LOG_IF(FATAL, source && !source->IsValid())
      << "Failed to open the source file: " << image_path;
  auto destination = std::make_unique<base::File>(
      base::FilePath(hash_path),
      base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
  LOG_IF(FATAL, destination && !destination->IsValid())
      << "Failed to open destination file: " << hash_path;

  // Create the actual worker and create the hash image.
  verity::FileHasher hasher(std::move(source), std::move(destination),
                            image_blocks, alg.c_str());
  LOG_IF(FATAL, !hasher.Initialize()) << "Failed to initialize hasher";
  if (!salt.empty())
    hasher.set_salt(salt.c_str());
  LOG_IF(FATAL, !hasher.Hash()) << "Failed to hash hasher";
  LOG_IF(FATAL, !hasher.Store()) << "Failed to store hasher";
  hasher.PrintTable(true);
  return 0;
}
}  // namespace

int main(int argc, char** argv) {
  verity_mode_t mode = VERITY_CREATE;
  std::string alg, payload, hashtree, salt;
  unsigned int payload_blocks = 0;

  // TODO(b/269707854): Use flag arguments + update callers to verity tool.
  for (int i = 1; i < argc; i++) {
    auto [key, val] = brillo::string_utils::SplitAtFirst(
        argv[i], "=", /*trim_whitespaces=*/true);
    if (key.empty())
      continue;

    if (val.empty()) {
      fprintf(stderr, "missing value: %s\n", key.c_str());
      print_usage(argv[0]);
      return -1;
    }

    if (key == "alg") {
      alg = val;
    } else if (key == "payload") {
      payload = val;
    } else if (key == "payload_blocks") {
      CHECK(base::StringToUint(val, &payload_blocks));
    } else if (key == "hashtree") {
      hashtree = val;
    } else if (key == "root_hexdigest") {
      // Silently drop root_hexdigest for now...
    } else if (key == "mode") {
      // Silently drop the mode for now...
    } else if (key == "salt") {
      salt = val;
    } else {
      fprintf(stderr, "bogus key: '%s'\n", key.c_str());
      print_usage(argv[0]);
      return -1;
    }
  }

  if (alg.empty() || payload.empty() || hashtree.empty()) {
    fprintf(stderr, "missing data: %s%s%s\n", alg.empty() ? "alg " : "",
            payload.empty() ? "payload " : "",
            hashtree.empty() ? "hashtree" : "");
    print_usage(argv[0]);
    return -1;
  }

  if (mode == VERITY_CREATE) {
    return verity_create(alg, payload, payload_blocks, hashtree, salt);
  } else {
    LOG(FATAL) << "Verification not done yet";
  }
  return -1;
}
