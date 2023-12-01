// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This class abstracts away the details about the layout of the component dir
// and how to verify/copy it.
//
// A component directory contains the following files:
//
// imageloader.json       Manifest JSON file
// imageloader.sig.1      Manifest signature
// manifest.fingerprint   Fingerprint file (used for delta updates)
// image.squash           squashfs image
// table                  dm-verity table, including parameters
#ifndef IMAGELOADER_COMPONENT_H_
#define IMAGELOADER_COMPONENT_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/gtest_prod_util.h>
#include <crypto/secure_hash.h>

#include "imageloader/helper_process_proxy.h"
#include "imageloader/imageloader_impl.h"
#include "imageloader/manifest.h"

namespace imageloader {

// The permissions that the component update directory must use.
constexpr int kComponentDirPerms = 0755;
// The permissions that files in the component should have.
constexpr int kComponentFilePerms = 0644;
// The maximum size of any file to read into memory.
constexpr size_t kMaximumFilesize = 4096 * 10;

class Component {
 public:
  // Creates a Component. Returns nullptr if initialization and verification
  // fails.
  static std::unique_ptr<Component> Create(const base::FilePath& component_dir,
                                           const Keys& public_keys);

  // Copies the component into |dest_dir|. |dest_dir| must already exist. In
  // order to be robust against files being modified on disk, this function
  // verifies the files it copies against the manifest (which is loaded into
  // memory).
  bool CopyTo(const base::FilePath& dest_dir);

  // Mounts the component into |mount_point|. |mount_point| must already exist.
  bool Mount(HelperProcessProxy* proxy, const base::FilePath& mount_point);

  // Return a reference to the parsed manifest object, which is stored in
  // memory.
  const Manifest& manifest();

 private:
  // Constructs a Component. We want to avoid using this where possible since
  // you need to load the manifest before doing anything anyway, so use the
  // static factory method above.
  Component(const base::FilePath& component_dir, int key_number);
  Component(const Component&) = delete;
  Component& operator=(const Component&) = delete;

  // Loads and verifies the manfiest. Returns false on failure. |public_key| is
  // the public key used to check the manifest signature.
  bool LoadManifest(const std::vector<uint8_t>& public_key);
  // Same as the above function, but it skips the verification.
  bool LoadManifestWithoutVerifyingKeyForTestingOnly();

  bool CopyComponentFile(const base::FilePath& src,
                         const base::FilePath& dest,
                         const std::vector<uint8_t>& expected_hash);
  // This reads the contents of |file|, hashes it with |sha256|, and if
  // |out_file| is not null, copies it into |out_file|.
  bool ReadHashAndCopyFile(base::File* file,
                           std::vector<uint8_t>* sha256,
                           base::File* out_file);
  // Copies the fingerprint file that Chrome users for delta updates.
  bool CopyFingerprintFile(const base::FilePath& src,
                           const base::FilePath& dest);
  // Validate the fingerprint file.
  static bool IsValidFingerprintFile(const std::string& contents);

  FRIEND_TEST_ALL_PREFIXES(ComponentTest, IsValidFingerprintFile);
  FRIEND_TEST_ALL_PREFIXES(ComponentTest, CopyValidImage);

  const base::FilePath component_dir_;
  size_t key_number_;
  std::string manifest_raw_;
  std::string manifest_sig_;
  Manifest manifest_;
};

}  // namespace imageloader

#endif  // IMAGELOADER_COMPONENT_H_
