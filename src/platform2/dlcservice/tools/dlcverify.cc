// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include <base/logging.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <brillo/flag_helper.h>
#include <chromeos/constants/imageloader.h>
#include <libimageloader/manifest.h>

#include "dlcservice/utils.h"

namespace dlcservice {

class DlcVerify {
 public:
  DlcVerify(int argc, const char** argv) : argc_(argc), argv_(argv) {}
  ~DlcVerify() = default;

  DlcVerify(const DlcVerify&) = delete;
  DlcVerify& operator=(const DlcVerify&) = delete;

  int Run() {
    if (!ParseFlags() || !ParseManifest() || !VerifyImage())
      return 1;
    LOG(INFO) << "Image hash is valid.";
    return 0;
  }

 private:
  bool ParseFlags() {
    DEFINE_string(id, "", "The ID of the DLC");
    DEFINE_string(package, "package",
                  "The package of the DLC (use the default)");
    DEFINE_string(image, "", "Path to the DLC image");
    DEFINE_string(rootfs_mount, "/", "Path to the rootfs mount path");

    brillo::FlagHelper::Init(argc_, argv_, "dlcverify");

    id_ = FLAGS_id;
    if (id_.empty()) {
      LOG(ERROR) << "Please provide a valid DLC ID.";
      return false;
    }

    package_ = FLAGS_package;
    if (package_.empty()) {
      LOG(ERROR) << "Please provide a valid DLC package.";
      return false;
    }

    image_ = base::FilePath{FLAGS_image};
    if (!base::PathExists(image_)) {
      LOG(ERROR) << "Please provide a valid image path.";
      return false;
    }

    rootfs_mount_ = base::FilePath{FLAGS_rootfs_mount};
    if (!base::DirectoryExists(rootfs_mount_)) {
      LOG(ERROR) << "Please provide a valid rootfs mount.";
      return false;
    }

    return true;
  }

  bool ParseManifest() {
    manifest_ = GetDlcManifest(
        rootfs_mount_.Append(imageloader::kRelativeDlcManifestRootpath), id_,
        package_);
    // Let `GetDlcManifest()` log the error.
    return manifest_ != nullptr;
  }

  bool VerifyImage() {
    CHECK(manifest_ != nullptr);
    std::vector<uint8_t> hash;
    if (!HashFile(image_, manifest_->size(), &hash)) {
      // Let `HashFile()` log the error.
      return false;
    }
    if (manifest_->image_sha256() != hash) {
      LOG(ERROR) << "The image hash is not valid.";
      return false;
    }
    return true;
  }

  int argc_;
  const char** argv_;

  base::FilePath rootfs_mount_;
  base::FilePath image_;
  std::string id_;
  std::string package_;

  std::shared_ptr<imageloader::Manifest> manifest_;
};

}  // namespace dlcservice

int main(int argc, const char** argv) {
  return dlcservice::DlcVerify(argc, argv).Run();
}
