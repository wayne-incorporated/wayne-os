// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "imageloader/component.h"

#include <fcntl.h>

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/json/json_string_value_serializer.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/numerics/safe_conversions.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <crypto/secure_hash.h>
#include <crypto/sha2.h>
#include <crypto/signature_verifier.h>

#include "imageloader/global_context.h"
#include "imageloader/helper_process_proxy.h"

namespace imageloader {

namespace {

// The name of the imageloader manifest file.
constexpr char kManifestName[] = "imageloader.json";
// The name of the fingerprint file.
constexpr char kFingerprintName[] = "manifest.fingerprint";
// The manifest signature.
constexpr char kManifestSignatureNamePattern[] = "imageloader.sig.[1-2]";
// The name of the image file (squashfs).
constexpr char kImageFileNameSquashFS[] = "image.squash";
// The name of the image file (ext4).
constexpr char kImageFileNameExt4[] = "image.ext4";
// The name of the table file.
constexpr char kTableFileName[] = "table";

base::FilePath GetManifestPath(const base::FilePath& component_dir) {
  return component_dir.Append(kManifestName);
}

bool GetSignaturePath(const base::FilePath& component_dir,
                      base::FilePath* signature_path,
                      size_t* key_number) {
  DCHECK(signature_path);
  DCHECK(key_number);

  base::FileEnumerator files(component_dir, false,
                             base::FileEnumerator::FileType::FILES,
                             kManifestSignatureNamePattern);
  for (base::FilePath path = files.Next(); !path.empty(); path = files.Next()) {
    // Extract the key number.
    std::string key_ext = path.FinalExtension();
    if (key_ext.empty())
      continue;

    size_t ext_number;
    if (!base::StringToSizeT(key_ext.substr(1), &ext_number))
      continue;

    *signature_path = path;
    *key_number = ext_number;
    return true;
  }
  return false;
}

base::FilePath GetSignaturePathForKey(const base::FilePath& component_dir,
                                      size_t key_number) {
  std::string signature_name(kManifestSignatureNamePattern);
  signature_name =
      signature_name.substr(0, signature_name.find_last_of('.') + 1);
  return component_dir.Append(signature_name +
                              base::NumberToString(key_number));
}

base::FilePath GetFingerprintPath(const base::FilePath& component_dir) {
  return component_dir.Append(kFingerprintName);
}

base::FilePath GetTablePath(const base::FilePath& component_dir) {
  return component_dir.Append(kTableFileName);
}

base::FilePath GetImagePath(const base::FilePath& component_dir,
                            FileSystem fs_type) {
  if (fs_type == FileSystem::kExt4) {
    return component_dir.Append(kImageFileNameExt4);
  } else if (fs_type == FileSystem::kSquashFS) {
    return component_dir.Append(kImageFileNameSquashFS);
  } else {
    NOTREACHED();
    return base::FilePath();
  }
}

bool WriteFileToDisk(const base::FilePath& path, const std::string& contents) {
  base::ScopedFD fd(HANDLE_EINTR(open(
      path.value().c_str(), O_CREAT | O_WRONLY | O_EXCL, kComponentFilePerms)));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "Error creating file for " << path.value();
    return false;
  }

  base::File file(fd.release());
  int size = base::checked_cast<int>(contents.size());
  return file.Write(0, contents.data(), contents.size()) == size;
}

bool GetAndVerifyTable(const base::FilePath& path,
                       const std::vector<uint8_t>& hash,
                       std::string* out_table) {
  std::string table;
  if (!base::ReadFileToStringWithMaxSize(path, &table, kMaximumFilesize)) {
    return false;
  }

  std::vector<uint8_t> table_hash(crypto::kSHA256Length);
  crypto::SHA256HashString(table, table_hash.data(), table_hash.size());
  if (table_hash != hash) {
    LOG(ERROR) << "dm-verity table file has the wrong hash.";
    return false;
  }

  out_table->assign(table);
  return true;
}

}  // namespace

Component::Component(const base::FilePath& component_dir, int key_number)
    : component_dir_(component_dir), key_number_(key_number) {}

std::unique_ptr<Component> Component::Create(
    const base::FilePath& component_dir, const Keys& public_keys) {
  bool is_official_build = GlobalContext::Current()->IsOfficialBuild();

  // Try to verify signatures in all type of images (signed/test/etc) if they
  // exists. Only for non-official images, if the signature is missing, ignore
  // verification otherwise fail.
  base::FilePath signature_path;
  size_t key_number = 0;
  if (GetSignaturePath(component_dir, &signature_path, &key_number)) {
    if (key_number < 1 || key_number > public_keys.size()) {
      LOG(ERROR) << "Invalid key number.";
      return nullptr;
    }
  } else if (is_official_build) {
    LOG(ERROR) << "Could not find manifest signature.";
    return nullptr;
  } else {
    LOG(WARNING) << "Could not find manifest signature, but since this is not "
                 << "an official image, we allow loading the component.";
  }

  std::unique_ptr<Component> component(
      new Component(component_dir, key_number));
  if (key_number > 0) {
    if (!component->LoadManifest(public_keys[key_number - 1])) {
      return nullptr;
    }
  } else if (!component->LoadManifestWithoutVerifyingKeyForTestingOnly()) {
    return nullptr;
  }
  return component;
}

const Manifest& Component::manifest() {
  return manifest_;
}

bool Component::Mount(HelperProcessProxy* mounter,
                      const base::FilePath& dest_dir) {
  // Read the table in and verify the hash.
  std::string table;
  if (!GetAndVerifyTable(GetTablePath(component_dir_), manifest_.table_sha256(),
                         &table)) {
    LOG(ERROR) << "Could not read and verify dm-verity table.";
    return false;
  }

  base::FilePath image_path(GetImagePath(component_dir_, manifest_.fs_type()));
  base::File image(image_path, base::File::FLAG_OPEN | base::File::FLAG_READ);
  if (!image.IsValid()) {
    LOG(ERROR) << "Could not open image file.";
    return false;
  }
  base::ScopedFD image_fd(image.TakePlatformFile());

  return mounter->SendMountCommand(image_fd.get(), dest_dir.value(),
                                   manifest_.fs_type(), table);
}

bool Component::LoadManifestWithoutVerifyingKeyForTestingOnly() {
  if (!base::ReadFileToStringWithMaxSize(GetManifestPath(component_dir_),
                                         &manifest_raw_, kMaximumFilesize)) {
    LOG(ERROR) << "Could not read manifest file.";
    return false;
  }
  return manifest_.ParseManifest(manifest_raw_);
}

bool Component::LoadManifest(const std::vector<uint8_t>& public_key) {
  if (!base::ReadFileToStringWithMaxSize(GetManifestPath(component_dir_),
                                         &manifest_raw_, kMaximumFilesize)) {
    LOG(ERROR) << "Could not read manifest file.";
    return false;
  }
  if (!base::ReadFileToStringWithMaxSize(
          GetSignaturePathForKey(component_dir_, key_number_), &manifest_sig_,
          kMaximumFilesize)) {
    LOG(ERROR) << "Could not read signature file.";
    return false;
  }

  crypto::SignatureVerifier verifier;

  if (!verifier.VerifyInit(
          crypto::SignatureVerifier::ECDSA_SHA256,
          reinterpret_cast<const uint8_t*>(manifest_sig_.data()),
          base::checked_cast<int>(manifest_sig_.size()), public_key.data(),
          base::checked_cast<int>(public_key.size()))) {
    LOG(ERROR) << "Failed to initialize signature verification.";
    return false;
  }

  verifier.VerifyUpdate(reinterpret_cast<const uint8_t*>(manifest_raw_.data()),
                        base::checked_cast<int>(manifest_raw_.size()));

  if (!verifier.VerifyFinal()) {
    LOG(ERROR) << "Manifest failed signature verification.";
    return false;
  }
  return manifest_.ParseManifest(manifest_raw_);
}

bool Component::CopyTo(const base::FilePath& dest_dir) {
  if (!WriteFileToDisk(GetManifestPath(dest_dir), manifest_raw_) ||
      (key_number_ > 0 &&
       !WriteFileToDisk(GetSignaturePathForKey(dest_dir, key_number_),
                        manifest_sig_))) {
    LOG(ERROR) << "Could not write manifest and signature to disk.";
    return false;
  }

  base::FilePath table_src(GetTablePath(component_dir_));
  base::FilePath table_dest(GetTablePath(dest_dir));
  if (!CopyComponentFile(table_src, table_dest, manifest_.table_sha256())) {
    LOG(ERROR) << "Could not copy table file.";
    return false;
  }

  base::FilePath image_src(GetImagePath(component_dir_, manifest_.fs_type()));
  base::FilePath image_dest(GetImagePath(dest_dir, manifest_.fs_type()));
  if (!CopyComponentFile(image_src, image_dest, manifest_.image_sha256())) {
    LOG(ERROR) << "Could not copy image file.";
    return false;
  }

  if (!CopyFingerprintFile(component_dir_, dest_dir)) {
    LOG(ERROR) << "Could not copy manifest.fingerprint file.";
    return false;
  }

  return true;
}

bool Component::CopyComponentFile(const base::FilePath& src,
                                  const base::FilePath& dest_path,
                                  const std::vector<uint8_t>& expected_hash) {
  base::File file(src, base::File::FLAG_OPEN | base::File::FLAG_READ);
  if (!file.IsValid())
    return false;

  base::ScopedFD dest(
      HANDLE_EINTR(open(dest_path.value().c_str(), O_CREAT | O_WRONLY | O_EXCL,
                        kComponentFilePerms)));
  if (!dest.is_valid())
    return false;

  base::File out_file(dest.release());
  std::unique_ptr<crypto::SecureHash> sha256(
      crypto::SecureHash::Create(crypto::SecureHash::SHA256));

  std::vector<uint8_t> file_hash(crypto::kSHA256Length);
  if (!ReadHashAndCopyFile(&file, &file_hash, &out_file)) {
    LOG(ERROR) << "Failed to read image file.";
    return false;
  }

  if (expected_hash != file_hash) {
    LOG(ERROR) << "Image is corrupt or modified.";
    return false;
  }
  return true;
}

bool Component::ReadHashAndCopyFile(base::File* file,
                                    std::vector<uint8_t>* file_hash,
                                    base::File* out_file) {
  std::unique_ptr<crypto::SecureHash> sha256(
      crypto::SecureHash::Create(crypto::SecureHash::SHA256));
  int size = file->GetLength();
  if (size <= 0)
    return false;

  int rv = 0, bytes_read = 0;
  char buf[4096];
  do {
    int remaining = size - bytes_read;
    int bytes_to_read =
        std::min(remaining, base::checked_cast<int>(sizeof(buf)));

    rv = file->ReadAtCurrentPos(buf, bytes_to_read);
    if (rv <= 0)
      break;

    bytes_read += rv;
    sha256->Update(buf, rv);
    if (out_file) {
      out_file->WriteAtCurrentPos(buf, rv);
    }
  } while (bytes_read <= size);

  sha256->Finish(file_hash->data(), file_hash->size());
  return bytes_read == size;
}

bool Component::CopyFingerprintFile(const base::FilePath& src,
                                    const base::FilePath& dest) {
  base::FilePath fingerprint_path(GetFingerprintPath(src));
  if (base::PathExists(fingerprint_path)) {
    std::string fingerprint_contents;
    if (!base::ReadFileToStringWithMaxSize(
            fingerprint_path, &fingerprint_contents, kMaximumFilesize)) {
      return false;
    }

    if (!IsValidFingerprintFile(fingerprint_contents))
      return false;

    if (!WriteFileToDisk(GetFingerprintPath(dest), fingerprint_contents)) {
      return false;
    }
  }
  return true;
}

// The client inserts manifest.fingerprint into components after unpacking the
// CRX. The file is used for delta updates. Since Chrome OS doesn't rely on it
// for security of the disk image, we are fine with validating the contents
// and then preserving the unsigned file.
bool Component::IsValidFingerprintFile(const std::string& contents) {
  return contents.size() <= 256 &&
         std::find_if_not(contents.begin(), contents.end(), [](char ch) {
           return base::IsAsciiAlpha(ch) || base::IsAsciiDigit(ch) || ch == '.';
         }) == contents.end();
}

}  // namespace imageloader
