/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hardware_verifier/hw_verification_spec_getter_impl.h"

#include <optional>
#include <string>
#include <utility>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/hash/sha1.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <google/protobuf/text_format.h>
#include <vboot/crossystem.h>

#include "hardware_verifier/hardware_verifier.pb.h"
#include "hardware_verifier/log_utils.h"

namespace hardware_verifier {

namespace {

constexpr char kTextFmtExt[] = ".prototxt";
constexpr char kDefaultHwVerificationSpecRelPath[] =
    "etc/hardware_verifier/hw_verification_spec.prototxt";
constexpr char kUsrLocal[] = "usr/local";

std::string GetSHA1HashHexString(const std::string& content) {
  const auto& sha1_hash = base::SHA1HashString(content);
  return base::HexEncode(sha1_hash.data(), sha1_hash.size());
}

std::optional<HwVerificationSpec> ReadOutHwVerificationSpecFromFile(
    const base::FilePath& file_path) {
  VLOG(1) << "Try to retrieve the verification payload from file ("
          << file_path.value() << ").";
  if (file_path.Extension() != kTextFmtExt) {
    LOG(ERROR) << "The extension (" << file_path.Extension()
               << ") is unrecognizable.";
    return std::nullopt;
  }

  std::string content;
  if (!base::ReadFileToString(file_path, &content)) {
    LOG(ERROR) << "Failed to read the verification payload file.";
    return std::nullopt;
  }
  LOG(INFO) << "SHA-1 Hash of the file content: "
            << GetSHA1HashHexString(content) << ".";

  HwVerificationSpec hw_spec;
  if (!google::protobuf::TextFormat::ParseFromString(content, &hw_spec)) {
    LOG(ERROR) << "Failed to parse the verification payload in text format.";
    return std::nullopt;
  }
  VLogProtobuf(2, "HwVerificationSpec", hw_spec);
  return hw_spec;
}

}  // namespace

int VbSystemPropertyGetter::GetCrosDebug() const {
  return VbGetSystemPropertyInt("cros_debug");
}

HwVerificationSpecGetterImpl::HwVerificationSpecGetterImpl()
    : HwVerificationSpecGetterImpl(std::make_unique<VbSystemPropertyGetter>()) {
}

HwVerificationSpecGetterImpl::HwVerificationSpecGetterImpl(
    std::unique_ptr<VbSystemPropertyGetter> vb_system_property_getter)
    : vb_system_property_getter_(std::move(vb_system_property_getter)),
      root_("/") {}

std::optional<HwVerificationSpec> HwVerificationSpecGetterImpl::GetDefault()
    const {
  if (vb_system_property_getter_->GetCrosDebug() == 1) {
    auto spec = ReadOutHwVerificationSpecFromFile(
        root_.Append(kUsrLocal).Append(kDefaultHwVerificationSpecRelPath));
    if (spec)
      return spec;
  }
  return ReadOutHwVerificationSpecFromFile(
      root_.Append(kDefaultHwVerificationSpecRelPath));
}

std::optional<HwVerificationSpec> HwVerificationSpecGetterImpl::GetFromFile(
    const base::FilePath& file_path) const {
  if (vb_system_property_getter_->GetCrosDebug() != 1) {
    LOG(ERROR) << "Arbitrary hardware verificaion spec is only allowed with "
                  "cros_debug=1";
    return std::nullopt;
  }
  return ReadOutHwVerificationSpecFromFile(file_path);
}

}  // namespace hardware_verifier
