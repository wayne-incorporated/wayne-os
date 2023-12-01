// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/fetchers/system_fetcher.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/system/sys_info.h>

#include "diagnostics/base/file_utils.h"
#include "diagnostics/cros_healthd/fetchers/system_fetcher_constants.h"
#include "diagnostics/cros_healthd/utils/callback_barrier.h"
#include "diagnostics/cros_healthd/utils/error_utils.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

class State {
 public:
  explicit State(Context* context);
  State(const State&) = delete;
  State& operator=(const State&) = delete;
  ~State();

  static void Fetch(Context* context, FetchSystemInfoCallback callback);

 private:
  bool FetchCachedVpdInfo();

  bool FetchDmiInfo();

  template <typename StringType>
  bool GetLsbReleaseValue(const std::string& field, StringType& out_str);

  bool FetchOsVersion(mojom::OsVersionPtr& os_version);

  void FetchBootMode(mojom::BootMode& boot_mode);

  bool FetchOsInfo();

  void HandleSecureBootResponse(const std::optional<std::string>& content);

  void HandleEfiPlatformSize(const std::optional<std::string>& context);

  // Sets the error to be reported.
  void SetError(mojom::ErrorType type, const std::string& message);

  void HandlePsrInfo(mojom::PsrInfoPtr psr_info_ptr,
                     const std::optional<std::string>& err);

  // Sends the result. If error is set it will be sent. Otherwise, sends the
  // |info_| as the result.
  void HandleResult(FetchSystemInfoCallback callback, bool success);

  Context* const context_;
  mojom::SystemInfoPtr info_;
  mojom::ProbeErrorPtr error_;
};

State::State(Context* context)
    : context_(context), info_(mojom::SystemInfo::New()) {}

State::~State() = default;

// Fetches information from DMI. Since there are several devices that do not
// provide DMI information, these fields are optional in SystemInfo. As a
// result, a missing DMI file does not indicate a ProbeError. A ProbeError is
// reported when the "chassis_type" field cannot be successfully parsed into an
// unsigned integer.
bool State::FetchDmiInfo() {
  const auto& dmi_path = context_->root_dir().Append(kRelativePathDmiInfo);
  // If dmi path doesn't exist, the device doesn't support dmi at
  // all. It is considered as successful.
  if (!base::DirectoryExists(dmi_path)) {
    info_->dmi_info = nullptr;
    return true;
  }

  auto dmi_info = mojom::DmiInfo::New();
  ReadAndTrimString(dmi_path, kFileNameBiosVendor, &dmi_info->bios_vendor);
  ReadAndTrimString(dmi_path, kFileNameBiosVersion, &dmi_info->bios_version);
  ReadAndTrimString(dmi_path, kFileNameBoardName, &dmi_info->board_name);
  ReadAndTrimString(dmi_path, kFileNameBoardVendor, &dmi_info->board_vendor);
  ReadAndTrimString(dmi_path, kFileNameBoardVersion, &dmi_info->board_version);
  ReadAndTrimString(dmi_path, kFileNameChassisVendor,
                    &dmi_info->chassis_vendor);
  ReadAndTrimString(dmi_path, kFileNameProductFamily,
                    &dmi_info->product_family);
  ReadAndTrimString(dmi_path, kFileNameProductName, &dmi_info->product_name);
  ReadAndTrimString(dmi_path, kFileNameProductVersion,
                    &dmi_info->product_version);
  ReadAndTrimString(dmi_path, kFileNameSysVendor, &dmi_info->sys_vendor);

  std::string chassis_type_str;
  if (ReadAndTrimString(dmi_path, kFileNameChassisType, &chassis_type_str)) {
    uint64_t chassis_type;
    if (base::StringToUint64(chassis_type_str, &chassis_type)) {
      dmi_info->chassis_type = mojom::NullableUint64::New(chassis_type);
    } else {
      SetError(mojom::ErrorType::kParseError,
               base::StringPrintf("Failed to convert chassis_type: %s",
                                  chassis_type_str.c_str()));
      return false;
    }
  }

  info_->dmi_info = std::move(dmi_info);
  return true;
}

bool State::FetchCachedVpdInfo() {
  auto vpd_info = mojom::VpdInfo::New();

  const auto ro_path = context_->root_dir().Append(kRelativePathVpdRo);
  ReadAndTrimString(ro_path, kFileNameMfgDate, &vpd_info->mfg_date);
  ReadAndTrimString(ro_path, kFileNameModelName, &vpd_info->model_name);
  ReadAndTrimString(ro_path, kFileNameRegion, &vpd_info->region);
  ReadAndTrimString(ro_path, kFileNameSerialNumber, &vpd_info->serial_number);
  ReadAndTrimString(ro_path, kFileNameOemName, &vpd_info->oem_name);
  if (context_->system_config()->HasSkuNumber() &&
      !ReadAndTrimString(ro_path, kFileNameSkuNumber, &vpd_info->sku_number)) {
    SetError(mojom::ErrorType::kFileReadError,
             base::StringPrintf("Unable to read VPD file \"%s\" at path: %s",
                                kFileNameSkuNumber, ro_path.value().c_str()));
    return false;
  }

  const auto rw_path = context_->root_dir().Append(kRelativePathVpdRw);
  ReadAndTrimString(rw_path, kFileNameActivateDate, &vpd_info->activate_date);

  if (!base::DirectoryExists(ro_path) && !base::DirectoryExists(rw_path)) {
    // If both the ro and rw path don't exist, sets the whole
    // vpd_info to nullptr. This indicates that the vpd doesn't
    // exist on this platform. It is considered as successful.
    info_->vpd_info = nullptr;
  } else {
    info_->vpd_info = std::move(vpd_info);
  }
  return true;
}

template <typename StringType>
bool State::GetLsbReleaseValue(const std::string& field, StringType& out_str) {
  std::string out_raw;
  if (base::SysInfo::GetLsbReleaseValue(field, &out_raw)) {
    out_str = out_raw;
    return true;
  }

  SetError(mojom::ErrorType::kFileReadError,
           base::StringPrintf("Unable to read %s from /etc/lsb-release",
                              field.c_str()));
  return false;
}

bool State::FetchOsVersion(mojom::OsVersionPtr& os_version) {
  os_version = mojom::OsVersion::New();
  if (!GetLsbReleaseValue("CHROMEOS_RELEASE_CHROME_MILESTONE",
                          os_version->release_milestone)) {
    return false;
  }
  if (!GetLsbReleaseValue("CHROMEOS_RELEASE_BUILD_NUMBER",
                          os_version->build_number)) {
    return false;
  }
  if (!GetLsbReleaseValue("CHROMEOS_RELEASE_BRANCH_NUMBER",
                          os_version->branch_number)) {
    return false;
  }
  if (!GetLsbReleaseValue("CHROMEOS_RELEASE_PATCH_NUMBER",
                          os_version->patch_number)) {
    return false;
  }
  if (!GetLsbReleaseValue("CHROMEOS_RELEASE_TRACK",
                          os_version->release_channel)) {
    return false;
  }
  return true;
}

void State::FetchBootMode(mojom::BootMode& boot_mode) {
  // Default to unknown if there's no match.
  boot_mode = mojom::BootMode::kUnknown;

  std::string cmdline;
  const auto path = context_->root_dir().Append(kFilePathProcCmdline);
  if (!ReadAndTrimString(path, &cmdline))
    return;

  auto tokens = base::SplitString(cmdline, " ", base::TRIM_WHITESPACE,
                                  base::SPLIT_WANT_NONEMPTY);
  for (const auto& token : tokens) {
    if (token == "cros_secure") {
      boot_mode = mojom::BootMode::kCrosSecure;
      break;
    }
    if (token == "cros_efi") {
      boot_mode = mojom::BootMode::kCrosEfi;
      return;
    }
    if (token == "cros_legacy") {
      boot_mode = mojom::BootMode::kCrosLegacy;
      break;
    }
  }
}

bool State::FetchOsInfo() {
  auto os_info = mojom::OsInfo::New();
  if (!FetchOsVersion(os_info->os_version))
    return false;
  os_info->code_name = context_->system_config()->GetCodeName();
  os_info->marketing_name = context_->system_config()->GetMarketingName();

  // Note that the following fields, oem_name, efi_platform_size and boot_mode,
  // may be further modified. See `State::Fetch()`.
  os_info->oem_name = context_->system_config()->GetOemName();
  os_info->efi_platform_size = mojom::OsInfo::EfiPlatformSize::kUnknown;
  FetchBootMode(os_info->boot_mode);

  info_->os_info = std::move(os_info);
  return true;
}

bool IsUEFISecureBoot(const std::string& content) {
  if (content.size() != 5) {
    LOG(ERROR) << "Expected 5 bytes from UEFISecureBoot "
                  "variable, but got "
               << content.size() << " bytes.";
    return false;
  }
  // The first four bytes are the "attributes" of the variable.
  // The last byte indicates the secure boot state.
  switch (content.back()) {
    case '\x00':
      return false;
    case '\x01':
      return true;
    default:
      LOG(ERROR) << "Unexpected secure boot value: "
                 << (uint32_t)(content.back());
      return false;
  }
}

void State::HandleSecureBootResponse(
    const std::optional<std::string>& content) {
  DCHECK_EQ(info_->os_info->boot_mode, mojom::BootMode::kCrosEfi);
  if (content && IsUEFISecureBoot(content.value()))
    info_->os_info->boot_mode = mojom::BootMode::kCrosEfiSecure;
}

void State::HandleEfiPlatformSize(const std::optional<std::string>& content) {
  if (!content)
    return;
  std::string content_trimmed;
  base::TrimWhitespaceASCII(content.value(), base::TRIM_ALL, &content_trimmed);
  if (content_trimmed == "64") {
    info_->os_info->efi_platform_size = mojom::OsInfo::EfiPlatformSize::k64;
  } else if (content_trimmed == "32") {
    info_->os_info->efi_platform_size = mojom::OsInfo::EfiPlatformSize::k32;
  } else {
    info_->os_info->efi_platform_size =
        mojom::OsInfo::EfiPlatformSize::kUnknown;
    LOG(ERROR) << "Got unknown efi platform size: " << content_trimmed;
  }
}

void State::SetError(mojom::ErrorType type, const std::string& message) {
  LOG(ERROR) << message;
  // Ignore the error if there is already an error to be returned.
  if (!error_)
    error_ = mojom::ProbeError::New(type, message);
}

void State::HandlePsrInfo(mojom::PsrInfoPtr psr_info_ptr,
                          const std::optional<std::string>& err) {
  if (err.has_value())
    return;

  info_->psr_info = std::move(psr_info_ptr);
}

void State::HandleResult(FetchSystemInfoCallback callback, bool success) {
  if (!success) {
    SetError(mojom::ErrorType::kServiceUnavailable,
             "Some async task cannot be finish.");
  }

  std::move(callback).Run(
      error_ ? mojom::SystemResult::NewError(std::move(error_))
             : mojom::SystemResult::NewSystemInfo(std::move(info_)));
}

// static
void State::Fetch(Context* context, FetchSystemInfoCallback callback) {
  auto state = std::make_unique<State>(context);
  State* state_ptr = state.get();
  CallbackBarrier barrier{base::BindOnce(&State::HandleResult, std::move(state),
                                         std::move(callback))};

  if (!state_ptr->FetchCachedVpdInfo() || !state_ptr->FetchDmiInfo() ||
      !state_ptr->FetchOsInfo())
    return;

  // `base::Unretained` is safe because `state` is hold by CallbackBarrier.
  if (state_ptr->info_->os_info->boot_mode == mojom::BootMode::kCrosEfi) {
    state_ptr->context_->executor()->ReadFile(
        mojom::Executor::File::kUEFISecureBootVariable,
        barrier.Depend(base::BindOnce(&State::HandleSecureBootResponse,
                                      base::Unretained(state_ptr))));
    state_ptr->context_->executor()->ReadFile(
        mojom::Executor::File::kUEFIPlatformSize,
        barrier.Depend(base::BindOnce(&State::HandleEfiPlatformSize,
                                      base::Unretained(state_ptr))));
  }

  state_ptr->context_->executor()->GetPsr(barrier.Depend(
      base::BindOnce(&State::HandlePsrInfo, base::Unretained(state_ptr))));

  // OEM name in cros-config is usually filled after (or right before) launch.
  // Fallback to VPD (vpd.ro.oem-name) if it’s missing in cros-config. Note that
  // VPD info may be null, for example, on Flex devices & VM.
  if (!state_ptr->info_->os_info->oem_name.has_value() &&
      !state_ptr->info_->vpd_info.is_null())
    state_ptr->info_->os_info->oem_name = state_ptr->info_->vpd_info->oem_name;
}

}  // namespace

void FetchSystemInfo(Context* context, FetchSystemInfoCallback callback) {
  State::Fetch(context, std::move(callback));
}

}  // namespace diagnostics
