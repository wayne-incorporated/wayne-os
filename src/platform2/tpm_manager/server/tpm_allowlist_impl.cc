// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tpm_manager/server/tpm_allowlist_impl.h"

#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <libhwsec-foundation/tpm/tpm_version.h>

namespace {

#if USE_TPM_DYNAMIC

constexpr char kTpmForceAllowTpmFile[] = "/var/lib/tpm_manager/force_allow_tpm";
constexpr char kNoPreinitFlagFile[] = "/run/tpm_manager/no_preinit";

// The path to check the TPM is enabled or not.
constexpr char kTpmEnabledFile[] = "/sys/class/tpm/tpm0/enabled";

// Simulator Vendor ID ("SIMU").
constexpr uint32_t kVendorIdSimulator = 0x53494d55;
// STMicroelectronics Vendor ID ("STM ").
constexpr uint32_t kVendorIdStm = 0x53544D20;

// The location of TPM DID & VID information.
constexpr char kTpmDidVidPath[] = "/sys/class/tpm/tpm0/did_vid";
// The location of system vendor information.
constexpr char kSysVendorPath[] = "/sys/class/dmi/id/sys_vendor";
// The location of product name information.
constexpr char kProductNamePath[] = "/sys/class/dmi/id/product_name";
// The location of product family information.
constexpr char kProductFamilyPath[] = "/sys/class/dmi/id/product_family";

struct TpmVidDid {
  uint16_t vendor_id;
  uint16_t device_id;
};

constexpr uint16_t kTpmVidAtmel = 0x1114;
constexpr uint16_t kTpmVidIbm = 0x1014;
constexpr uint16_t kTpmVidWinbond = 0x1050;
constexpr uint16_t kTpmVidIfx = 0x15D1;

constexpr TpmVidDid kTpm1DidVidAllowlist[] = {
    // Atmel TPM used in some Dell Latitudes.
    TpmVidDid{kTpmVidAtmel, 0x3204},
    // Emulated TPM provided by the swtpm program, used with QEMU.
    TpmVidDid{kTpmVidIbm, 0x1},
    // Enable TPM chip in Toshiba TCXWave 6140 tablet kiosk.
    TpmVidDid{kTpmVidWinbond, 0xFE},
    // The vendor is INFINEON, HP Elitebook 840 G1.
    TpmVidDid{kTpmVidIfx, 0xB},
    // The vendor is INFINEON, HP Elitebook 840 G2.
    TpmVidDid{kTpmVidIfx, 0x1A},
    // The vendor is INFINEON, HP Elitebook 840 G3.
    TpmVidDid{kTpmVidIfx, 0x1B},
};

constexpr TpmVidDid kTpm2DidVidAllowlist[] = {
    // Emulated TPM provided by the swtpm program, used with QEMU.
    TpmVidDid{kTpmVidIbm, 0x1},
};

struct DeviceModel {
  const char* sys_vendor;
  const char* product_name;
  TpmVidDid vid_did;
};

struct DeviceFamily {
  const char* sys_vendor;
  const char* product_family;
  uint32_t tpm_vendor_id;
};

constexpr DeviceModel kTpm2ModelsAllowlist[] = {
    DeviceModel{"Dell Inc.", "Latitude 7490", TpmVidDid{kTpmVidWinbond, 0xFC}},
};

constexpr DeviceFamily kTpm2FamiliesAllowlist[] = {
    DeviceFamily{"LENOVO", "ThinkPad X1 Carbon Gen 8", kVendorIdStm},
    DeviceFamily{"LENOVO", "ThinkPad X1 Carbon Gen 9", kVendorIdStm},
};

std::optional<bool> IsTpmFileEnabled() {
  base::FilePath file_path(kTpmEnabledFile);
  std::string file_content;

  if (!base::ReadFileToString(file_path, &file_content)) {
    return {};
  }

  std::string enabled_str;
  base::TrimWhitespaceASCII(file_content, base::TRIM_ALL, &enabled_str);

  int enabled = 0;
  if (!base::StringToInt(enabled_str, &enabled)) {
    LOG(ERROR) << "enabled is not a number";
    return {};
  }
  return static_cast<bool>(enabled);
}

bool GetDidVid(uint16_t* did, uint16_t* vid) {
  base::FilePath file_path(kTpmDidVidPath);
  std::string did_vid_s;

  if (!base::ReadFileToString(file_path, &did_vid_s)) {
    return false;
  }

  uint32_t did_vid = 0;
  if (sscanf(did_vid_s.c_str(), "0x%X", &did_vid) != 1) {
    LOG(ERROR) << __func__ << ": Failed to parse TPM DID & VID: " << did_vid_s;
    return false;
  }

  *vid = did_vid & 0xFFFF;
  *did = did_vid >> 16;

  return true;
}

bool GetSysVendor(std::string* sys_vendor) {
  base::FilePath file_path(kSysVendorPath);
  std::string file_content;

  if (!base::ReadFileToString(file_path, &file_content)) {
    return false;
  }

  base::TrimWhitespaceASCII(file_content, base::TRIM_ALL, sys_vendor);
  return true;
}

bool GetProductName(std::string* product_name) {
  base::FilePath file_path(kProductNamePath);
  std::string file_content;

  if (!base::ReadFileToString(file_path, &file_content)) {
    return false;
  }

  base::TrimWhitespaceASCII(file_content, base::TRIM_ALL, product_name);
  return true;
}

bool GetProductFamily(std::string* product_family) {
  base::FilePath file_path(kProductFamilyPath);
  std::string file_content;

  if (!base::ReadFileToString(file_path, &file_content)) {
    return false;
  }

  base::TrimWhitespaceASCII(file_content, base::TRIM_ALL, product_family);
  return true;
}

std::optional<bool> IsForceAllow() {
  base::FilePath file_path(kTpmForceAllowTpmFile);
  std::string file_content;

  if (!base::ReadFileToString(file_path, &file_content)) {
    return {};
  }

  std::string force_allow_str;
  base::TrimWhitespaceASCII(file_content, base::TRIM_ALL, &force_allow_str);

  int force_allow = 0;
  if (!base::StringToInt(force_allow_str, &force_allow)) {
    LOG(ERROR) << "force_allow is not a number";
    return {};
  }
  return static_cast<bool>(force_allow);
}

#endif

}  // namespace

namespace tpm_manager {

TpmAllowlistImpl::TpmAllowlistImpl(TpmStatus* tpm_status)
    : tpm_status_(tpm_status) {
  CHECK(tpm_status_);
}

bool TpmAllowlistImpl::IsAllowed() {
#if !USE_TPM_DYNAMIC
  // Allow all kinds of TPM if we are not using runtime TPM selection.
  return true;
#else

  std::optional<bool> force_allow = IsForceAllow();
  if (force_allow.has_value()) {
    return force_allow.value();
  }

  if (USE_OS_INSTALL_SERVICE) {
    if (base::PathExists(base::FilePath(kNoPreinitFlagFile))) {
      // If USE_OS_INSTALL_SERVICE, kNoPreinitFlagFile will be touched in the
      // pre-start phase of tpm_managerd if the OS is running from installer
      // (see check_tpm_preinit_condition.cc). Note that under current scope
      // USE_OS_INSTALL_SERVICE and USE_TPM_DYNAMIC will always have the same
      // value (and only in reven case both flags are true).
      LOG(WARNING) << __func__
                   << ": Disallow TPM when OS running from installer.";
      return false;
    }
  }

  if (!tpm_status_->IsTpmEnabled()) {
    LOG(WARNING) << __func__ << ": Disallow the disabled TPM.";
    return false;
  }

  TPM_SELECT_BEGIN;

  TPM2_SECTION({
    uint32_t family;
    uint64_t spec_level;
    uint32_t manufacturer;
    uint32_t tpm_model;
    uint64_t firmware_version;
    std::vector<uint8_t> vendor_specific;
    if (!tpm_status_->GetVersionInfo(&family, &spec_level, &manufacturer,
                                     &tpm_model, &firmware_version,
                                     &vendor_specific)) {
      LOG(ERROR) << __func__ << ": failed to get version info from tpm status.";
      return false;
    }

    // Allow the tpm2-simulator.
    if (manufacturer == kVendorIdSimulator) {
      return true;
    }

    std::string sys_vendor;
    std::string product_name;
    std::string product_family;

    if (!GetSysVendor(&sys_vendor)) {
      LOG(ERROR) << __func__ << ": Failed to get the system vendor.";
      return false;
    }
    if (!GetProductName(&product_name)) {
      LOG(ERROR) << __func__ << ": Failed to get the product name.";
      return false;
    }
    if (!GetProductFamily(&product_family)) {
      LOG(ERROR) << __func__ << ": Failed to get the product family.";
      return false;
    }

    for (const DeviceFamily& match : kTpm2FamiliesAllowlist) {
      if (sys_vendor == match.sys_vendor &&
          product_family == match.product_family &&
          manufacturer == match.tpm_vendor_id) {
        return true;
      }
    }

    uint16_t device_id;
    uint16_t vendor_id;

    if (!GetDidVid(&device_id, &vendor_id)) {
      LOG(ERROR) << __func__ << ": Failed to get the TPM DID & VID.";
      return false;
    }

    for (const DeviceModel& match : kTpm2ModelsAllowlist) {
      if (sys_vendor == match.sys_vendor &&
          product_name == match.product_name) {
        if (vendor_id == match.vid_did.vendor_id &&
            device_id == match.vid_did.device_id) {
          return true;
        }
      }
    }

    for (const TpmVidDid& match : kTpm2DidVidAllowlist) {
      if (device_id == match.device_id && vendor_id == match.vendor_id) {
        return true;
      }
    }

    LOG(INFO) << "Not allowed TPM2.0:";
    LOG(INFO) << "  System Vendor: " << sys_vendor;
    LOG(INFO) << "  Product Name: " << product_name;
    LOG(INFO) << "  Product Family: " << product_family;
    LOG(INFO) << "  TPM Vendor ID: " << std::hex << vendor_id;
    LOG(INFO) << "  TPM Device ID: " << std::hex << device_id;

    return false;
  });

  TPM1_SECTION({
    std::optional<bool> is_enabled = IsTpmFileEnabled();
    if (is_enabled.has_value() && !is_enabled.value()) {
      LOG(WARNING) << __func__ << ": Disallow the disabled TPM.";
      return false;
    }

    uint16_t device_id;
    uint16_t vendor_id;

    if (!GetDidVid(&device_id, &vendor_id)) {
      LOG(ERROR) << __func__ << ": Failed to get the TPM DID & VID.";
      return false;
    }

    for (const TpmVidDid& match : kTpm1DidVidAllowlist) {
      if (device_id == match.device_id && vendor_id == match.vendor_id) {
        return true;
      }
    }

    LOG(INFO) << "Not allowed TPM1.2:";
    LOG(INFO) << "  TPM Vendor ID: " << std::hex << vendor_id;
    LOG(INFO) << "  TPM Device ID: " << std::hex << device_id;

    return false;
  });

  OTHER_TPM_SECTION({
    // We don't allow the other TPM cases.
    return false;
  });

  TPM_SELECT_END;
#endif
}

}  // namespace tpm_manager
