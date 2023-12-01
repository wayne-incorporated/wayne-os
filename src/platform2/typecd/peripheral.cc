// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "typecd/peripheral.h"

#include <iomanip>
#include <string>

#include <base/logging.h>
#include <base/strings/string_util.h>
#include <re2/re2.h>

#include "typecd/pd_vdo_constants.h"
#include "typecd/utils.h"

namespace {
constexpr char kPDRevisionRegex[] = R"((\d)\.\d)";

// We don't want to display VID in the logs, so zero it out.
uint32_t ObfuscatedIdHeaderVDO(uint32_t id_header_vdo) {
  return id_header_vdo & ~typecd::kIdHeaderVDOVidMask;
}

// We don't want to display PID in the logs, so zero it out.
uint32_t ObfuscatedProductVDO(uint32_t product_vdo) {
  return product_vdo & ~typecd::kProductVDOPidMaskWithOffset;
}

}  // namespace

namespace typecd {

Peripheral::Peripheral(const base::FilePath& syspath, std::string type)
    : id_header_vdo_(0),
      cert_stat_vdo_(0),
      product_vdo_(0),
      pd_revision_(PDRevision::kNone),
      type_(type),
      syspath_(syspath) {
  UpdatePDIdentityVDOs();
  UpdatePDRevision();
}

void Peripheral::UpdatePDIdentityVDOs() {
  // If the Product VDO is non-zero, we can be assured that it's been parsed
  // already, so we can avoid parsing it again.
  if (GetProductVDO() != 0) {
    LOG(INFO)
        << "PD identity VDOs already registered, skipping re-registration.";
    return;
  }
  // Create the various sysfs file paths for PD Identity.
  auto cert_stat = syspath_.Append("identity").Append("cert_stat");
  auto product = syspath_.Append("identity").Append("product");
  auto id_header = syspath_.Append("identity").Append("id_header");
  auto product_type1 = syspath_.Append("identity").Append("product_type_vdo1");
  auto product_type2 = syspath_.Append("identity").Append("product_type_vdo2");
  auto product_type3 = syspath_.Append("identity").Append("product_type_vdo3");

  uint32_t product_vdo;
  uint32_t cert_stat_vdo;
  uint32_t id_header_vdo;
  uint32_t product_type_vdo1;
  uint32_t product_type_vdo2;
  uint32_t product_type_vdo3;

  if (!ReadHexFromPath(product, &product_vdo))
    return;
  LOG(INFO) << type_ << " Product VDO: " << std::hex << std::setfill('0')
            << std::setw(8) << ObfuscatedProductVDO(product_vdo);

  if (!ReadHexFromPath(cert_stat, &cert_stat_vdo))
    return;
  LOG(INFO) << type_ << " Cert stat VDO: " << std::hex << cert_stat_vdo;

  if (!ReadHexFromPath(id_header, &id_header_vdo))
    return;
  LOG(INFO) << type_ << " Id Header VDO: " << std::hex << std::setfill('0')
            << std::setw(8) << ObfuscatedIdHeaderVDO(id_header_vdo);

  if (!ReadHexFromPath(product_type1, &product_type_vdo1))
    return;
  LOG(INFO) << type_ << " Product Type VDO 1: " << std::hex
            << product_type_vdo1;

  if (!ReadHexFromPath(product_type2, &product_type_vdo2))
    return;
  LOG(INFO) << type_ << " Product Type VDO 2: " << std::hex
            << product_type_vdo2;

  if (!ReadHexFromPath(product_type3, &product_type_vdo3))
    return;
  LOG(INFO) << type_ << " Product Type VDO 3: " << std::hex
            << product_type_vdo3;

  SetIdHeaderVDO(id_header_vdo);
  SetProductVDO(product_vdo);
  SetCertStatVDO(cert_stat_vdo);
  SetProductTypeVDO1(product_type_vdo1);
  SetProductTypeVDO2(product_type_vdo2);
  SetProductTypeVDO3(product_type_vdo3);
}

void Peripheral::UpdatePDRevision() {
  if (GetPDRevision() != PDRevision::kNone)
    return;

  auto path = syspath_.Append("usb_power_delivery_revision");

  std::string val_str;
  if (!base::ReadFileToString(path, &val_str)) {
    LOG(ERROR) << "Couldn't read value from path " << path;
    return;
  }
  base::TrimWhitespaceASCII(val_str, base::TRIM_TRAILING, &val_str);

  int maj;
  if (!RE2::FullMatch(val_str, kPDRevisionRegex, &maj)) {
    LOG(ERROR) << "PD revision in incorrect format: " << val_str;
    return;
  }

  // TODO(pmalani): Handle min revision correctly. For now, we just use the
  // major revision.
  if (maj == 3) {
    SetPDRevision(PDRevision::k30);
  } else if (maj == 2) {
    SetPDRevision(PDRevision::k20);
  } else {
    LOG(INFO) << "Unsupported PD revision: " << val_str;
    return;
  }

  LOG(INFO) << "PD revision: " << val_str;
}

}  // namespace typecd
