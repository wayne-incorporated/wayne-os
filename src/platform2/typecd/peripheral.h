// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TYPECD_PERIPHERAL_H_
#define TYPECD_PERIPHERAL_H_

#include <map>
#include <memory>
#include <string>
#include <utility>

#include <base/files/file_path.h>
#include <gtest/gtest_prod.h>

#include "typecd/alt_mode.h"

namespace typecd {

enum class PDRevision {
  kNone = 0,
  k20,
  k30,
  kMaxValue = k30,
};

// This is a base class which can represent the components connected to a Type C
// Port. These components (Partner and Cable) have common properties like PD
// identity, so it is worthwhile to abstract those into a common base class
// which they can then derive from.
class Peripheral {
 public:
  explicit Peripheral(const base::FilePath& syspath,
                      std::string type = "Peripheral");
  Peripheral(const Peripheral&) = delete;
  Peripheral& operator=(const Peripheral&) = delete;

  // Setters and Getters for PD identity information.
  void SetIdHeaderVDO(uint32_t id_header_vdo) {
    id_header_vdo_ = id_header_vdo;
  }
  void SetCertStatVDO(uint32_t cert_stat_vdo) {
    cert_stat_vdo_ = cert_stat_vdo;
  }
  void SetProductVDO(uint32_t product_vdo) { product_vdo_ = product_vdo; }

  void SetProductTypeVDO1(uint32_t product_type_vdo) {
    product_type_vdo1_ = product_type_vdo;
  }
  void SetProductTypeVDO2(uint32_t product_type_vdo) {
    product_type_vdo2_ = product_type_vdo;
  }
  void SetProductTypeVDO3(uint32_t product_type_vdo) {
    product_type_vdo3_ = product_type_vdo;
  }
  void SetPDRevision(PDRevision pd_revision) { pd_revision_ = pd_revision; }

  uint32_t GetIdHeaderVDO() { return id_header_vdo_; }
  uint32_t GetCertStateVDO() { return cert_stat_vdo_; }
  uint32_t GetProductVDO() { return product_vdo_; }

  uint32_t GetProductTypeVDO1() { return product_type_vdo1_; }
  uint32_t GetProductTypeVDO2() { return product_type_vdo2_; }
  uint32_t GetProductTypeVDO3() { return product_type_vdo3_; }
  PDRevision GetPDRevision() { return pd_revision_; }

 protected:
  base::FilePath GetSysPath() { return syspath_; }

  // Get the PD Identity VDOs from sysfs. This is called during Peripheral
  // creation and other times (e.g "change" udev events). We mark this as void
  // as Peripheral registration should not fail if we are unable to grab the
  // VDOs.
  void UpdatePDIdentityVDOs();

  // Get the PD revision from sysfs. This is called during Peripheral
  // creation and other times (e.g "change" udev events). We mark this as void
  // as Peripheral registration should not fail if we are unable to grab the
  // PD revision.
  void UpdatePDRevision();

 private:
  friend class PartnerTest;
  FRIEND_TEST(PartnerTest, AltModeManualAddition);
  FRIEND_TEST(PartnerTest, PDIdentityScan);
  FRIEND_TEST(PeripheralTest, CheckPDRevision);

  // PD Identity Data objects; expected to be read from the peripheral sysfs.
  uint32_t id_header_vdo_;
  uint32_t cert_stat_vdo_;
  uint32_t product_vdo_;
  uint32_t product_type_vdo1_;
  uint32_t product_type_vdo2_;
  uint32_t product_type_vdo3_;
  PDRevision pd_revision_;
  // Helper member to denote the type of Peripheral (Partner/Cable) while
  // printing log messages. For the base class, set it to "Peripheral".
  std::string type_;
  // Sysfs path used to access peripheral PD information.
  base::FilePath syspath_;
};

}  // namespace typecd

#endif  // TYPECD_PERIPHERAL_H_
