// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_VPD_UTILS_IMPL_H_
#define RMAD_UTILS_VPD_UTILS_IMPL_H_

#include "rmad/utils/vpd_utils.h"

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "rmad/utils/cmd_utils.h"

namespace rmad {

// Calls `vpd` command to set/get RO/RW VPD values. The subprocess needs access
// to /dev/mem and has CAP_SYS_RAWIO,CAP_DAC_OVERRIDE capability if not running
// as root.
class VpdUtilsImpl : public VpdUtils {
 public:
  VpdUtilsImpl();
  explicit VpdUtilsImpl(std::unique_ptr<CmdUtils> cmd_utils);
  ~VpdUtilsImpl() override;

  bool GetSerialNumber(std::string* serial_number) const override;
  bool GetCustomLabelTag(std::string* custom_label_tag,
                         bool use_legacy) const override;
  bool GetRegion(std::string* region) const override;
  bool GetCalibbias(const std::vector<std::string>& entries,
                    std::vector<int>* calibbias) const override;
  bool GetRegistrationCode(std::string* ubind,
                           std::string* gbind) const override;
  bool GetStableDeviceSecret(std::string* stable_device_secret) const override;
  bool SetSerialNumber(const std::string& serial_number) override;
  bool SetCustomLabelTag(const std::string& custom_label_tag,
                         bool use_legacy) override;
  bool SetRegion(const std::string& region) override;
  bool SetCalibbias(const std::map<std::string, int>& calibbias) override;
  bool SetRegistrationCode(const std::string& ubind,
                           const std::string& gbind) override;
  bool SetStableDeviceSecret(const std::string& stable_device_secret) override;
  bool RemoveCustomLabelTag() override;
  bool FlushOutRoVpdCache() override;
  bool FlushOutRwVpdCache() override;
  void ClearRoVpdCache() override;
  void ClearRwVpdCache() override;

 protected:
  bool SetRoVpd(const std::map<std::string, std::string>& key_value_map);
  bool GetRoVpd(const std::string& key, std::string* value) const;
  bool DelRoVpd(const std::string& key);
  bool SetRwVpd(const std::map<std::string, std::string>& key_value_map);
  bool GetRwVpd(const std::string& key, std::string* value) const;
  bool DelRwVpd(const std::string& key);

 private:
  // RO VPD
  std::map<std::string, std::string> cache_ro_;
  // RW VPD
  std::map<std::string, std::string> cache_rw_;

  std::unique_ptr<CmdUtils> cmd_utils_;
};

}  // namespace rmad

#endif  // RMAD_UTILS_VPD_UTILS_IMPL_H_
