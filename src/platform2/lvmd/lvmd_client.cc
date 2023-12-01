// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sysexits.h>
#include <unistd.h>

#include <iostream>
#include <string>
#include <utility>

#include <base/logging.h>
#include <base/json/json_writer.h>
#include <base/strings/stringprintf.h>
#include <base/values.h>
#include <brillo/daemons/daemon.h>
#include <brillo/errors/error.h>
#include <brillo/flag_helper.h>
#include <dbus/bus.h>
#include <lvmd/proto_bindings/lvmd.pb.h>

#include "lvmd/dbus-proxies.h"

using org::chromium::LvmdProxy;

namespace {

const char kDevicePath[] = "device_path";
const char kFreeBytes[] = "free_bytes";
const char kName[] = "name";
const char kPath[] = "path";
const char kTotalBytes[] = "total_bytes";

const char kLogicalVolume[] = "logical_volume";
const char kLogicalVolumeList[] = "logical_volume_list";
const char kPhysicalVolume[] = "physical_volume";
const char kThinpool[] = "thinpool";
const char kVolumeGroup[] = "volume_group";

std::string ErrorPtrToStr(const brillo::ErrorPtr& err) {
  return base::StringPrintf("Domain=%s Error Code=%s Error Message=%s",
                            err->GetDomain().c_str(), err->GetCode().c_str(),
                            err->GetMessage().c_str());
}

int PrintDict(const base::Value::Dict& dict) {
  std::string json;
  if (!base::JSONWriter::WriteWithOptions(
          dict, base::JSONWriter::OPTIONS_PRETTY_PRINT, &json)) {
    LOG(ERROR) << "Failed to write json.";
    return EX_SOFTWARE;
  }
  std::cout << json;
  return EX_OK;
}

base::Value::Dict Dict() {
  return base::Value::Dict();
}

base::Value::Dict ToDict(const lvmd::PhysicalVolume& pv) {
  auto pv_dict = Dict().Set(kDevicePath, pv.device_path());

  auto dict = Dict().Set(kPhysicalVolume, std::move(pv_dict));
  return dict;
}

base::Value::Dict ToDict(const lvmd::VolumeGroup& vg) {
  auto vg_dict = Dict().Set(kName, vg.name());

  auto dict = Dict().Set(kVolumeGroup, std::move(vg_dict));
  return dict;
}

base::Value::Dict ToDict(const lvmd::Thinpool& thinpool) {
  auto vg_dict = ToDict(thinpool.volume_group());
  auto thinpool_dict =
      Dict()
          .Set(kVolumeGroup, std::move(vg_dict))
          .Set(kName, thinpool.name())
          .Set(kTotalBytes, static_cast<int>(thinpool.total_bytes()))
          .Set(kFreeBytes, static_cast<int>(thinpool.free_bytes()));

  auto dict = Dict().Set(kThinpool, std::move(thinpool_dict));
  return dict;
}

base::Value::Dict ToDict(const lvmd::LogicalVolume& lv) {
  auto lv_dict = Dict().Set(kName, lv.name()).Set(kPath, lv.path());

  auto dict = Dict().Set(kLogicalVolume, std::move(lv_dict));
  return dict;
}

base::Value::Dict ToDict(const lvmd::LogicalVolumeList& lvs) {
  auto lv_list = base::Value::List();
  for (const auto& lv : lvs.logical_volume()) {
    lv_list.Append(ToDict(lv));
  }

  auto dict = Dict().Set(kLogicalVolumeList, base::Value(std::move(lv_list)));
  return dict;
}

class LvmdClient : public brillo::Daemon {
 public:
  LvmdClient(int argc, const char** argv) : argc_(argc), argv_(argv) {}
  ~LvmdClient() override = default;

  // Delete copy constructor and assignment operator.
  LvmdClient(const LvmdClient&) = delete;
  LvmdClient& operator=(const LvmdClient&) = delete;

  int OnEventLoopStarted() override;

 private:
  // Initialize the client.
  int Init();

  // Checks for exclusivity of boolean flags.
  bool CheckExclusiveFlags(const std::vector<bool>& flags);

  // Process flags for correctness and execute.
  int ProcessFlags();

  // Helpers when processing given flags.
  // `--show` helpers:
  int GetPhysicalVolume(const std::string& device_path);
  int GetVolumeGroup(const std::string& device_path);
  int GetThinpool(const std::string& vg_name, const std::string& thinpool_name);
  int ListLogicalVolumes(const std::string& vg_name);
  int GetLogicalVolume(const std::string& vg_name, const std::string& lv_name);
  // `--create` helpers:
  int CreateLogicalVolume(const std::string& vg_name,
                          const std::string& thinpool_name,
                          const std::string& lv_name,
                          int64_t size);
  // `--remove` helpers:
  int RemoveLogicalVolume(const std::string& vg_name,
                          const std::string& lv_name);

  // `--activate` helpers:
  // `--deactivate` helpers:
  int ToggleLogicalVolumeActivation(const std::string& vg_name,
                                    const std::string& lv_name,
                                    bool activate);

  // argc and argv passed to main().
  int argc_;
  const char** argv_;

  std::unique_ptr<LvmdProxy> lvmd_proxy_;
};

int LvmdClient::Init() {
  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<dbus::Bus> bus{new dbus::Bus{options}};

  if (!bus->Connect()) {
    LOG(ERROR) << "Failed to connect to DBus.";
    return EX_UNAVAILABLE;
  }

  lvmd_proxy_ = std::make_unique<LvmdProxy>(bus);

  return EX_OK;
}

bool LvmdClient::CheckExclusiveFlags(const std::vector<bool>& flags) {
  return std::count(std::begin(flags), std::end(flags), true) == 1;
}

int LvmdClient::ProcessFlags() {
  // Exclusive top level lvm actions.
  DEFINE_bool(show, false, "Show action.");
  DEFINE_bool(create, false, "Create action.");
  DEFINE_bool(remove, false, "Remove action.");
  DEFINE_bool(activate, false, "Activate action.");
  DEFINE_bool(deactivate, false, "Deactivation action.");

  // Exclusive top level lvm devices.
  DEFINE_bool(pv, false, "Get PhysicalVolume.");
  DEFINE_bool(vg, false, "Get VolumeGroup.");
  DEFINE_bool(thinpool, false, "Get Thinpool.");
  DEFINE_bool(lvs, false, "Get LogicalVolumes.");
  DEFINE_bool(lv, false, "Get LogicalVolume.");

  // Used in `--show`:
  //   `--pv`
  //   `--vg`
  DEFINE_string(device_path, "", "Path to a device.");
  // Used in `--show`:
  //   `--thinpool`
  //   `--lvs`
  //   `--lv`
  // Used in `--create`:
  //   `--lv`
  // Used in `--remove`:
  //   `--lv`
  // Used in `--activate`:
  //   `--lv`
  // Used in `--deactivate`:
  //   `--lv`
  DEFINE_string(vg_name, "", "Volume Group name.");
  // Used in `--show`:
  //   `--thinpool`
  // Used in `--create`:
  //   `--lv`
  DEFINE_string(thinpool_name, "", "Thinpool name.");
  // Used in `--show`:
  //   `--lv`
  // Used in `--create`:
  //   `--lv`
  // Used in `--remove`:
  //   `--lv`
  // Used in `--activate`:
  //   `--lv`
  // Used in `--deactivate`:
  //   `--lv`
  DEFINE_string(lv_name, "", "Logical Volume name.");
  // Used in `--create`:
  //   `--lv`
  DEFINE_int64(size, -1, "Size in MiB.");

  brillo::FlagHelper::Init(argc_, argv_, "Lvmd Client");

  if (!CheckExclusiveFlags({
          FLAGS_show,
          FLAGS_create,
          FLAGS_remove,
          FLAGS_activate,
          FLAGS_deactivate,
      })) {
    LOG(ERROR) << "Please provide only one of "
                  "`--show`"
                  ", "
                  "`--create`"
                  ", "
                  "`--remove`"
                  ", "
                  "`--activate`"
                  ", "
                  "`--deactivate`"
                  ".";
    return EX_USAGE;
  }

  if (!CheckExclusiveFlags({
          FLAGS_pv,
          FLAGS_vg,
          FLAGS_thinpool,
          FLAGS_lvs,
          FLAGS_lv,
      })) {
    LOG(ERROR) << "Please provide only one of "
                  "`--pv`"
                  ", "
                  "`--vg`"
                  ", "
                  "`--thinpool`"
                  ", "
                  "`--lvs`"
                  ", "
                  "`--lv`"
                  ".";
    return EX_USAGE;
  }

  if (FLAGS_show) {
    if (FLAGS_pv)
      return GetPhysicalVolume(FLAGS_device_path);
    if (FLAGS_vg)
      return GetVolumeGroup(FLAGS_device_path);
    if (FLAGS_thinpool)
      return GetThinpool(FLAGS_vg_name, FLAGS_thinpool_name);
    if (FLAGS_lvs)
      return ListLogicalVolumes(FLAGS_vg_name);
    if (FLAGS_lv)
      return GetLogicalVolume(FLAGS_vg_name, FLAGS_lv_name);

    LOG(ERROR) << "`--show` is not support for this LVM device.";
    return EX_USAGE;
  }

  if (FLAGS_create) {
    if (FLAGS_lv)
      return CreateLogicalVolume(FLAGS_vg_name, FLAGS_thinpool_name,
                                 FLAGS_lv_name, FLAGS_size);

    LOG(ERROR) << "`--create` is not support for this LVM device.";
    return EX_USAGE;
  }

  if (FLAGS_remove) {
    if (FLAGS_lv)
      return RemoveLogicalVolume(FLAGS_vg_name, FLAGS_lv_name);

    LOG(ERROR) << "`--remove` is not support for this LVM device.";
    return EX_USAGE;
  }

  if (FLAGS_activate) {
    if (FLAGS_lv)
      return ToggleLogicalVolumeActivation(FLAGS_vg_name, FLAGS_lv_name,
                                           /*activate=*/true);

    LOG(ERROR) << "`--activate` is not support for this LVM device.";
    return EX_USAGE;
  }

  if (FLAGS_deactivate) {
    if (FLAGS_lv)
      return ToggleLogicalVolumeActivation(FLAGS_vg_name, FLAGS_lv_name,
                                           /*activate=*/false);

    LOG(ERROR) << "`--deactivate` is not support for this LVM device.";
    return EX_USAGE;
  }

  // Should never reach here.
  LOG(FATAL) << "Client missed handling a flag, please file a bug.";
  return EX_SOFTWARE;
}

int LvmdClient::GetPhysicalVolume(const std::string& device_path) {
  if (device_path.empty()) {
    LOG(ERROR) << "`--device_path` must be provided.";
    return EX_USAGE;
  }

  brillo::ErrorPtr err;
  lvmd::PhysicalVolume pv;
  if (!lvmd_proxy_->GetPhysicalVolume(device_path, &pv, &err)) {
    LOG(ERROR) << "Failed to get physical volume, " << ErrorPtrToStr(err);
    return EX_SOFTWARE;
  }

  return PrintDict(ToDict(pv));
}

int LvmdClient::GetVolumeGroup(const std::string& device_path) {
  if (device_path.empty()) {
    LOG(ERROR) << "`--device_path` must be provided.";
    return EX_USAGE;
  }

  lvmd::PhysicalVolume pv;
  pv.set_device_path(device_path);

  brillo::ErrorPtr err;
  lvmd::VolumeGroup vg;
  if (!lvmd_proxy_->GetVolumeGroup(pv, &vg, &err)) {
    LOG(ERROR) << "Failed to get volume group, " << ErrorPtrToStr(err);
    return EX_SOFTWARE;
  }

  return PrintDict(ToDict(vg));
}

int LvmdClient::GetThinpool(const std::string& vg_name,
                            const std::string& thinpool_name) {
  if (vg_name.empty()) {
    LOG(ERROR) << "`--vg_name` must be provided.";
    return EX_USAGE;
  }

  if (thinpool_name.empty()) {
    LOG(ERROR) << "`--thinpool_name` must be provided.";
    return EX_USAGE;
  }

  lvmd::VolumeGroup vg;
  vg.set_name(vg_name);

  brillo::ErrorPtr err;
  lvmd::Thinpool thinpool;
  if (!lvmd_proxy_->GetThinpool(vg, thinpool_name, &thinpool, &err)) {
    LOG(ERROR) << "Failed to get thinpool, " << ErrorPtrToStr(err);
    return EX_SOFTWARE;
  }

  return PrintDict(ToDict(thinpool));
}

int LvmdClient::ListLogicalVolumes(const std::string& vg_name) {
  if (vg_name.empty()) {
    LOG(ERROR) << "`--vg_name` must be provided.";
    return EX_USAGE;
  }

  lvmd::VolumeGroup vg;
  vg.set_name(vg_name);

  brillo::ErrorPtr err;
  lvmd::LogicalVolumeList lvs;
  if (!lvmd_proxy_->ListLogicalVolumes(vg, &lvs, &err)) {
    LOG(ERROR) << "Failed to list logical volumes, " << ErrorPtrToStr(err);
    return EX_SOFTWARE;
  }

  return PrintDict(ToDict(lvs));
}

int LvmdClient::GetLogicalVolume(const std::string& vg_name,
                                 const std::string& lv_name) {
  if (vg_name.empty()) {
    LOG(ERROR) << "`--vg_name` must be provided.";
    return EX_USAGE;
  }

  if (lv_name.empty()) {
    LOG(ERROR) << "`--lv_name` must be provided.";
    return EX_USAGE;
  }

  lvmd::VolumeGroup vg;
  vg.set_name(vg_name);

  brillo::ErrorPtr err;
  lvmd::LogicalVolume lv;
  if (!lvmd_proxy_->GetLogicalVolume(vg, lv_name, &lv, &err)) {
    LOG(ERROR) << "Failed to get logical volume, " << ErrorPtrToStr(err);
    return EX_SOFTWARE;
  }

  return PrintDict(ToDict(lv));
}

int LvmdClient::CreateLogicalVolume(const std::string& vg_name,
                                    const std::string& thinpool_name,
                                    const std::string& lv_name,
                                    int64_t size) {
  if (vg_name.empty()) {
    LOG(ERROR) << "`--vg_name` must be provided.";
    return EX_USAGE;
  }

  if (thinpool_name.empty()) {
    LOG(ERROR) << "`--thinpool_name` must be provided.";
    return EX_USAGE;
  }

  if (lv_name.empty()) {
    LOG(ERROR) << "`--lv_name` must be provided.";
    return EX_USAGE;
  }

  if (size < 0) {
    LOG(ERROR) << "`--size` must be positive.";
    return EX_USAGE;
  }

  lvmd::VolumeGroup vg;
  vg.set_name(vg_name);

  lvmd::Thinpool thinpool;
  *thinpool.mutable_volume_group() = vg;
  thinpool.set_name(thinpool_name);

  lvmd::LogicalVolumeConfiguration lv_config;
  lv_config.set_name(lv_name);
  lv_config.set_size(size);

  brillo::ErrorPtr err;
  lvmd::LogicalVolume lv;
  if (!lvmd_proxy_->CreateLogicalVolume(thinpool, lv_config, &lv, &err)) {
    LOG(ERROR) << "Failed to create logical volume, " << ErrorPtrToStr(err);
    return EX_SOFTWARE;
  }

  return PrintDict(ToDict(lv));
}

int LvmdClient::RemoveLogicalVolume(const std::string& vg_name,
                                    const std::string& lv_name) {
  if (vg_name.empty()) {
    LOG(ERROR) << "`--vg_name` must be provided.";
    return EX_USAGE;
  }

  if (lv_name.empty()) {
    LOG(ERROR) << "`--lv_name` must be provided.";
    return EX_USAGE;
  }

  lvmd::VolumeGroup vg;
  vg.set_name(vg_name);

  lvmd::LogicalVolume lv;
  *lv.mutable_volume_group() = vg;
  lv.set_name(lv_name);

  brillo::ErrorPtr err;
  if (!lvmd_proxy_->RemoveLogicalVolume(lv, &err)) {
    LOG(ERROR) << "Failed to remove logical volume, " << ErrorPtrToStr(err);
    return EX_SOFTWARE;
  }

  return EX_OK;
}

int LvmdClient::ToggleLogicalVolumeActivation(const std::string& vg_name,
                                              const std::string& lv_name,
                                              bool activate) {
  if (vg_name.empty()) {
    LOG(ERROR) << "`--vg_name` must be provided.";
    return EX_USAGE;
  }

  if (lv_name.empty()) {
    LOG(ERROR) << "`--lv_name` must be provided.";
    return EX_USAGE;
  }

  lvmd::VolumeGroup vg;
  vg.set_name(vg_name);

  lvmd::LogicalVolume lv;
  *lv.mutable_volume_group() = vg;
  lv.set_name(lv_name);

  brillo::ErrorPtr err;
  if (!lvmd_proxy_->ToggleLogicalVolumeActivation(lv, activate, &err)) {
    LOG(ERROR) << "Failed to toggle activation for logical volume, "
               << ErrorPtrToStr(err);
    return EX_SOFTWARE;
  }

  return EX_OK;
}

int LvmdClient::OnEventLoopStarted() {
  Quit();

  for (auto fnc : {&LvmdClient::Init, &LvmdClient::ProcessFlags}) {
    if (int ret = (this->*fnc)(); ret != EX_OK) {
      return ret;
    }
  }

  return EX_OK;
}

}  // namespace

int main(int argc, const char** argv) {
  switch (getuid()) {
    case 0:
      break;
    default:
      LOG(ERROR) << "lvmd_client can only be run as root.";
      return EX_USAGE;
  }

  return LvmdClient(argc, argv).Run();
}
