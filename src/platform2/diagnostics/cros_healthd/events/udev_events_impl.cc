// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/events/udev_events_impl.h"

#include <libusb.h>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_enumerator.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <brillo/udev/udev_device.h>

#include "diagnostics/base/file_utils.h"
#include "diagnostics/cros_healthd/utils/usb_utils.h"
#include "diagnostics/cros_healthd/utils/usb_utils_constants.h"
#include "diagnostics/mojom/public/cros_healthd_events.mojom.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

std::string GetString(const char* str) {
  if (str) {
    return std::string(str);
  }

  return "";
}

void FillUsbCategory(const std::unique_ptr<brillo::UdevDevice>& device,
                     mojom::UsbEventInfo* info) {
  auto sys_path = GetString(device->GetSysPath());
  uint32_t class_code = 0;
  std::set<std::string> categories;

  ReadInteger(base::FilePath(sys_path), kFileUsbDevClass,
              &base::HexStringToUInt, &class_code);
  if (class_code != libusb_class_code::LIBUSB_CLASS_PER_INTERFACE) {
    categories.insert(LookUpUsbDeviceClass(class_code));
  } else {  // The category is determined by interfaces.
    base::FileEnumerator file_enum(base::FilePath(sys_path), false,
                                   base::FileEnumerator::FileType::DIRECTORIES);
    for (auto path = file_enum.Next(); !path.empty(); path = file_enum.Next()) {
      std::string content;
      ReadAndTrimString(path.Append(kFileUsbIFClass), &content);
      if (!base::HexStringToUInt(content, &class_code))
        continue;
      categories.insert(LookUpUsbDeviceClass(class_code));
    }
  }

  categories.erase("Unknown");
  for (const auto& category : categories) {
    info->categories.push_back(category);
  }
}

void FillUsbEventInfo(const std::unique_ptr<brillo::UdevDevice>& device,
                      mojom::UsbEventInfo* info) {
  info->vendor = GetUsbVendorName(device);
  info->name = GetUsbProductName(device);
  std::tie(info->vid, info->pid) = GetUsbVidPid(device);
  FillUsbCategory(device, info);
}

}  // namespace

UdevEventsImpl::UdevEventsImpl(Context* context) : context_(context) {
  DCHECK(context_);
}

bool UdevEventsImpl::Initialize() {
  if (!context_->udev_monitor()->EnableReceiving()) {
    LOG(ERROR) << "Failed to enable receiving for udev monitor.";
    return false;
  }

  int fd = context_->udev_monitor()->GetFileDescriptor();
  if (fd == brillo::UdevMonitor::kInvalidFileDescriptor) {
    LOG(ERROR) << "Failed to get udev monitor fd.";
    return false;
  }

  udev_monitor_watcher_ = base::FileDescriptorWatcher::WatchReadable(
      fd, base::BindRepeating(&UdevEventsImpl::OnUdevEvent,
                              base::Unretained(this)));

  if (!udev_monitor_watcher_) {
    LOG(ERROR) << "Failed to start watcher for udev monitor fd.";
    return false;
  }

  context_->executor()->GetConnectedHdmiConnectors(
      base::BindOnce(&UdevEventsImpl::HandleGetConnectedHdmiConnectors,
                     weak_factory_.GetWeakPtr())
          .Then(
              base::BindOnce(&UdevEventsImpl::InitializeConnectedHdmiConnectors,
                             weak_factory_.GetWeakPtr())));

  return true;
}

void UdevEventsImpl::InitializeConnectedHdmiConnectors() {
  last_known_hdmi_connectors_ = std::move(current_hdmi_connectors_);
  current_hdmi_connectors_ = {};
}

void UdevEventsImpl::HandleGetConnectedHdmiConnectors(
    base::flat_map<uint32_t, mojom::ExternalDisplayInfoPtr> connected_displays,
    const std::optional<std::string>& error) {
  if (error.has_value()) {
    LOG(ERROR) << "Error from executor call: " << error.value();
    return;
  }
  current_hdmi_connectors_ = {};
  for (auto& [connector_id, display_info] : connected_displays) {
    current_hdmi_connectors_.insert(connector_id);
    if (connector_id_to_display_info_.count(connector_id) == 0) {
      connector_id_to_display_info_[connector_id] = std::move(display_info);
    }
  }
}

void UdevEventsImpl::OnUdevEvent() {
  auto device = context_->udev_monitor()->ReceiveDevice();
  if (!device) {
    LOG(ERROR) << "Udev receive device failed.";
    return;
  }

  auto action = GetString(device->GetAction());
  auto subsystem = GetString(device->GetSubsystem());
  auto device_type = GetString(device->GetDeviceType());

  // Distinguished events by subsystem and action here.
  if (subsystem == "thunderbolt") {
    if (action == "add") {
      OnThunderboltAddEvent();
    } else if (action == "remove") {
      OnThunderboltRemoveEvent();
    } else if (action == "change") {
      auto path = base::FilePath(device->GetSysPath());
      std::string authorized;
      if (ReadAndTrimString(path.Append("authorized"), &authorized)) {
        unsigned auth;
        base::StringToUint(authorized, &auth);
        auth ? OnThunderboltAuthorizedEvent()
             : OnThunderboltUnAuthorizedEvent();
      }
    }
  } else if (subsystem == "usb" && device_type == "usb_device") {
    if (action == "add") {
      OnUsbAdd(device);
    } else if (action == "remove") {
      OnUsbRemove(device);
    }
  } else if (subsystem == "mmc") {
    if (action == "add") {
      OnSdCardAdd();
    } else if (action == "remove") {
      OnSdCardRemove();
    }
  } else if (subsystem == "drm" && device_type == "drm_minor") {
    if (action == "change") {
      OnHdmiChange();
    }
  }
}

void UdevEventsImpl::AddThunderboltObserver(
    mojo::PendingRemote<mojom::EventObserver> observer) {
  thunderbolt_observers_.Add(std::move(observer));
}

void UdevEventsImpl::AddThunderboltObserver(
    mojo::PendingRemote<mojom::CrosHealthdThunderboltObserver> observer) {
  deprecated_thunderbolt_observers_.Add(std::move(observer));
}

void UdevEventsImpl::OnThunderboltAddEvent() {
  mojom::ThunderboltEventInfo info;
  info.state = mojom::ThunderboltEventInfo::State::kAdd;
  for (auto& observer : thunderbolt_observers_)
    observer->OnEvent(mojom::EventInfo::NewThunderboltEventInfo(info.Clone()));
  for (auto& observer : deprecated_thunderbolt_observers_)
    observer->OnAdd();
}

void UdevEventsImpl::OnThunderboltRemoveEvent() {
  mojom::ThunderboltEventInfo info;
  info.state = mojom::ThunderboltEventInfo::State::kRemove;
  for (auto& observer : thunderbolt_observers_)
    observer->OnEvent(mojom::EventInfo::NewThunderboltEventInfo(info.Clone()));
  for (auto& observer : deprecated_thunderbolt_observers_)
    observer->OnRemove();
}

void UdevEventsImpl::OnThunderboltAuthorizedEvent() {
  mojom::ThunderboltEventInfo info;
  info.state = mojom::ThunderboltEventInfo::State::kAuthorized;
  for (auto& observer : thunderbolt_observers_)
    observer->OnEvent(mojom::EventInfo::NewThunderboltEventInfo(info.Clone()));
  for (auto& observer : deprecated_thunderbolt_observers_)
    observer->OnAuthorized();
}

void UdevEventsImpl::OnThunderboltUnAuthorizedEvent() {
  mojom::ThunderboltEventInfo info;
  info.state = mojom::ThunderboltEventInfo::State::kUnAuthorized;
  for (auto& observer : thunderbolt_observers_)
    observer->OnEvent(mojom::EventInfo::NewThunderboltEventInfo(info.Clone()));
  for (auto& observer : deprecated_thunderbolt_observers_)
    observer->OnUnAuthorized();
}

void UdevEventsImpl::AddUsbObserver(
    mojo::PendingRemote<mojom::CrosHealthdUsbObserver> observer) {
  deprecated_usb_observers_.Add(std::move(observer));
}

void UdevEventsImpl::AddUsbObserver(
    mojo::PendingRemote<mojom::EventObserver> observer) {
  usb_observers_.Add(std::move(observer));
}

void UdevEventsImpl::OnUsbAdd(
    const std::unique_ptr<brillo::UdevDevice>& device) {
  mojom::UsbEventInfo info;
  FillUsbEventInfo(device, &info);
  info.state = mojom::UsbEventInfo::State::kAdd;

  for (auto& observer : usb_observers_)
    observer->OnEvent(mojom::EventInfo::NewUsbEventInfo(info.Clone()));
  for (auto& observer : deprecated_usb_observers_)
    observer->OnAdd(info.Clone());
}

void UdevEventsImpl::OnUsbRemove(
    const std::unique_ptr<brillo::UdevDevice>& device) {
  mojom::UsbEventInfo info;
  FillUsbEventInfo(device, &info);
  info.state = mojom::UsbEventInfo::State::kRemove;

  for (auto& observer : usb_observers_)
    observer->OnEvent(mojom::EventInfo::NewUsbEventInfo(info.Clone()));
  for (auto& observer : deprecated_usb_observers_)
    observer->OnRemove(info.Clone());
}

void UdevEventsImpl::AddSdCardObserver(
    mojo::PendingRemote<mojom::EventObserver> observer) {
  sd_card_observers_.Add(std::move(observer));
}

void UdevEventsImpl::OnSdCardAdd() {
  mojom::SdCardEventInfo info;
  info.state = mojom::SdCardEventInfo::State::kAdd;
  for (auto& observer : sd_card_observers_) {
    observer->OnEvent(mojom::EventInfo::NewSdCardEventInfo(info.Clone()));
  }
}

void UdevEventsImpl::OnSdCardRemove() {
  mojom::SdCardEventInfo info;
  info.state = mojom::SdCardEventInfo::State::kRemove;
  for (auto& observer : sd_card_observers_)
    observer->OnEvent(mojom::EventInfo::NewSdCardEventInfo(info.Clone()));
}

void UdevEventsImpl::AddHdmiObserver(
    mojo::PendingRemote<mojom::EventObserver> observer) {
  hdmi_observers_.Add(std::move(observer));
}

void UdevEventsImpl::OnHdmiChange() {
  context_->executor()->GetConnectedHdmiConnectors(
      base::BindOnce(&UdevEventsImpl::HandleGetConnectedHdmiConnectors,
                     weak_factory_.GetWeakPtr())
          .Then(base::BindOnce(&UdevEventsImpl::UpdateHdmiObservers,
                               weak_factory_.GetWeakPtr())));
}

void UdevEventsImpl::UpdateHdmiObservers() {
  std::set<uint32_t> added_connectors;
  std::set<uint32_t> removed_connectors;

  std::set_difference(
      current_hdmi_connectors_.begin(), current_hdmi_connectors_.end(),
      last_known_hdmi_connectors_.begin(), last_known_hdmi_connectors_.end(),
      std::inserter(added_connectors, added_connectors.end()));

  std::set_difference(
      last_known_hdmi_connectors_.begin(), last_known_hdmi_connectors_.end(),
      current_hdmi_connectors_.begin(), current_hdmi_connectors_.end(),
      std::inserter(removed_connectors, removed_connectors.end()));

  last_known_hdmi_connectors_ = std::move(current_hdmi_connectors_);
  current_hdmi_connectors_ = {};

  for (auto connector_id : added_connectors) {
    auto info = mojom::HdmiEventInfo::New();
    info->state = mojom::HdmiEventInfo::State::kAdd;
    if (connector_id_to_display_info_.count(connector_id) == 0) {
      LOG(ERROR) << "Cannot find display info for connector id: "
                 << connector_id;
      continue;
    }
    info->display_info = connector_id_to_display_info_[connector_id].Clone();
    for (auto& observer : hdmi_observers_) {
      observer->OnEvent(mojom::EventInfo::NewHdmiEventInfo(std::move(info)));
    }
  }
  for (auto connector_id : removed_connectors) {
    auto info = mojom::HdmiEventInfo::New();
    info->state = mojom::HdmiEventInfo::State::kRemove;
    if (connector_id_to_display_info_.count(connector_id) == 0) {
      LOG(ERROR) << "Cannot find display info for connector id: "
                 << connector_id;
      continue;
    }
    info->display_info = connector_id_to_display_info_[connector_id].Clone();
    for (auto& observer : hdmi_observers_) {
      observer->OnEvent(mojom::EventInfo::NewHdmiEventInfo(std::move(info)));
    }
    // Remove the connector from the map in case a new connector with the same
    // ID is received.
    connector_id_to_display_info_.erase(connector_id);
  }
}

}  // namespace diagnostics
