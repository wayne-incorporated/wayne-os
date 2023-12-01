// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_UDEV_UDEV_DEVICE_H_
#define LIBBRILLO_BRILLO_UDEV_UDEV_DEVICE_H_

#include <stdint.h>
#include <sys/types.h>

#include <memory>

#include <brillo/brillo_export.h>
#include <brillo/udev/udev_list_entry.h>

struct udev_device;

namespace brillo {

// A udev device, which wraps a udev_device C struct from libudev and related
// library functions into a C++ object.
class BRILLO_EXPORT UdevDevice {
 public:
  virtual ~UdevDevice() = default;

  // Wraps udev_device_get_parent().
  virtual std::unique_ptr<UdevDevice> GetParent() const = 0;

  // Wraps udev_device_get_parent_with_subsystem_devtype().
  virtual std::unique_ptr<UdevDevice> GetParentWithSubsystemDeviceType(
      const char* subsystem, const char* device_type) const = 0;

  // Wraps udev_device_get_is_initialized().
  virtual bool IsInitialized() const = 0;

  // Wraps udev_device_get_usec_since_initialized().
  virtual uint64_t GetMicrosecondsSinceInitialized() const = 0;

  // Wraps udev_device_get_seqnum().
  virtual uint64_t GetSequenceNumber() const = 0;

  // Wraps udev_device_get_devpath().
  virtual const char* GetDevicePath() const = 0;

  // Wraps udev_device_get_devnode().
  virtual const char* GetDeviceNode() const = 0;

  // Wraps udev_device_get_devnum().
  virtual dev_t GetDeviceNumber() const = 0;

  // Wraps udev_device_get_devtype().
  virtual const char* GetDeviceType() const = 0;

  // Wraps udev_device_get_driver().
  virtual const char* GetDriver() const = 0;

  // Wraps udev_device_get_subsystem().
  virtual const char* GetSubsystem() const = 0;

  // Wraps udev_device_get_syspath().
  virtual const char* GetSysPath() const = 0;

  // Wraps udev_device_get_sysname().
  virtual const char* GetSysName() const = 0;

  // Wraps udev_device_get_sysnum().
  virtual const char* GetSysNumber() const = 0;

  // Wraps udev_device_get_action().
  virtual const char* GetAction() const = 0;

  // Wraps udev_device_get_devlinks_list_entry().
  virtual std::unique_ptr<UdevListEntry> GetDeviceLinksListEntry() const = 0;

  // Wraps udev_device_get_properties_list_entry().
  virtual std::unique_ptr<UdevListEntry> GetPropertiesListEntry() const = 0;

  // Wraps udev_device_get_property_value().
  virtual const char* GetPropertyValue(const char* key) const = 0;

  // Wraps udev_device_get_tags_list_entry().
  virtual std::unique_ptr<UdevListEntry> GetTagsListEntry() const = 0;

  // Wraps udev_device_get_sysattr_list_entry().
  virtual std::unique_ptr<UdevListEntry> GetSysAttributeListEntry() const = 0;

  // Wraps udev_device_get_sysattr_value().
  virtual const char* GetSysAttributeValue(const char* attribute) const = 0;

  virtual std::unique_ptr<UdevDevice> Clone() = 0;
};

class BRILLO_EXPORT UdevDeviceImpl : public UdevDevice {
 public:
  // Constructs a UdevDevice object by taking a raw pointer to a udev_device
  // struct as |device|. The ownership of |device| is not transferred, but its
  // reference count is increased by one during the lifetime of this object.
  explicit UdevDeviceImpl(udev_device* device);

  // Use Clone() if you want to copy this UdevDeviceImpl.
  UdevDeviceImpl(const UdevDeviceImpl&) = delete;
  UdevDeviceImpl& operator=(const UdevDeviceImpl&) = delete;

  // Destructs this UdevDevice object and decreases the libudev reference count
  // of the underlying udev_device struct by 1.
  ~UdevDeviceImpl() override;

  // UdevDevice overrides.
  std::unique_ptr<UdevDevice> GetParent() const override;
  std::unique_ptr<UdevDevice> GetParentWithSubsystemDeviceType(
      const char* subsystem, const char* device_type) const override;
  bool IsInitialized() const override;
  uint64_t GetMicrosecondsSinceInitialized() const override;
  uint64_t GetSequenceNumber() const override;
  const char* GetDevicePath() const override;
  const char* GetDeviceNode() const override;
  dev_t GetDeviceNumber() const override;
  const char* GetDeviceType() const override;
  const char* GetDriver() const override;
  const char* GetSubsystem() const override;
  const char* GetSysPath() const override;
  const char* GetSysName() const override;
  const char* GetSysNumber() const override;
  const char* GetAction() const override;
  std::unique_ptr<UdevListEntry> GetDeviceLinksListEntry() const override;
  std::unique_ptr<UdevListEntry> GetPropertiesListEntry() const override;
  const char* GetPropertyValue(const char* key) const override;
  std::unique_ptr<UdevListEntry> GetTagsListEntry() const override;
  std::unique_ptr<UdevListEntry> GetSysAttributeListEntry() const override;
  const char* GetSysAttributeValue(const char* attribute) const override;

  // Creates a copy of this UdevDevice pointing to the same underlying
  // struct udev_device* (increasing its libudev reference count by 1).
  std::unique_ptr<UdevDevice> Clone() override;

 private:
  udev_device* device_;
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_UDEV_UDEV_DEVICE_H_
