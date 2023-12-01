// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_UDEV_UDEV_ENUMERATE_H_
#define LIBBRILLO_BRILLO_UDEV_UDEV_ENUMERATE_H_

#include <memory>

#include <brillo/brillo_export.h>
#include <brillo/udev/udev_list_entry.h>

struct udev_enumerate;

namespace brillo {

// A udev enumerate class, which wraps a udev_enumerate C struct from libudev
// and related library functions into a C++ object.
class BRILLO_EXPORT UdevEnumerate {
 public:
  // Constructs a UdevEnumerate object by taking a raw pointer to a
  // udev_enumerate struct as |enumerate|. The ownership of |enumerate| is not
  // transferred, but its reference count is increased by one during the
  // lifetime of this object.
  explicit UdevEnumerate(udev_enumerate* enumerate);

  // Destructs this UdevEnumerate object and decreases the reference count of
  // the underlying udev_enumerate struct by one.
  virtual ~UdevEnumerate();

  // Wraps udev_enumerate_add_match_subsystem(). Returns true on success.
  virtual bool AddMatchSubsystem(const char* subsystem);

  // Wraps udev_enumerate_add_nomatch_subsystem(). Returns true on success.
  virtual bool AddNoMatchSubsystem(const char* subsystem);

  // Wraps udev_enumerate_add_match_sysattr(). Returns true on success.
  virtual bool AddMatchSysAttribute(const char* attribute, const char* value);

  // Wraps udev_enumerate_add_nomatch_sysattr(). Returns true on success.
  virtual bool AddNoMatchSysAttribute(const char* attribute, const char* value);

  // Wraps udev_enumerate_add_match_property(). Returns true on success.
  virtual bool AddMatchProperty(const char* property, const char* value);

  // Wraps udev_enumerate_add_match_sysname(). Returns true on success.
  virtual bool AddMatchSysName(const char* sys_name);

  // Wraps udev_enumerate_add_match_tag(). Returns true on success.
  virtual bool AddMatchTag(const char* tag);

  // Wraps udev_enumerate_add_match_is_initialized(). Returns true on success.
  virtual bool AddMatchIsInitialized();

  // Wraps udev_enumerate_add_syspath(). Returns true on success.
  virtual bool AddSysPath(const char* sys_path);

  // Wraps udev_enumerate_scan_devices(). Returns true on success.
  virtual bool ScanDevices();

  // Wraps udev_enumerate_scan_subsystems(). Returns true on success.
  virtual bool ScanSubsystems();

  // Wraps udev_enumerate_get_list_entry().
  virtual std::unique_ptr<UdevListEntry> GetListEntry() const;

 private:
  // Allows MockUdevEnumerate to invoke the private default constructor below.
  friend class MockUdevEnumerate;

  // Constructs a UdevEnumerate object without referencing a udev_enumerate
  // struct, which is only allowed to be called by MockUdevEnumerate.
  UdevEnumerate();
  UdevEnumerate(const UdevEnumerate&) = delete;
  UdevEnumerate& operator=(const UdevEnumerate&) = delete;

  udev_enumerate* enumerate_;
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_UDEV_UDEV_ENUMERATE_H_
