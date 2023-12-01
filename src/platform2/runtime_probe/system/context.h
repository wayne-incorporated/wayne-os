// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_SYSTEM_CONTEXT_H_
#define RUNTIME_PROBE_SYSTEM_CONTEXT_H_

#include <memory>

#include <base/files/file_path.h>

#include "runtime_probe/system/helper_invoker.h"
#include "runtime_probe/system/syscaller.h"

namespace brillo {
class CrosConfigInterface;
}

namespace crossystem {
class Crossystem;
}

namespace org {
namespace chromium {
class debugdProxyInterface;
}  // namespace chromium
}  // namespace org

namespace org::chromium::flimflam {
class ManagerProxyInterface;
class DeviceProxyInterface;
}  // namespace org::chromium::flimflam

namespace dbus {
class ObjectPath;
}  // namespace dbus

namespace runtime_probe {

// A context class for holding the helper objects used in runtime probe, which
// simplifies the passing of the helper objects to other objects. For instance,
// instead of passing various helper objects to an object via its constructor,
// the context object is passed.
class Context {
 public:
  Context(const Context&) = delete;
  Context& operator=(const Context&) = delete;

  // Returns the current global context instance. The global instance will be
  // overridden by derived classes. Only one global instance is allowed at a
  // time.
  static Context* Get();

  // The object to access the ChromeOS model configuration.
  virtual brillo::CrosConfigInterface* cros_config() = 0;

  // The object to access crossystem system properties.
  virtual crossystem::Crossystem* crossystem() = 0;

  // Use the object returned by syscaller() to make syscalls.
  virtual Syscaller* syscaller() = 0;

  // Use the object returned by debugd_proxy() to make calls to debugd.
  virtual org::chromium::debugdProxyInterface* debugd_proxy() = 0;

  // Use the object returned by shill_manager_proxy() to make calls to shill
  // manager.
  virtual org::chromium::flimflam::ManagerProxyInterface*
  shill_manager_proxy() = 0;

  // Use the object returned by CreateShillDeviceProxy() to make calls to shill
  // device.
  virtual std::unique_ptr<org::chromium::flimflam::DeviceProxyInterface>
  CreateShillDeviceProxy(const dbus::ObjectPath& path) = 0;

  // The object to invoke the runtime_probe helper.
  virtual HelperInvoker* helper_invoker() = 0;

  // Returns the root directory. This can be overridden during test.
  virtual const base::FilePath& root_dir();

 protected:
  Context();
  virtual ~Context();
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_SYSTEM_CONTEXT_H_
