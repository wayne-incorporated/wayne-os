// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_CONTAINER_OBB_MOUNTER_SERVICE_H_
#define ARC_CONTAINER_OBB_MOUNTER_SERVICE_H_

#include <base/memory/weak_ptr.h>
#include <dbus/exported_object.h>

namespace dbus {
class Bus;
class MethodCall;
}  // namespace dbus

namespace arc {
namespace obb_mounter {

// This class handles incoming D-Bus method calls.
class Service {
 public:
  Service();
  Service(const Service&) = delete;
  Service& operator=(const Service&) = delete;

  ~Service();

  // Exports D-Bus methods via the given bus and requests the ownership of the
  // service name.
  bool Initialize(scoped_refptr<dbus::Bus> bus);

 private:
  // D-Bus method call handlers:
  void MountObb(dbus::MethodCall* method_call,
                dbus::ExportedObject::ResponseSender response_sender);
  void UnmountObb(dbus::MethodCall* method_call,
                  dbus::ExportedObject::ResponseSender response_sender);

  scoped_refptr<dbus::Bus> bus_;
  dbus::ExportedObject* exported_object_ = nullptr;

  base::WeakPtrFactory<Service> weak_ptr_factory_;
};

}  // namespace obb_mounter
}  // namespace arc

#endif  // ARC_CONTAINER_OBB_MOUNTER_SERVICE_H_
