/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef HARDWARE_VERIFIER_DBUS_ADAPTOR_H_
#define HARDWARE_VERIFIER_DBUS_ADAPTOR_H_

#include <memory>
#include <utility>

#include <brillo/dbus/async_event_sequencer.h>
#include <brillo/dbus/dbus_method_response.h>
#include <brillo/dbus/dbus_object.h>
#include <dbus/hardware_verifier/dbus-constants.h>

// Include the protobuf before generated D-Bus adaptors to ensure the protobuf
// messages are defined before adaptors.
// TODO(crbug.com/1255584): Includes headers in alphabetical order.
#include "hardware_verifier/hardware_verifier.pb.h"
#include "hardware_verifier/dbus_adaptors/org.chromium.HardwareVerifier.h"  // NOLINT(build/include_alpha)
#include "hardware_verifier/hw_verification_report_getter_impl.h"

namespace hardware_verifier {

// Implementation of the hardware_verifier D-Bus methods.
class DBusAdaptor : public org::chromium::HardwareVerifierInterface,
                    public org::chromium::HardwareVerifierAdaptor {
 public:
  using VerifyComponentsResponseCallback = std::unique_ptr<
      brillo::dbus_utils::DBusMethodResponse<VerifyComponentsReply>>;

  explicit DBusAdaptor(scoped_refptr<dbus::Bus> bus,
                       brillo::dbus_utils::DBusObject* dbus_object)
      : org::chromium::HardwareVerifierAdaptor(this),
        dbus_object_(dbus_object),
        vr_getter_(new HwVerificationReportGetterImpl()) {}
  DBusAdaptor(const DBusAdaptor&) = delete;
  DBusAdaptor& operator=(const DBusAdaptor&) = delete;

  void RegisterAsync(
      brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb) {
    DCHECK(dbus_object_);
    RegisterWithDBusObject(dbus_object_);
    dbus_object_->RegisterAsync(std::move(cb));
  }

  void VerifyComponents(VerifyComponentsResponseCallback callback) override;

 protected:
  // This constructor is reserved only for testing.
  explicit DBusAdaptor(std::unique_ptr<HwVerificationReportGetter> vr_getter)
      : org::chromium::HardwareVerifierAdaptor(this),
        dbus_object_(nullptr),
        vr_getter_(std::move(vr_getter)) {}

 private:
  brillo::dbus_utils::DBusObject* dbus_object_;

  // Dependent classes.
  std::unique_ptr<HwVerificationReportGetter> vr_getter_;
};

}  // namespace hardware_verifier

#endif  // HARDWARE_VERIFIER_DBUS_ADAPTOR_H_
