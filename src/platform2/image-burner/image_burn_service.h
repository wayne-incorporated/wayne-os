// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IMAGE_BURNER_IMAGE_BURN_SERVICE_H_
#define IMAGE_BURNER_IMAGE_BURN_SERVICE_H_

#include <stdint.h>

#include <string>

#include <brillo/dbus/dbus_object.h>
#include <chromeos/dbus/service_constants.h>

#include "image-burner/dbus_adaptors/org.chromium.ImageBurnerInterface.h"
#include "image-burner/image_burner_impl.h"
#include "image-burner/image_burner_utils_interfaces.h"

namespace imageburn {

// Provides a wrapper for exporting ImageBurnerInterface to
// D-Bus.
class ImageBurnService : public org::chromium::ImageBurnerInterfaceInterface,
                         public org::chromium::ImageBurnerInterfaceAdaptor,
                         public SignalSender {
 public:
  ImageBurnService(scoped_refptr<dbus::Bus> bus, BurnerImpl* burner_impl);
  virtual ~ImageBurnService();

  void RegisterAsync(
      brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb);

  // org::chromium::ImageBurnerInterfaceInterface overrides.
  bool BurnImage(brillo::ErrorPtr* error,
                 const std::string& from_path,
                 const std::string& to_path) override;

  void SendFinishedSignal(const char* target_path,
                          bool success,
                          const char* error_message) override;
  void SendProgressSignal(int64_t amount_burnt,
                          int64_t total_size,
                          const char* target_path) override;

 private:
  void BurnImageInternal(const std::string& from_path,
                         const std::string& to_path);

  brillo::dbus_utils::DBusObject dbus_object_;

  int64_t amount_burnt_for_next_signal_;
  bool burning_;
  BurnerImpl* burner_impl_;
};

}  // namespace imageburn

#endif  // IMAGE_BURNER_IMAGE_BURN_SERVICE_H_
