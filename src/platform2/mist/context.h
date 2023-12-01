// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MIST_CONTEXT_H_
#define MIST_CONTEXT_H_

#include <memory>

namespace brillo {

class Udev;
class UsbDeviceEventNotifier;
class UsbManager;

}  // namespace brillo

namespace mist {

class ConfigLoader;
class EventDispatcher;
class Metrics;

// A context class for holding the key helper objects used in mist, which
// simplifies the passing of the helper objects to other objects. For instance,
// instead of passing various helper objects to an object via its constructor,
// the context object is passed.
class Context {
 public:
  Context();
  Context(const Context&) = delete;
  Context& operator=(const Context&) = delete;

  virtual ~Context();

  // Initializes all helper objects in the context. Returns true on success.
  virtual bool Initialize();

  Metrics* metrics() const { return metrics_.get(); }
  ConfigLoader* config_loader() const { return config_loader_.get(); }
  EventDispatcher* event_dispatcher() const { return event_dispatcher_.get(); }
  brillo::Udev* udev() const { return udev_.get(); }
  brillo::UsbDeviceEventNotifier* usb_device_event_notifier() const {
    return usb_device_event_notifier_.get();
  }
  brillo::UsbManager* usb_manager() const { return usb_manager_.get(); }

 private:
  friend class MockContext;

  std::unique_ptr<Metrics> metrics_;
  std::unique_ptr<ConfigLoader> config_loader_;
  std::unique_ptr<EventDispatcher> event_dispatcher_;
  std::unique_ptr<brillo::Udev> udev_;
  std::unique_ptr<brillo::UsbDeviceEventNotifier> usb_device_event_notifier_;
  std::unique_ptr<brillo::UsbManager> usb_manager_;
};

}  // namespace mist

#endif  // MIST_CONTEXT_H_
