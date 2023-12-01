// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MIDIS_DEVICE_TRACKER_H_
#define MIDIS_DEVICE_TRACKER_H_

#include <alsa/asoundlib.h>

#include <map>
#include <memory>
#include <vector>

#include <base/files/scoped_file.h>
#include <base/observer_list.h>
#include <base/observer_list_types.h>
#include <gtest/gtest_prod.h>

#include "midis/device.h"
#include "midis/seq_handler.h"
#include "mojo/midis.mojom.h"

namespace midis {

class SeqHandler;

class DeviceTracker {
 public:
  DeviceTracker();
  DeviceTracker(const DeviceTracker&) = delete;
  DeviceTracker& operator=(const DeviceTracker&) = delete;

  void AddDevice(std::unique_ptr<Device> dev);
  void RemoveDevice(uint32_t sys_num, uint32_t dev_num);
  bool InitDeviceTracker();
  void ListDevices(std::vector<arc::mojom::MidisDeviceInfoPtr>* list);

  class Observer : public base::CheckedObserver {
   public:
    virtual ~Observer() {}
    // Function which is executed when a MIDI device is added or removed
    // from the h/w. The client registered as an observer can expect
    // that struct MidisDeviceInfo pointer is allocated and its fields have
    // been filled out correctly.
    //
    // The 'added' argument is set to true if the device was added, and false
    // otherwise.
    virtual void OnDeviceAddedOrRemoved(const Device& dev, bool added) = 0;
  };

  void AddDeviceObserver(Observer* obs);

  void RemoveDeviceObserver(Observer* obs);

  base::ScopedFD AddClientToReadSubdevice(uint32_t sys_num,
                                          uint32_t device_num,
                                          uint32_t subdevice_num,
                                          uint32_t client_id);

  // Remove the client from all watchers for the element of |device_| which
  // matches is identified by |sys_num| and |device_num|. This is useful when a
  // client wants to close requested ports for a device, but may choose to
  // re-request them later on.
  void RemoveClientFromDevice(uint32_t client_id,
                              uint32_t sys_num,
                              uint32_t device_num);

  // Remove the client from all devices in |devices_|. This function is intended
  // to be used when we detect the removal of an entire client either through
  // orderly or disorderly shutdown.
  void RemoveClientFromDevices(uint32_t client_id);

  static uint32_t GenerateDeviceId(uint32_t sys_num, uint32_t device_num) {
    return (sys_num << 8) | device_num;
  }

 private:
  void HandleReceiveData(uint32_t card_id,
                         uint32_t device_id,
                         uint32_t port_id,
                         const char* buffer,
                         size_t buf_len);

  // Utility function to ascertain whether a device is already registered.
  bool IsDevicePresent(uint32_t card_id, uint32_t device_id);

  // Utility function to ascertain whether a port is already registered.
  bool IsPortPresent(uint32_t card_id, uint32_t device_id, uint32_t port_id);

  // Private helper to retrieve a Device pointer if it exists.
  Device* FindDevice(uint32_t card_id, uint32_t device_id) const;

  friend class DeviceTrackerTest;
  FRIEND_TEST(DeviceTrackerTest, Add2DevicesPositive);
  FRIEND_TEST(DeviceTrackerTest, AddRemoveDevicePositive);
  FRIEND_TEST(DeviceTrackerTest, AddDeviceRemoveNegative);
  void NotifyObserversDeviceAddedOrRemoved(const Device& dev, bool added);

  std::map<uint32_t, std::unique_ptr<Device>> devices_;
  std::unique_ptr<SeqHandler> seq_handler_;

  base::ObserverList<Observer> observer_list_;
};

}  // namespace midis

#endif  // MIDIS_DEVICE_TRACKER_H_
