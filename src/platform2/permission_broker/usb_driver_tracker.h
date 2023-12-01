// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PERMISSION_BROKER_USB_DRIVER_TRACKER_H_
#define PERMISSION_BROKER_USB_DRIVER_TRACKER_H_

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/memory/weak_ptr.h>

namespace permission_broker {

constexpr const int kInvalidLifelineFD = -1;

class UsbDriverTracker {
 public:
  UsbDriverTracker();
  UsbDriverTracker(const UsbDriverTracker&) = delete;
  UsbDriverTracker& operator=(const UsbDriverTracker&) = delete;

  virtual ~UsbDriverTracker();

  // Detach all the interfaces of the USB device at |path| which is associated
  // with the |client_id|. In case |client_id| is null, |fd| is used (i.e.
  // Permission Broker's OpenPath method).
  bool DetachPathFromKernel(int fd,
                            const std::string* client_id,
                            const base::FilePath& path);

  // Register a client with |path| and watch its lifeline using |lifeline_fd|.
  // Return the assigned client id after successfully registration.
  std::optional<std::string> RegisterClient(int lifeline_fd,
                                            const base::FilePath& path);

  // Try to detach the kernel driver to the interface of |iface_num| of the USB
  // device associated with the |client_id|.
  bool DetachInterface(const std::string& client_id, uint8_t iface_num);

  // Try to reattach the kernel driver to the interface of |iface_num| of the
  // USB device associated with the |client_id|.
  bool ReattachInterface(const std::string& client_id, uint8_t iface_num);

 private:
  friend class UsbDriverTrackerTest;
  friend class MockUsbDriverTracker;

  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerTest, RegisterClientSuccess);
  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerTest, RegisterClientDifferentIds);
  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerTest, RegisterClientOpenPathFail);
  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerTest,
                           RegisterClientDupLifelineFdFail);
  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerTest,
                           RegisterClientWatchLifelineFdFail);
  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerTest, CleanUpTracking);
  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerTest,
                           CleanUpTrackingConnectInterfaceFail);
  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerTest, HandleClosedFd);
  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerTest,
                           HandleClosedFdConnectInterfaceError);
  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerTest,
                           HandleClosedFdUnTrackedClientId);
  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerTest,
                           HandleClosedFdTwoClientsOnDifferentPaths);
  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerTest,
                           HandleClosedFdTwoClientsOnSamePath);
  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerTest, RecordInterfaceDetached);
  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerTest, ClearDetachedInterfaceRecord);
  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerTest, DetachInterfaceSuccess);
  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerTest,
                           DetachInterfaceUnTrackedClientFail);
  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerTest,
                           DetachInterfaceIfaceDetachedByOtherClient);
  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerTest,
                           DetachInterfaceIfaceAlreadyDetachedByTheClientNoOp);
  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerTest,
                           DetachInterfaceIfaceDisconnectFail);
  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerTest, ReattachInterfaceSuccess);
  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerTest,
                           ReattachInterfaceUntrackedClientFail);
  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerTest,
                           ReattachInterfacePathNoIfaceDetachedNoOp);
  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerTest,
                           ReattachInterfaceIfaceNotDetachedNoOp);
  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerTest,
                           ReattachInterfaceIfaceDetachedByOtherClient);

  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerDeathTest,
                           RecordInterfaceDetachedUntrackedClient);
  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerDeathTest,
                           RecordInterfaceDetachedIfaceWatched);
  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerDeathTest,
                           ClearDetachedInterfaceRecordUntrackedClient);
  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerDeathTest,
                           ClearDetachedInterfaceRecordUnknownPath);
  FRIEND_TEST_ALL_PREFIXES(UsbDriverTrackerDeathTest,
                           ClearDetachedInterfaceRecordDupIface);

  struct UsbInterfaces {
    // Note we have this structure take ownership of the |controller| and
    // |lifeline_fd| to keep readable callback registered.
    base::FilePath path;
    std::unique_ptr<base::FileDescriptorWatcher::Controller> controller;
    std::vector<uint8_t> interfaces;
    base::ScopedFD fd;  // Client's open path file descriptor.
    base::ScopedFD lifeline_fd;
  };

  using ClientMap = std::map<std::string /* client_id */, UsbInterfaces>;
  using PathMap = std::map<
      base::FilePath /* device_path */,
      std::map<uint8_t /* interface_num*/, std::string /* client_id */>>;

  void HandleClosedFd(std::string client_id);
  virtual std::unique_ptr<base::FileDescriptorWatcher::Controller>
  WatchLifelineFd(const std::string& client_id, int lifeline_fd);

  virtual bool DisconnectInterface(int fd, uint8_t iface_num);
  virtual bool ConnectInterface(int fd, uint8_t iface_num);

  // These two are to update tracking structures, assuming checks
  // are done by the caller.
  void RecordInterfaceDetached(const std::string& client_id,
                               const base::FilePath& path,
                               uint8_t iface_num);
  void ClearDetachedInterfaceRecord(const std::string& client_id,
                                    const base::FilePath& path,
                                    uint8_t iface_num);

  // This is used by the destructor for reattaching any detached interfaces
  // being tracked.
  virtual void CleanUpTracking();

  // Check if |client_id| is being tracked.
  bool IsClientIdTracked(const std::string& client_id);

  // This structure is to track registered clients for their detaching and
  // reattaching requests, and cleanup reattaching when the client terminates.
  // The key is the client's id which is a 128-bit token.
  ClientMap dev_fds_;

  // This structure is to track USB device interfaces' detaching states. It is
  // used to detect conflicts between clients making requests to detach or
  // reattach the same device interface. The key of the first layer map is the
  // usb device path, and the key of the second layer map is the interface
  // number of the usb device. The value of the map is the id of the client who
  // detaches the interface.
  PathMap dev_ifaces_;

  base::WeakPtrFactory<UsbDriverTracker> weak_ptr_factory_{this};
};

}  // namespace permission_broker

#endif  // PERMISSION_BROKER_USB_DRIVER_TRACKER_H_
