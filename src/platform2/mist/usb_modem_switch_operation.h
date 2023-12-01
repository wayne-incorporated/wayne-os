// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MIST_USB_MODEM_SWITCH_OPERATION_H_
#define MIST_USB_MODEM_SWITCH_OPERATION_H_

#include <stdint.h>

#include <memory>
#include <string>

#include <base/cancelable_callback.h>
#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <base/time/time.h>
#include <brillo/usb/usb_device_event_observer.h>

namespace brillo {

class UsbBulkTransfer;
class UsbDevice;
class UsbTransfer;

}  // namespace brillo

namespace mist {

class Context;
class UsbModemSwitchContext;

// A USB modem switch operation for switching a USB modem into the modem mode.
// The whole operation involves the following tasks:
// 1. Open the USB modem device. If the modem has a USB configuration that
//    exposes a MBIM interface, select that configuration and complete the
//    switch operation. Otherwise, find and claim the mass storage interface of
//    the mdoem.
// 2. Initiate a bulk output transfer of a (or multiple) special USB message(s)
//    to the mass storage endpoint of the modem.
// 3. On some modems, a bulk input transfer from the mass storage endpoint of
//    the modem is expected after completing each bulk output transfer.
// 4. Once the transfer of the last message completes, the modem is expected to
//    disconnect from the USB bus and then reconnect to the bus after it has
//    been switched to the modem mode.
//
// As mist may run multiple modem switch operations concurrently, in order to
// maximize the overall concurrency, the modem switch operation is broken up
// into the aforementioned tasks and each task is scheduled to execute in the
// message loop via EventDispatcher.
class UsbModemSwitchOperation
    : public base::SupportsWeakPtr<UsbModemSwitchOperation>,
      public brillo::UsbDeviceEventObserver {
 public:
  using CompletionCallback = base::OnceCallback<void(
      UsbModemSwitchOperation* operation, bool success)>;

  // Constructs a UsbModemSwitchOperation object by taking a raw pointer to a
  // Context object as |context| and a raw pointer to a UsbModemSwitchContext
  // object as |switch_context| that contains information about the device to
  // be switched to the modem mode. The ownership of |context| is not
  // transferred, and thus it should outlive this object. The ownership of
  // |switch_context| is transferred.
  UsbModemSwitchOperation(Context* context,
                          UsbModemSwitchContext* switch_context);
  UsbModemSwitchOperation(const UsbModemSwitchOperation&) = delete;
  UsbModemSwitchOperation& operator=(const UsbModemSwitchOperation&) = delete;

  ~UsbModemSwitchOperation();

  // Starts the modem switch operation. Upon the completion of the operation,
  // the completion callback |completion_callback| is invoked with the status
  // of the operation.
  void Start(CompletionCallback completion_callback);

  // Cancels the modem switch operation and closes any open device. It is a
  // no-op if the operation has not been started by Start().
  void Cancel();

 private:
  using Task = void (UsbModemSwitchOperation::*)();
  using UsbTransferCompletionHandler =
      void (UsbModemSwitchOperation::*)(brillo::UsbTransfer* transfer);

  // Schedules the specified |task| in the message loop for execution. At most
  // one pending task is allowed, so any pending task previously scheduled by
  // ScheduleTask() or ScheduleDelayedTask() is cancelled before |task| is
  // scheduled.
  void ScheduleTask(Task task);

  // Schedules the specified |task| in the message loop for execution after the
  // specified |delay|. At most one pending task is allowed, so any pending
  // task previously scheduled by ScheduleTask() or ScheduleDelayedTask() is
  // cancelled before |task| is scheduled.
  void ScheduleDelayedTask(Task task, const base::TimeDelta& delay);

  // Completes the operation, which invokes the completion callback with the
  // status of the operation as |success|. The completion callback may delete
  // this object, so this object should not be accessed after this method
  // returns.
  void Complete(bool success);

  // Detaches all the kernel drivers associated with the interfaces of the
  // currently active USB configuration. Continues to detach other kernel
  // drivers if it fails to detach any driver.
  void DetachAllKernelDrivers();

  // Returns the value of the USB configuration at which the device exposes a
  // MBIM interface, or kUsbConfigurationValueInvalid if no MBIM interface is
  // found.
  int GetMBIMConfigurationValue();

  // Sets the USB configuration of the device to |configuration|. Returns true
  // on success.
  bool SetConfiguration(int configuration);

  // Closes the device.
  void CloseDevice();

  // Opens the device. If the device has a USB configuration that exposes a MBIM
  // interface, selects that configuration and completes the switch operation.
  // Otherwise, finds and claims the mass storage interface on the device.
  void OpenDeviceAndSelectInterface();

  // Clears the halt condition on the endpoint at |endpoint_address|. Returns
  // true on success.
  bool ClearHalt(uint8_t endpoint_address);

  // Sends a special USB message to the mass storage endpoint of the device.
  void SendMessageToMassStorageEndpoint();

  // Receives a USB message from the mass storage endpoint of the device.
  void ReceiveMessageFromMassStorageEndpoint();

  // Creates and submits a USB bulk transfer to the specified |endpoint_address|
  // on the device. |length| specifies the size of the transfer in bytes. For a
  // host-to-device transfer, |data| should point to a buffer containing
  // |length| bytes of data to be transferred. For a device-to-host transfer,
  // |data| is not used and thus ignored. |completion_handler| will be invoked
  // upon the completion of the transfer.
  void InitiateUsbBulkTransfer(uint8_t endpoint_address,
                               const uint8_t* data,
                               int length,
                               UsbTransferCompletionHandler completion_handler);

  // Schedules the invocation of SendMessageToMassStorageEndpoint() on the next
  // USB message to be sent to the mass storage endpoint of the device, or when
  // there is no more message to send, schedule the wait for the device to
  // reconnect.
  void ScheduleNextMessageToMassStorageEndpoint();

  // Starts waiting for the device to reconnect to the USB bus.
  void StartWaitingForDeviceToReconnect();

  // Invoked upon the completion of the last USB bulk transfer submitted by
  // SendMessageToMassStorageEndpoint().
  void OnSendMessageCompleted(brillo::UsbTransfer* transfer);

  // Invoked upon the completion of the last USB bulk transfer submitted by
  // ReceiveMessageFromMassStorageEndpoint().
  void OnReceiveMessageCompleted(brillo::UsbTransfer* transfer);

  // Invoked when this switcher times out waiting for the device to reconnect
  // to the bus, after a specified period time since
  // StartWaitingForDeviceToReconnect() is invoked.
  void OnReconnectTimeout();

  // Implements UsbDeviceEventObserver.
  void OnUsbDeviceAdded(const std::string& sys_path,
                        uint8_t bus_number,
                        uint8_t device_address,
                        uint16_t vendor_id,
                        uint16_t product_id) override;
  void OnUsbDeviceRemoved(const std::string& sys_path) override;

  Context* const context_;
  std::unique_ptr<UsbModemSwitchContext> switch_context_;
  std::unique_ptr<brillo::UsbDevice> device_;
  CompletionCallback completion_callback_;
  bool interface_claimed_;
  uint8_t interface_number_;
  uint8_t in_endpoint_address_;
  uint8_t out_endpoint_address_;
  int message_index_;
  int num_usb_messages_;
  std::unique_ptr<brillo::UsbBulkTransfer> bulk_transfer_;
  base::CancelableOnceClosure pending_task_;
  base::CancelableOnceClosure reconnect_timeout_callback_;
};

}  // namespace mist

#endif  // MIST_USB_MODEM_SWITCH_OPERATION_H_
