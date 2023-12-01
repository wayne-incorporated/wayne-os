// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_WILCO_EC_EC_SERVICE_H_
#define DIAGNOSTICS_CROS_HEALTHD_WILCO_EC_EC_SERVICE_H_

#include <cstdint>
#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/functional/callback.h>
#include <base/observer_list.h>
#include <base/observer_list_types.h>
#include <base/sequence_checker_impl.h>
#include <base/task/single_thread_task_runner.h>
#include <base/threading/simple_thread.h>

#include "diagnostics/cros_healthd/wilco_ec/ec_constants.h"

namespace diagnostics {

namespace internal {
class EcEventMonitoringThreadDelegate;
}  // namespace internal

// Reads EC telemetry data and subscribes on EC events then distributes them to
// the list of observers.
class EcService {
 public:
  // A packet of data sent by the EC when it notices certain events have
  // occurred, such as the battery, AC adapter, or USB-C state changing.
  // The format of this packet is a variable length sequence of 16-bit words.
  // Word 0 is the |size| word, representing the number of following
  // words in the struct. Word 1 is the |type| word. The following |size|-1
  // words are the |payload|. Depending on the value of |type|, the |payload|
  // is interpreted in different ways. There are other possible values of |type|
  // and other interpretations of |payload| than those listed here. There will
  // be, at most, 6 words in the |payload|. See section 2.3 "ACPI EC Event
  // notification" of the Wilco EC specification at go/wilco-ec-spec for more
  // information.
  struct alignas(2) EcEvent {
   public:
    // Derived value representing the reason/cause of the EC event.
    //
    // NOTE: This is a computed value and not sent by the EC.
    enum Reason {
      // |SYSTEM_NOTIFY| EC event types:
      //
      // When |SystemNotifySubType| is "AC_ADAPTER" and
      // |AcAdapterFlags::Cause::NON_WILCO_CHARGER| is true.
      kNonWilcoCharger,
      // When |SystemNotifySubType| is "AC_ADAPTER" and
      // |AcAdapterFlags::Cause::LOW_POWER_CHARGER| is true.
      kLowPowerCharger,
      // When |SystemNotifySubType| is "BATTERY" and
      // |BatteryFlags::Cause::BATTERY_AUTH| is true.
      kBatteryAuth,
      // When |SystemNotifySubType| is "USB_C" and
      // |UsbCFlags::Billboard::HDMI_USBC_CONFLICT| is true.
      kDockDisplay,
      // When |SystemNotifySubType| is "USB_C" and
      // |UsbCFlags::Dock|::THUNDERBOLT_UNSUPPORTED_USING_USBC| is true.
      kDockThunderbolt,
      // When |SystemNotifySubType| is "USB_C" and
      // |UsbCFlags::Dock::INCOMPATIBLE_DOCK| is true.
      kIncompatibleDock,
      // When |SystemNotifySubType| is "USB_C" and
      // |UsbCFlags::Dock::OVERTEMP_ERROR| is true.
      kDockError,

      // |SYSTEM_NOTIFY| EC event type with no appropriate |SystemNotifySubType|
      // or flags.
      kSysNotification,
      // Non |SYSTEM_NOTIFY| EC event type.
      kNonSysNotification,
    };

    // The |type| member will be one of these.
    enum Type : uint16_t {
      // Interpret |payload| as SystemNotifyPayload.
      SYSTEM_NOTIFY = 0x0012,
    };

    // Sub-types applicable for SystemNotifyPayload.
    enum SystemNotifySubType : uint16_t {
      AC_ADAPTER = 0x0000,
      BATTERY = 0x0003,
      USB_C = 0x0008,
    };

    // Flags used within |SystemNotifyPayload|.
    struct alignas(2) AcAdapterFlags {
      enum Cause : uint16_t {
        // Barrel charger is incompatible and performance will be restricted.
        NON_WILCO_CHARGER = 1 << 0,
        // Attached charger does not supply enough power.
        LOW_POWER_CHARGER = 1 << 1,
      };
      uint16_t reserved0;
      Cause cause;
      uint16_t reserved2;
      uint16_t reserved3;
      uint16_t reserved4;
    };

    // Flags used within |SystemNotifyPayload|.
    struct alignas(2) BatteryFlags {
      enum Cause : uint16_t {
        // An incompatible battery is connected and battery will not charge.
        BATTERY_AUTH = 1 << 0,
      };
      uint16_t reserved0;
      Cause cause;
      uint16_t reserved2;
      uint16_t reserved3;
      uint16_t reserved4;
    };

    // Flags used within |SystemNotifyPayload|
    struct alignas(2) UsbCFlags {
      // "Billboard" is the name taken directly from the EC spec. It's a weird
      // name, but these can represent a variety of miscellaneous events.
      enum Billboard : uint16_t {
        // HDMI and USB Type-C ports on the dock cannot be used for
        // displays at the same time. Only the first one connected will work.
        HDMI_USBC_CONFLICT = 1 << 9,
      };
      enum Dock : uint16_t {
        // Thunderbolt is not supported on Chromebooks, so the dock
        // will fall back on using USB Type-C.
        THUNDERBOLT_UNSUPPORTED_USING_USBC = 1 << 8,
        // Attached dock is incompatible.
        INCOMPATIBLE_DOCK = 1 << 12,
        // Attached dock has overheated.
        OVERTEMP_ERROR = 1 << 15,
      };
      Billboard billboard;
      uint16_t reserved1;
      Dock dock;
    };

    // Interpretation of |payload| applicable when |type|==Type::SYSTEM_NOTIFY.
    struct alignas(2) SystemNotifyPayload {
      SystemNotifySubType sub_type;
      // Depending on |sub_type| we interpret the following data in different
      // ways. Note that these flags aren't all the same size.
      union SystemNotifyFlags {
        AcAdapterFlags ac_adapter;
        BatteryFlags battery;
        UsbCFlags usb_c;
      } flags;
    };

    EcEvent();

    EcEvent(uint16_t num_words_in_payload,
            Type type,
            const uint16_t payload[6]);

    bool operator==(const EcEvent& other) const {
      return memcmp(this, &other, sizeof(*this)) == 0;
    }

    // Extracts the EC event's reason from the event's |Type|,
    // |SystemNotifySubType| and flags.
    Reason GetReason() const;

    // Translates the |size| member into how many bytes of |payload| are used.
    size_t PayloadSizeInBytes() const;

    // |size| is the number of following 16-bit words in the event.
    // Default is 1 to account for |type| word and empty |payload|.
    uint16_t size = 1;
    Type type = static_cast<Type>(0);
    // Depending on |type| we interpret the following data in different ways.
    union {
      SystemNotifyPayload system_notify;
    } payload = {};
  };

  class Observer : public base::CheckedObserver {
   public:
    virtual ~Observer() = default;

    // Called when event from EC was received.
    virtual void OnEcEvent(const EcEvent& ec_event) = 0;
  };

  struct GetEcTelemetryResponse {
    enum Status {
      STATUS_UNSET,
      // The EC telemetry command was successfully completed.
      STATUS_OK,
      // The EC telemetry command was rejected due to the empty request payload.
      STATUS_ERROR_INPUT_PAYLOAD_EMPTY,
      // The EC telemetry command was rejected due to the request payload being
      // too large.
      STATUS_ERROR_INPUT_PAYLOAD_MAX_SIZE_EXCEEDED,
      // The EC telemetry command was failed due to EC driver error.
      STATUS_ERROR_ACCESSING_DRIVER,
    };
    Status status;
    std::string payload;
  };

  EcService();
  EcService(const EcService&) = delete;
  EcService& operator=(const EcService&) = delete;

  virtual ~EcService();

  // Starts service.
  bool Start();

  // Shuts down service.
  void ShutDown(base::OnceClosure on_shutdown_callback);

  // Reads the telemetry information.
  GetEcTelemetryResponse GetEcTelemetry(const std::string& request_payload);

  // Overrides the file system root directory for file operations in tests.
  void set_root_dir_for_testing(const base::FilePath& root_dir) {
    root_dir_ = root_dir;
  }

  // Overrides the |event_fd_events_| in tests.
  void set_event_fd_events_for_testing(int16_t events) {
    event_fd_events_ = events;
  }

  void AddObserver(Observer* observer);
  void RemoveObserver(Observer* observer);
  bool HasObserver(Observer* observer);

 protected:
  base::ObserverList<Observer> observers_;

 private:
  // Signal via writing to the |shutdown_fd_| that the monitoring thread should
  // shut down. Once the monitoring thread handles this event and gets ready
  // for shutting down, it will reply by scheduling an invocation of
  // OnShutdown() on the foreground thread.
  void ShutDownMonitoringThread();

  // This is called on the |task_runner_| when new EC event
  // was received by background monitoring thread.
  void OnEventAvailable(const EcEvent& ec_event);

  // This is called on the |task_runner_| when the background
  // monitoring thread is shutting down.
  void OnShutdown();

  const scoped_refptr<base::SingleThreadTaskRunner> task_runner_;

  // This callback will be invoked after current service shutdown.
  base::OnceClosure on_shutdown_callback_;

  // The file system root directory. Can be overridden in tests.
  base::FilePath root_dir_{"/"};

  // EC event |event_fd_| and |event_fd_events_| are using for |poll()|
  // function in |monitoring_thread_|. Both can be overridden in tests.
  base::ScopedFD event_fd_;
  int16_t event_fd_events_ = kEcEventFilePollEvents;

  // Shutdown event fd. It is used to stop |poll()| immediately and shutdown
  // |monitoring_thread_|.
  base::ScopedFD shutdown_fd_;

  // The delegate which will be executed on the |monitoring_thread_|.
  std::unique_ptr<internal::EcEventMonitoringThreadDelegate>
      monitoring_thread_delegate_;
  // The background thread monitoring the EC sysfs file for upcoming events.
  std::unique_ptr<base::SimpleThread> monitoring_thread_;

  base::SequenceCheckerImpl sequence_checker_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_WILCO_EC_EC_SERVICE_H_
