// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/wilco_ec/ec_service.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <utility>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/ref_counted.h>
#include <base/posix/eintr_wrapper.h>
#include <base/task/single_thread_task_runner.h>

namespace diagnostics {

namespace internal {

// This is the background ("monitoring") thread delegate used by
// |EcService|.
class EcEventMonitoringThreadDelegate final
    : public base::DelegateSimpleThread::Delegate {
 public:
  using OnEventAvailableCallback =
      base::RepeatingCallback<void(const EcService::EcEvent&)>;

  // |EcService| guarantees that the unowned pointer and file descriptors
  // outlive this delegate. This delegate will post
  // |on_event_available_callback| on the |foreground_task_runner| when an EC
  // event is available and it will post |on_shutdown_callback| on the
  // |foreground_task_runner| when it is shutting down.
  EcEventMonitoringThreadDelegate(
      int event_fd,
      int16_t event_fd_events,
      int shutdown_fd,
      scoped_refptr<base::SequencedTaskRunner> foreground_task_runner,
      OnEventAvailableCallback on_event_available_callback,
      base::OnceClosure on_shutdown_callback)
      : foreground_task_runner_(foreground_task_runner),
        on_event_available_callback_(std::move(on_event_available_callback)),
        on_shutdown_callback_(std::move(on_shutdown_callback)) {
    fds[0] = pollfd{event_fd, event_fd_events, 0};
    fds[1] = pollfd{shutdown_fd, POLLIN, 0};
  }

  ~EcEventMonitoringThreadDelegate() override = default;

  void Run() override {
    while (true) {
      int retval =
          HANDLE_EINTR(poll(fds, 2 /* nfds */, -1 /* infinite timeout */));
      if (retval < 0) {
        PLOG(ERROR)
            << "EC event poll error. Shutting down EC monitoring thread";
        break;
      }
      if (fds[1].events & fds[1].revents) {
        // Exit: the main thread requested our shutdown by writing data into
        // |shutdown_fd_|.
        break;
      }
      if ((fds[0].revents & POLLERR) || (fds[1].revents & POLLERR)) {
        LOG(ERROR) << "EC event POLLERR poll error. Shutting down EC"
                      " monitoring thread";
        break;
      }
      if ((fds[0].events & fds[0].revents) == 0) {
        // No data available for reading from |event_fd_|, so proceed to poll()
        // to wait for new events.
        continue;
      }

      EcService::EcEvent ec_event;
      ssize_t bytes_read =
          HANDLE_EINTR(read(fds[0].fd, &ec_event, sizeof(ec_event)));
      if (bytes_read < 0) {
        PLOG(ERROR)
            << "EC event read error. Shutting down EC monitoring thread";
        break;
      }
      if (bytes_read > 0) {
        foreground_task_runner_->PostTask(
            FROM_HERE, base::BindOnce(on_event_available_callback_, ec_event));
      }
    }

    foreground_task_runner_->PostTask(FROM_HERE,
                                      std::move(on_shutdown_callback_));
  }

 private:
  // Pollfd array, where |fds[0]| is a real sysfs fd and |fds[1]| is a fake fd
  // used to shutdown this monitoring thread delegate.
  // Not owned.
  pollfd fds[2];

  // The |SequencedTaskRunner| this object is posting tasks to. It is accessed
  // from the monitoring thread.
  scoped_refptr<base::SequencedTaskRunner> foreground_task_runner_;

  OnEventAvailableCallback on_event_available_callback_;
  base::OnceClosure on_shutdown_callback_;
};

}  // namespace internal

EcService::EcEvent::EcEvent() = default;

EcService::EcEvent::EcEvent(uint16_t num_words_in_payload,
                            Type type,
                            const uint16_t payload[6])
    : size(num_words_in_payload + 1), type(type), payload{} {
  memcpy(&this->payload, payload,
         std::min(sizeof(this->payload),
                  num_words_in_payload * sizeof(payload[0])));
}

EcService::EcEvent::Reason EcService::EcEvent::GetReason() const {
  if (type != Type::SYSTEM_NOTIFY) {
    return Reason::kNonSysNotification;
  }

  const SystemNotifyPayload::SystemNotifyFlags& flags =
      payload.system_notify.flags;
  switch (payload.system_notify.sub_type) {
    case SystemNotifySubType::AC_ADAPTER:
      if (flags.ac_adapter.cause & AcAdapterFlags::Cause::NON_WILCO_CHARGER) {
        return Reason::kNonWilcoCharger;
      }
      if (flags.ac_adapter.cause & AcAdapterFlags::Cause::LOW_POWER_CHARGER) {
        return Reason::kLowPowerCharger;
      }
      break;
    case SystemNotifySubType::BATTERY:
      if (flags.battery.cause & BatteryFlags::Cause::BATTERY_AUTH) {
        return Reason::kBatteryAuth;
      }
      break;
    case SystemNotifySubType::USB_C:
      if (flags.usb_c.billboard & UsbCFlags::Billboard::HDMI_USBC_CONFLICT) {
        return Reason::kDockDisplay;
      }
      if (flags.usb_c.dock &
          UsbCFlags::Dock::THUNDERBOLT_UNSUPPORTED_USING_USBC) {
        return Reason::kDockThunderbolt;
      }
      if (flags.usb_c.dock & UsbCFlags::Dock::INCOMPATIBLE_DOCK) {
        return Reason::kIncompatibleDock;
      }
      if (flags.usb_c.dock & UsbCFlags::Dock::OVERTEMP_ERROR) {
        return Reason::kDockError;
      }
      break;
  }
  return Reason::kSysNotification;
}

size_t EcService::EcEvent::PayloadSizeInBytes() const {
  // Guard against the case when |size| == 0.
  uint16_t sanitized_size = std::max(size, static_cast<uint16_t>(1));
  return (sanitized_size - 1) * sizeof(uint16_t);
}

EcService::EcService()
    : task_runner_(base::SingleThreadTaskRunner::GetCurrentDefault()) {}

EcService::~EcService() {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  DCHECK(!monitoring_thread_);
}

bool EcService::Start() {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  DCHECK(!monitoring_thread_);

  auto event_file_path = root_dir_.Append(kEcEventFilePath);
  event_fd_.reset(HANDLE_EINTR(
      open(event_file_path.value().c_str(), O_RDONLY | O_NONBLOCK)));
  if (!event_fd_.is_valid()) {
    PLOG(ERROR) << "Unable to open sysfs event file: "
                << event_file_path.value();
    return false;
  }

  shutdown_fd_.reset(eventfd(0, EFD_NONBLOCK));
  if (!shutdown_fd_.is_valid()) {
    PLOG(ERROR) << "Unable to create eventfd";
    return false;
  }

  monitoring_thread_delegate_ =
      std::make_unique<internal::EcEventMonitoringThreadDelegate>(
          event_fd_.get(), event_fd_events_, shutdown_fd_.get(), task_runner_,
          base::BindRepeating(&EcService::OnEventAvailable,
                              base::Unretained(this)),
          base::BindOnce(&EcService::OnShutdown, base::Unretained(this)));
  monitoring_thread_ = std::make_unique<base::DelegateSimpleThread>(
      monitoring_thread_delegate_.get(),
      "WilcoDtcSupportdEcEventMonitoring" /* name_prefix */);
  monitoring_thread_->Start();
  return true;
}

void EcService::ShutDown(base::OnceClosure on_shutdown_callback) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  DCHECK(on_shutdown_callback_.is_null());
  DCHECK(!on_shutdown_callback.is_null());

  if (!monitoring_thread_) {
    std::move(on_shutdown_callback).Run();
    return;
  }

  on_shutdown_callback_ = std::move(on_shutdown_callback);

  ShutDownMonitoringThread();
}

EcService::GetEcTelemetryResponse EcService::GetEcTelemetry(
    const std::string& request_payload) {
  auto reply = GetEcTelemetryResponse();
  if (request_payload.empty()) {
    LOG(ERROR) << "GetEcTelemetry request payload was empty";
    reply.status = GetEcTelemetryResponse::STATUS_ERROR_INPUT_PAYLOAD_EMPTY;
    return reply;
  }
  if (request_payload.length() > kEcGetTelemetryPayloadMaxSize) {
    LOG(ERROR) << "GetEcTelemetry request payload size was exceeded: "
               << request_payload.length() << " vs "
               << kEcGetTelemetryPayloadMaxSize << " allowed";
    reply.status =
        GetEcTelemetryResponse::STATUS_ERROR_INPUT_PAYLOAD_MAX_SIZE_EXCEEDED;
    return reply;
  }

  base::FilePath telemetry_file_path =
      root_dir_.Append(kEcGetTelemetryFilePath);

  // Use base::ScopedFD to operate with non-seekable files.
  base::ScopedFD telemetry_file(
      HANDLE_EINTR(open(telemetry_file_path.value().c_str(), O_RDWR)));

  if (!telemetry_file.is_valid()) {
    VPLOG(2) << "GetEcTelemetry could not open the "
             << "telemetry node: " << telemetry_file_path.value();
    reply.status = GetEcTelemetryResponse::STATUS_ERROR_ACCESSING_DRIVER;
    return reply;
  }

  int write_result = HANDLE_EINTR(write(
      telemetry_file.get(), request_payload.c_str(), request_payload.length()));
  if (write_result != request_payload.length()) {
    VPLOG(2) << "GetEcTelemetry could not write request payload to the "
             << "telemetry node: " << telemetry_file_path.value();
    reply.status = GetEcTelemetryResponse::STATUS_ERROR_ACCESSING_DRIVER;
    return reply;
  }

  // Reply payload must be empty in case of any failure.
  char file_content[kEcGetTelemetryPayloadMaxSize];
  int read_result = HANDLE_EINTR(
      read(telemetry_file.get(), file_content, kEcGetTelemetryPayloadMaxSize));
  if (read_result == 0) {
    VPLOG(2) << "GetEcTelemetry could not read EC telemetry command "
             << "response from telemetry node: " << telemetry_file_path.value();
    reply.status = GetEcTelemetryResponse::STATUS_ERROR_ACCESSING_DRIVER;
    return reply;
  }

  reply.status = GetEcTelemetryResponse::STATUS_OK;
  reply.payload = std::string(file_content, read_result);
  return reply;
}

void EcService::AddObserver(EcService::Observer* observer) {
  DCHECK(observer);
  observers_.AddObserver(observer);
}

void EcService::RemoveObserver(EcService::Observer* observer) {
  DCHECK(observer);
  observers_.RemoveObserver(observer);
}

bool EcService::HasObserver(EcService::Observer* observer) {
  DCHECK(observer);
  return observers_.HasObserver(observer);
}

void EcService::ShutDownMonitoringThread() {
  // Due to |eventfd| documentation to invoke |poll()| on |shutdown_fd_| file
  // descriptor we must write any 8-byte value greater than 0 except
  // |0xffffffffffffffff|.
  uint64_t counter = 1;
  if (HANDLE_EINTR(write(shutdown_fd_.get(), &counter, sizeof(counter))) !=
      sizeof(counter)) {
    PLOG(ERROR)
        << "Unable to write data in fake fd to shutdown EC event service";
  }
}

void EcService::OnEventAvailable(const EcEvent& ec_event) {
  DCHECK(sequence_checker_.CalledOnValidSequence());

  for (auto& observer : observers_)
    observer.OnEcEvent(ec_event);
}

void EcService::OnShutdown() {
  DCHECK(sequence_checker_.CalledOnValidSequence());

  monitoring_thread_->Join();
  monitoring_thread_.reset();
  monitoring_thread_delegate_.reset();

  if (!on_shutdown_callback_.is_null()) {
    std::move(on_shutdown_callback_).Run();
    std::move(on_shutdown_callback_).Reset();
  }
}

}  // namespace diagnostics
