// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IIOSERVICE_DAEMON_EVENTS_HANDLER_H_
#define IIOSERVICE_DAEMON_EVENTS_HANDLER_H_

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/memory/weak_ptr.h>
#include <base/task/sequenced_task_runner.h>
#include <base/task/single_thread_task_runner.h>
#include <libmems/iio_device.h>
#include <mojo/public/cpp/bindings/remote_set.h>

#include "iioservice/daemon/common_types.h"
#include "iioservice/mojo/sensor.mojom.h"

namespace iioservice {

class EventsHandler {
 public:
  static void EventsHandlerDeleter(EventsHandler* handler);
  using ScopedEventsHandler =
      std::unique_ptr<EventsHandler, decltype(&EventsHandlerDeleter)>;

  static ScopedEventsHandler Create(
      scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
      scoped_refptr<base::SingleThreadTaskRunner> event_task_runner,
      libmems::IioDevice* iio_device);

  ~EventsHandler();

  void ResetWithReason(cros::mojom::SensorDeviceDisconnectReason reason,
                       std::string description);

  // It's the user's responsibility to maintain |client_data| before being
  // removed or this class being destructed.
  // |client_data.iio_device| should be the same as |iio_device_|.
  void AddClient(const std::vector<int32_t>& iio_event_indices,
                 mojo::PendingRemote<cros::mojom::SensorDeviceEventsObserver>
                     events_observer);

 private:
  EventsHandler(scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
                scoped_refptr<base::SingleThreadTaskRunner> event_task_runner,
                libmems::IioDevice* iio_device);

  void ResetWithReasonOnThread(cros::mojom::SensorDeviceDisconnectReason reason,
                               std::string description);

  void AddClientOnThread(
      const std::vector<int32_t>& iio_event_indices,
      mojo::PendingRemote<cros::mojom::SensorDeviceEventsObserver>
          events_observer);

  void OnEventsObserverDisconnect(mojo::RemoteSetElementId id);

  void SetEventWatcherOnThread();
  void StopEventWatcherOnThread();

  void OnEventAvailableWithoutBlocking();

  scoped_refptr<base::SequencedTaskRunner> ipc_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> event_task_runner_;
  libmems::IioDevice* iio_device_;

  mojo::RemoteSet<cros::mojom::SensorDeviceEventsObserver> events_observers_;
  std::map<mojo::RemoteSetElementId, std::vector<int32_t>> enabled_indices_;

  std::unique_ptr<base::FileDescriptorWatcher::Controller> watcher_;

  base::WeakPtrFactory<EventsHandler> weak_factory_{this};
};

}  // namespace iioservice

#endif  // IIOSERVICE_DAEMON_EVENTS_HANDLER_H_
