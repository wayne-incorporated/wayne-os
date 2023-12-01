// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MIDIS_CLIENT_TRACKER_H_
#define MIDIS_CLIENT_TRACKER_H_

#include <map>
#include <memory>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/memory/weak_ptr.h>
#include <gtest/gtest_prod.h>
#include <mojo/core/embedder/scoped_ipc_support.h>

#include "midis/client.h"
#include "midis/device_tracker.h"
#include "mojo/midis.mojom.h"

namespace midis {

class ClientTracker {
 public:
  ClientTracker();
  ClientTracker(const ClientTracker&) = delete;
  ClientTracker& operator=(const ClientTracker&) = delete;

  ~ClientTracker();
  void InitClientTracker();
  void SetDeviceTracker(DeviceTracker* ptr) { device_tracker_ = ptr; }
  size_t GetNumClientsForTesting() const { return clients_.size(); }
  void RemoveClient(uint32_t client_id);

  // Sets up the MidisHost Mojo interface using the FD passed in
  // via D-Bus. The net result of this function should be the creation
  // of a MidisHostImpl object which ClientTracker manages.
  void AcceptProxyConnection(base::ScopedFD fd);

  // Helper function to check whether a |midis_host_| object is
  // already associated with ClientTracker.
  bool IsProxyConnected();

  // Create a new Mojo Client and place it in the list of clients.
  void MakeMojoClient(mojo::PendingReceiver<arc::mojom::MidisServer> receiver,
                      mojo::PendingRemote<arc::mojom::MidisClient> client);

 private:
  friend class ClientTrackerTest;
  FRIEND_TEST(ClientTrackerTest, AddClientPositive);
  // Helper function to set the base directory to be used for looking for the
  // Unix Domain socket path. Helpful for testing, where the we won't be allowed
  // to create directories in locations other than tempfs.
  void SetBaseDirForTesting(const base::FilePath& dir) { basedir_ = dir; }
  std::map<uint32_t, std::unique_ptr<Client>> clients_;
  base::ScopedFD server_fd_;
  int client_id_counter_;
  // ClientTracker and DeviceTracker both exist for the lifetime of the service.
  // As such, it is safe to maintain this pointer as a means to make updates and
  // derive information regarding devices.
  DeviceTracker* device_tracker_;
  base::FilePath basedir_;
  base::SequenceChecker sequence_checker_;
  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;
  std::unique_ptr<arc::mojom::MidisHost> midis_host_;

  base::WeakPtrFactory<ClientTracker> weak_factory_;
};

}  // namespace midis

#endif  // MIDIS_CLIENT_TRACKER_H_
