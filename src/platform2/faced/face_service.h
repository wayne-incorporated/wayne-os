// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_FACE_SERVICE_H_
#define FACED_FACE_SERVICE_H_

#include <libminijail.h>
#include <scoped_minijail.h>

#include <memory>
#include <utility>

#include <absl/status/status.h>
#include <absl/status/statusor.h>
#include <base/files/scoped_file.h>
#include <base/functional/callback_forward.h>
#include <base/task/sequenced_task_runner.h>
#include <brillo/grpc/async_grpc_client.h>

#include "faced/proto/face_service.grpc.pb.h"
#include "faced/util/lease.h"

namespace faced {

// Create a pair of sockets.
absl::StatusOr<std::pair<base::ScopedFD, base::ScopedFD>> SocketPair();

// FaceServiceClient encapsulates a gRPC channel and client for communicating
// with the FaceServiceProcess.
class FaceServiceClient {
 public:
  // Create a connection to a FaceService instance, using the given socket `fd`
  // as the transport.
  explicit FaceServiceClient(base::ScopedFD fd);

  ~FaceServiceClient();

  // Disallow copy, allow move.
  FaceServiceClient(FaceServiceClient&&) = default;
  FaceServiceClient& operator=(FaceServiceClient&&) = default;

  // Get the gRPC stub to FaceService.
  //
  // Ownership is retained by this class.
  brillo::AsyncGrpcClient<faceauth::eora::FaceService>* GetAsyncClient();

  // Close the connection to FaceService.
  void ShutDown();

 private:
  // The gRPC channel used to create a client
  std::shared_ptr<grpc::Channel> channel_;

  // The gRPC client for FaceService
  std::unique_ptr<brillo::AsyncGrpcClient<faceauth::eora::FaceService>>
      rpc_client_;
};

// FaceServiceProcess contains the minijail process and file descriptor of the
// gRPC service application.
class FaceServiceProcess {
 public:
  static absl::StatusOr<std::unique_ptr<FaceServiceProcess>> Create();

  FaceServiceProcess() = default;
  ~FaceServiceProcess() = default;

  // Disallow copy and move.
  FaceServiceProcess(const FaceServiceProcess&) = delete;
  FaceServiceProcess& operator=(const FaceServiceProcess&) = delete;

  // Starts the process.
  absl::Status Start();

  // Stops the process.
  absl::Status ShutDown();

  // Returns a client connected to this process.
  //
  // Creating a client consumes the file descriptor and can only
  // be performed once.
  absl::StatusOr<std::unique_ptr<FaceServiceClient>> CreateClient();

 private:
  // The Minijail containing the launched FaceService app.
  ScopedMinijail jail_;

  // The socket connection to the FaceService app.
  base::ScopedFD fd_;
};

class FaceServiceManagerInterface {
 public:
  virtual ~FaceServiceManagerInterface() = default;

  // Returns a client to the running FaceService.
  //
  // Only one client can be leased at any time.
  //
  // Returns an error if the client is already being leased.
  virtual absl::StatusOr<
      Lease<brillo::AsyncGrpcClient<faceauth::eora::FaceService>>>
  LeaseClient() = 0;
};

// FaceServiceManager is responsible for starting FaceServiceProcess
// and for leasing out an exclusive FaceServiceClient.
class FaceServiceManager : public FaceServiceManagerInterface {
 public:
  static std::unique_ptr<FaceServiceManager> Create();

  FaceServiceManager() = default;
  ~FaceServiceManager() override;

  // Disallow copy and move.
  FaceServiceManager(const FaceServiceManager&) = delete;
  FaceServiceManager& operator=(const FaceServiceManager&) = delete;

  // Implementation of `FaceServiceManagerInterface`
  absl::StatusOr<Lease<brillo::AsyncGrpcClient<faceauth::eora::FaceService>>>
  LeaseClient() override;

 private:
  // Handle release of leased FaceServiceClient.
  void OnReleaseClient();

  // Keeps track of whether the client is currently leased.
  bool leased_;

  std::unique_ptr<FaceServiceProcess> process_;
  std::unique_ptr<FaceServiceClient> client_;
};

}  // namespace faced

#endif  // FACED_FACE_SERVICE_H_
