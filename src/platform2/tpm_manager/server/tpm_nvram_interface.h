// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_TPM_NVRAM_INTERFACE_H_
#define TPM_MANAGER_SERVER_TPM_NVRAM_INTERFACE_H_

#include <base/functional/callback.h>

#include <tpm_manager/proto_bindings/tpm_manager.pb.h>

#include "tpm_manager/common/export.h"

namespace tpm_manager {

// The command interface for working with TPM NVRAM. Inherited by both IPC proxy
// and service classes. All methods are asynchronous because all TPM operations
// may take a long time to finish.
class TPM_MANAGER_EXPORT TpmNvramInterface {
 public:
  virtual ~TpmNvramInterface() = default;

  // Processes a DefineSpaceRequest and responds with a DefineSpaceReply.
  using DefineSpaceCallback = base::OnceCallback<void(const DefineSpaceReply&)>;
  virtual void DefineSpace(const DefineSpaceRequest& request,
                           DefineSpaceCallback callback) = 0;

  // Processes a DestroySpaceRequest and responds with a DestroySpaceReply.
  using DestroySpaceCallback =
      base::OnceCallback<void(const DestroySpaceReply&)>;
  virtual void DestroySpace(const DestroySpaceRequest& request,
                            DestroySpaceCallback callback) = 0;

  // Processes a WriteSpaceRequest and responds with a WriteSpaceReply.
  using WriteSpaceCallback = base::OnceCallback<void(const WriteSpaceReply&)>;
  virtual void WriteSpace(const WriteSpaceRequest& request,
                          WriteSpaceCallback callback) = 0;

  // Processes a ReadSpaceRequest and responds with a ReadSpaceReply.
  using ReadSpaceCallback = base::OnceCallback<void(const ReadSpaceReply&)>;
  virtual void ReadSpace(const ReadSpaceRequest& request,
                         ReadSpaceCallback callback) = 0;

  // Processes a LockSpaceRequest and responds with a LockSpaceReply.
  using LockSpaceCallback = base::OnceCallback<void(const LockSpaceReply&)>;
  virtual void LockSpace(const LockSpaceRequest& request,
                         LockSpaceCallback callback) = 0;

  // Processes a ListSpacesRequest and responds with a ListSpacesReply.
  using ListSpacesCallback = base::OnceCallback<void(const ListSpacesReply&)>;
  virtual void ListSpaces(const ListSpacesRequest& request,
                          ListSpacesCallback callback) = 0;

  // Processes a GetSpaceInfoRequest and responds with a GetSpaceInfoReply.
  using GetSpaceInfoCallback =
      base::OnceCallback<void(const GetSpaceInfoReply&)>;
  virtual void GetSpaceInfo(const GetSpaceInfoRequest& request,
                            GetSpaceInfoCallback callback) = 0;
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_TPM_NVRAM_INTERFACE_H_
