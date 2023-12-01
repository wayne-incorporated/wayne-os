// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLCSERVICE_DLC_INTERFACE_H_
#define DLCSERVICE_DLC_INTERFACE_H_

#include <optional>
#include <string>

#include <base/files/file_path.h>
#include <brillo/errors/error.h>
#include <dlcservice/proto_bindings/dlcservice.pb.h>

#include "dlcservice/types.h"
#include "dlcservice/utils.h"

namespace dlcservice {

class DlcInterface {
 public:
  DlcInterface() = default;
  virtual ~DlcInterface() = default;

  DlcInterface(const DlcInterface&) = delete;
  DlcInterface& operator=(const DlcInterface&) = delete;

  // Initializes the DLC. This should be called right after creating the DLC
  // object.
  virtual bool Initialize() = 0;

  // Returns the ID of the DLC.
  virtual const DlcId& GetId() const = 0;

  // Returns the human readable name of the DLC.
  virtual const std::string& GetName() const = 0;

  // Returns the description of the DLC.
  virtual const std::string& GetDescription() const = 0;

  // Returns the current state of the DLC.
  virtual DlcState GetState() const = 0;

  // Returns the root directory inside a mounted DLC module.
  virtual base::FilePath GetRoot() const = 0;

  // Returns true if the DLC is currently being installed.
  virtual bool IsInstalling() const = 0;

  // Returns true if the DLC is already installed and mounted.
  virtual bool IsInstalled() const = 0;

  // Returns true if the DLC is marked verified.
  virtual bool IsVerified() const = 0;

  // Returns true if the DLC is scaled.
  virtual bool IsScaled() const = 0;

  // Returns true if the DLC has any content on disk that is taking space. This
  // means mainly if it has images on disk.
  virtual bool HasContent() const = 0;

  // Returns the amount of disk space this DLC is using right now.
  virtual uint64_t GetUsedBytesOnDisk() const = 0;

  // Returns true if the DLC has a boolean true for 'preload-allowed'
  // attribute in the manifest for the given |id| and |package|.
  virtual bool IsPreloadAllowed() const = 0;

  // Returns true if the DLC has a boolean true for 'factory-install'
  // attribute in the manifest for the given `id` and `package`.
  virtual bool IsFactoryInstall() const = 0;

  // Creates the DLC image based on the fields from the manifest if the DLC is
  // not installed. If the DLC image exists or is installed already, some
  // verifications are passed to validate that the DLC is mounted.
  // Initializes the installation like creating the necessary files, etc.
  virtual bool Install(brillo::ErrorPtr* err) = 0;

  // This is called after the update_engine finishes the installation of a
  // DLC. This marks the DLC as installed and mounts the DLC image.
  virtual bool FinishInstall(bool installed_by_ue, brillo::ErrorPtr* err) = 0;

  // Cancels the ongoing installation of this DLC. The state will be set to
  // uninstalled after this call if successful.
  // The |err_in| argument is the error that causes the install to be cancelled.
  virtual bool CancelInstall(const brillo::ErrorPtr& err_in,
                             brillo::ErrorPtr* err) = 0;

  // Uninstalls the DLC.
  // Deletes all files associated with the DLC.
  virtual bool Uninstall(brillo::ErrorPtr* err) = 0;

  // Is called when the DLC image is finally installed on the disk and is
  // verified.
  virtual bool InstallCompleted(brillo::ErrorPtr* err) = 0;

  // Is called when the inactive DLC image is updated and verified.
  virtual bool UpdateCompleted(brillo::ErrorPtr* err) = 0;

  // Makes the DLC ready to be updated (creates and resizes the inactive
  // image). Returns false if anything goes wrong.
  virtual bool MakeReadyForUpdate() const = 0;

  // Changes the install progress on this DLC. Only changes if the |progress| is
  // greater than the current progress value.
  virtual void ChangeProgress(double progress) = 0;

  // Toggle for DLC to be reserved.
  // Will return the value set, pass `nullptr` to use as getter.
  virtual bool SetReserve(std::optional<bool> reserve) = 0;
};

}  // namespace dlcservice

#endif  // DLCSERVICE_DLC_INTERFACE_H_
