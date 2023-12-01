// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_NAMESPACES_MOUNT_NAMESPACE_H_
#define LIBBRILLO_BRILLO_NAMESPACES_MOUNT_NAMESPACE_H_

#include "brillo/namespaces/platform.h"

#include <base/files/file_path.h>
#include <brillo/brillo_export.h>

namespace brillo {

class BRILLO_EXPORT MountNamespaceInterface {
  // An interface declaring the basic functionality of a mount namespace bound
  // to a specific path. This basic functionality consists of reporting the
  // namespace path.
 public:
  virtual ~MountNamespaceInterface() = default;

  virtual const base::FilePath& path() const = 0;
};

class BRILLO_EXPORT UnownedMountNamespace : public MountNamespaceInterface {
  // A class to store and retrieve the path of a persistent namespace. This
  // class doesn't create nor destroy the namespace.
 public:
  explicit UnownedMountNamespace(const base::FilePath& ns_path)
      : ns_path_(ns_path) {}
  UnownedMountNamespace(const UnownedMountNamespace&) = delete;
  UnownedMountNamespace& operator=(const UnownedMountNamespace&) = delete;

  ~UnownedMountNamespace() override;

  const base::FilePath& path() const override { return ns_path_; }

 private:
  base::FilePath ns_path_;
};

class BRILLO_EXPORT MountNamespace : public MountNamespaceInterface {
  // A class to create a persistent mount namespace bound to a specific path.
  // A new mount namespace is unshared from the mount namespace of the calling
  // process when Create() is called; the namespace of the calling process
  // remains unchanged. Recurring creation on a path is not allowed.
  //
  // Given that we cannot ensure that creation always succeeds this class is not
  // fully RAII, but once the namespace is created (with Create()), it will be
  // destroyed when the object goes out of scope.
 public:
  MountNamespace(const base::FilePath& ns_path, Platform* platform);
  MountNamespace(const MountNamespace&) = delete;
  MountNamespace& operator=(const MountNamespace&) = delete;

  ~MountNamespace() override;

  bool Create();
  bool Destroy();
  const base::FilePath& path() const override { return ns_path_; }

 private:
  base::FilePath ns_path_;
  Platform* platform_;
  bool exists_;
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_NAMESPACES_MOUNT_NAMESPACE_H_
