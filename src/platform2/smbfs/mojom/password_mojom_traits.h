// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBFS_MOJOM_PASSWORD_MOJOM_TRAITS_H_
#define SMBFS_MOJOM_PASSWORD_MOJOM_TRAITS_H_

#include <memory>
#include <utility>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/numerics/safe_conversions.h>
#include <libpasswordprovider/password.h>
#include <mojo/public/cpp/system/platform_handle.h>

#include "smbfs/mojom/smbfs.mojom.h"

namespace mojo {

template <>
struct StructTraits<smbfs::mojom::PasswordDataView,
                    std::unique_ptr<password_provider::Password>> {
  static mojo::ScopedHandle fd(
      const std::unique_ptr<password_provider::Password>& password) {
    int fds[2];
    CHECK(base::CreateLocalNonBlockingPipe(fds));
    base::ScopedFD read_fd(fds[0]);
    base::ScopedFD write_fd(fds[1]);
    CHECK(base::WriteFileDescriptor(write_fd.get(), password->GetRaw()));
    return mojo::WrapPlatformHandle(mojo::PlatformHandle(std::move(read_fd)));
  }

  static int32_t length(
      const std::unique_ptr<password_provider::Password>& password) {
    return base::checked_cast<int32_t>(password->size());
  }

  static bool Read(smbfs::mojom::PasswordDataView data,
                   std::unique_ptr<password_provider::Password>* password) {
    if (data.length() > smbfs::mojom::Password::kMaxLength) {
      return false;
    }

    base::ScopedFD fd = mojo::UnwrapPlatformHandle(data.TakeFd()).TakeFD();
    *password = password_provider::Password::CreateFromFileDescriptor(
        fd.get(), data.length());
    return true;
  }
};

}  // namespace mojo

#endif  // SMBFS_MOJOM_PASSWORD_MOJOM_TRAITS_H_
