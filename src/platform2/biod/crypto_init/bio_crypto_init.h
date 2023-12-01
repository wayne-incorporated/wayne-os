// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_CRYPTO_INIT_BIO_CRYPTO_INIT_H_
#define BIOD_CRYPTO_INIT_BIO_CRYPTO_INIT_H_

#include <memory>
#include <optional>
#include <utility>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <brillo/secure_blob.h>
#include <chromeos/ec/ec_commands.h>
#include <libec/ec_command_factory.h>

namespace biod {

class BioCryptoInit {
 public:
  explicit BioCryptoInit(
      std::unique_ptr<ec::EcCommandFactoryInterface> ec_command_factory)
      : ec_command_factory_(std::move(ec_command_factory)) {}
  virtual ~BioCryptoInit() = default;

  virtual bool DoProgramSeed(const brillo::SecureVector& tpm_seed);
  virtual bool NukeFile(const base::FilePath& filepath);
  virtual bool CrosFpTemplateVersionCompatible(
      const uint32_t firmware_fp_template_format_version,
      const uint32_t biod_fp_template_format_version);

 protected:
  virtual bool InitCrosFp();
  virtual std::optional<uint32_t> GetFirmwareTemplateVersion();
  virtual bool WriteSeedToCrosFp(const brillo::SecureVector& seed);
  virtual base::ScopedFD OpenCrosFpDevice();
  virtual bool WaitOnEcBoot(const base::ScopedFD& cros_fp_fd,
                            ec_image expected_image);

 private:
  std::unique_ptr<ec::EcCommandFactoryInterface> ec_command_factory_;
  base::ScopedFD cros_fp_fd_;
};

}  // namespace biod

#endif  // BIOD_CRYPTO_INIT_BIO_CRYPTO_INIT_H_
