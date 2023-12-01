// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FACTORY_FACTORY_H_
#define LIBHWSEC_FACTORY_FACTORY_H_

#include <memory>
#include <utility>

#include "libhwsec/frontend/attestation/frontend.h"
#include "libhwsec/frontend/bootlockbox/frontend.h"
#include "libhwsec/frontend/chaps/frontend.h"
#include "libhwsec/frontend/client/frontend.h"
#include "libhwsec/frontend/cryptohome/frontend.h"
#include "libhwsec/frontend/local_data_migration/frontend.h"
#include "libhwsec/frontend/oobe_config/frontend.h"
#include "libhwsec/frontend/optee-plugin/frontend.h"
#include "libhwsec/frontend/pinweaver/frontend.h"
#include "libhwsec/frontend/recovery_crypto/frontend.h"
#include "libhwsec/frontend/u2fd/frontend.h"
#include "libhwsec/frontend/u2fd/vendor_frontend.h"
#include "libhwsec/hwsec_export.h"

// Factory holds the ownership of the middleware and backend.
// And generates different frontend for different usage.

namespace hwsec {

class Factory {
 public:
  virtual ~Factory() = default;
  virtual std::unique_ptr<CryptohomeFrontend> GetCryptohomeFrontend() = 0;
  virtual std::unique_ptr<PinWeaverFrontend> GetPinWeaverFrontend() = 0;
  virtual std::unique_ptr<RecoveryCryptoFrontend>
  GetRecoveryCryptoFrontend() = 0;
  virtual std::unique_ptr<ClientFrontend> GetClientFrontend() = 0;
  virtual std::unique_ptr<ChapsFrontend> GetChapsFrontend() = 0;
  virtual std::unique_ptr<U2fFrontend> GetU2fFrontend() = 0;
  virtual std::unique_ptr<U2fVendorFrontend> GetU2fVendorFrontend() = 0;
  virtual std::unique_ptr<OpteePluginFrontend> GetOpteePluginFrontend() = 0;
  virtual std::unique_ptr<BootLockboxFrontend> GetBootLockboxFrontend() = 0;
  virtual std::unique_ptr<OobeConfigFrontend> GetOobeConfigFrontend() = 0;
  virtual std::unique_ptr<LocalDataMigrationFrontend>
  GetLocalDataMigrationFrontend() = 0;
  virtual std::unique_ptr<AttestationFrontend> GetAttestationFrontend() = 0;
};

}  // namespace hwsec

#endif  // LIBHWSEC_FACTORY_FACTORY_H_
