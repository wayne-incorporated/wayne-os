// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_PROXY_TPM2_SIMULATOR_PROXY_FOR_TEST_H_
#define LIBHWSEC_PROXY_TPM2_SIMULATOR_PROXY_FOR_TEST_H_

#include <memory>
#include <string>

#include <base/files/scoped_temp_dir.h>
#include <libcrossystem/crossystem.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>
#include <tpm_manager-client-test/tpm_manager/dbus-proxy-mocks.h>
#include <trunks/command_transceiver.h>
#include <trunks/resource_manager.h>
#include <trunks/tpm_generated.h>
#include <trunks/tpm_simulator_handle.h>
#include <trunks/trunks_factory_impl.h>

#include "libhwsec/proxy/proxy.h"
#include "libhwsec/test_utils/fake_tpm_nvram_for_test.h"

namespace hwsec {

// A TPM2 simulator proxy implementation for testing.

class Tpm2SimulatorProxyForTest : public Proxy {
 public:
  Tpm2SimulatorProxyForTest();
  ~Tpm2SimulatorProxyForTest() override;

  // Initialize the proxy data. Returns true on success.
  bool Init();

  // Extend the PCR value for the different use case. (e.g. boot mode.)
  bool ExtendPCR(uint32_t index, const std::string& data);

  FakeTpmNvramForTest& GetFakeTpmNvramForTest() { return tpm_nvram_; }

 private:
  base::ScopedTempDir tmp_tpm_dir_;
  std::unique_ptr<trunks::CommandTransceiver> low_level_transceiver_;
  std::unique_ptr<trunks::TrunksFactoryImpl> low_level_factory_;
  std::unique_ptr<trunks::ResourceManager> resource_manager_;
  std::unique_ptr<trunks::TrunksFactoryImpl> trunks_factory_;
  testing::NiceMock<org::chromium::TpmManagerProxyMock> tpm_manager_;
  FakeTpmNvramForTest tpm_nvram_;
  std::unique_ptr<crossystem::Crossystem> crossystem_;
  bool initialized_ = false;
};

}  // namespace hwsec

#endif  // LIBHWSEC_PROXY_TPM2_SIMULATOR_PROXY_FOR_TEST_H_
