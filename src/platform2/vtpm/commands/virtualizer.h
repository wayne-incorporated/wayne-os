// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VTPM_COMMANDS_VIRTUALIZER_H_
#define VTPM_COMMANDS_VIRTUALIZER_H_

#include "vtpm/commands/command.h"

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <attestation/proto_bindings/attestation_ca.pb.h>
#include <attestation/proto_bindings/interface.pb.h>
#include <base/functional/callback.h>
#include <brillo/dbus/dbus_connection.h>
#include <brillo/errors/error.h>
#include <trunks/command_parser.h>
#include <trunks/real_command_parser.h>
#include <trunks/real_response_serializer.h>
#include <trunks/response_serializer.h>
#include <trunks/tpm_generated.h>
#include <trunks/trunks_factory_impl.h>

// Requires proto_bindings `attestation`.
#include <attestation-client/attestation/dbus-proxies.h>

#include "vtpm/backends/attested_virtual_endorsement.h"
#include "vtpm/backends/cacheable_blob.h"
#include "vtpm/backends/disk_cache_blob.h"
#include "vtpm/backends/endorsement_password_changer.h"
#include "vtpm/backends/real_static_analyzer.h"
#include "vtpm/backends/real_tpm_handle_manager.h"
#include "vtpm/backends/real_tpm_property_manager.h"
#include "vtpm/backends/vek.h"
#include "vtpm/backends/vek_cert.h"
#include "vtpm/backends/vek_cert_manager.h"
#include "vtpm/backends/vsrk.h"
#include "vtpm/commands/direct_forward_command.h"
#include "vtpm/commands/self_test_command.h"

namespace vtpm {

// `Virtualizer` implements the very top level of the TPM commands execution. it
// is designed to be configurable, and determines how to execute an incoming TPM
// command request with minimalist TPM-specifics. All the definition of the way
// a virtualized TPM works is abstracted into the implementation of those
// delegated objects.
class Virtualizer : public Command {
 public:
  enum Profile {
    kGLinux,
  };
  static std::unique_ptr<Virtualizer> Create(Profile profile);
  Virtualizer(trunks::CommandParser* parser,
              trunks::ResponseSerializer* serializer,
              std::unordered_map<trunks::TPM_CC, Command*> table,
              Command* fallback_command);
  void Run(const std::string& command,
           CommandResponseCallback callback) override;

 private:
  Virtualizer() = default;

  // Adds support for `cc` with `command` as the handler.
  void AddCommandSupport(trunks::TPM_CC cc, Command* command);

  // Functional object candidates for all profiles.
  RealTpmPropertyManager real_tpm_property_manager_;
  trunks::RealResponseSerializer real_response_serializer_;
  trunks::RealCommandParser real_command_parser_;
  RealStaticAnalyzer real_static_analyzer_;
  SelfTestCommand self_test_command_{&real_response_serializer_};
  brillo::DBusConnection system_bus_connection_;
  std::unique_ptr<org::chromium::AttestationProxy> attestation_proxy_;
  std::unique_ptr<AttestedVirtualEndorsement> attested_virtual_endorsement_;
  std::unique_ptr<EndorsementPasswordChanger> endorsement_password_changer_;

  // NOTE: This factory might be limited to used on the `Create()`-calling
  // thread.
  trunks::TrunksFactoryImpl trunks_factory_;
  Vsrk vsrk_{&trunks_factory_};
  std::unique_ptr<Vek> vek_;
  std::unique_ptr<VekCert> vek_cert_;
  DirectForwardCommand direct_forwarder_{&trunks_factory_};

  // Functional object candidates dynamically determined by profile.
  std::unique_ptr<DiskCacheBlob> vsrk_cache_;
  std::unique_ptr<DiskCacheBlob> vek_cache_;
  std::unique_ptr<DiskCacheBlob> vek_cert_cache_;
  std::unique_ptr<CacheableBlob> cacheable_vsrk_;
  std::unique_ptr<CacheableBlob> cacheable_vek_;
  std::unique_ptr<CacheableBlob> cacheable_vek_cert_;
  std::unique_ptr<VekCertManager> vek_cert_manager_;
  std::unique_ptr<RealTpmHandleManager> real_tpm_handle_manager_;

  std::vector<std::unique_ptr<Command>> commands_;

  // Functional objects used to execute the vtpm functions. The ownership of
  // the pointees of these are owned the Virtualizer w/ the fields above
  trunks::CommandParser* command_parser_ = nullptr;
  trunks::ResponseSerializer* response_serializer_ = nullptr;
  // The command table of which entries are the objects `this` delegates a TPM
  // command to.
  std::unordered_map<trunks::TPM_CC, Command*> command_table_;
  // The command object that handles TPM commands that are not supported by
  // `this`.
  Command* fallback_command_ = nullptr;
};

}  // namespace vtpm

#endif  // VTPM_COMMANDS_VIRTUALIZER_H_
