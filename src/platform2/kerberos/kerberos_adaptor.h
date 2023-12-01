// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef KERBEROS_KERBEROS_ADAPTOR_H_
#define KERBEROS_KERBEROS_ADAPTOR_H_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/memory/weak_ptr.h>
#include <brillo/dbus/async_event_sequencer.h>

#include "kerberos/org.chromium.Kerberos.h"
#include "kerberos/proto_bindings/kerberos_service.pb.h"

namespace brillo {
namespace dbus_utils {
class DBusObject;
}
}  // namespace brillo

namespace kerberos {

class AccountManager;
class KerberosMetrics;
class Krb5Interface;

// Implementation of the Kerberos D-Bus interface.
class KerberosAdaptor : public org::chromium::KerberosAdaptor,
                        public org::chromium::KerberosInterface {
 public:
  explicit KerberosAdaptor(
      std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object);
  KerberosAdaptor(const KerberosAdaptor&) = delete;
  KerberosAdaptor& operator=(const KerberosAdaptor&) = delete;

  ~KerberosAdaptor();

  // Registers the D-Bus object and interfaces.
  void RegisterAsync(brillo::dbus_utils::AsyncEventSequencer::CompletionAction
                         completion_callback);

  using ByteArray = std::vector<uint8_t>;

  // org::chromium::KerberosInterface: (see org.chromium.Kerberos.xml).
  ByteArray AddAccount(const ByteArray& request_blob) override;
  ByteArray ListAccounts(const ByteArray& request_blob) override;
  ByteArray RemoveAccount(const ByteArray& request_blob) override;
  ByteArray ClearAccounts(const ByteArray& request_blob) override;
  ByteArray SetConfig(const ByteArray& request_blob) override;
  ByteArray ValidateConfig(const ByteArray& request_blob) override;
  ByteArray AcquireKerberosTgt(const ByteArray& request_blob,
                               const base::ScopedFD& password_fd) override;
  ByteArray GetKerberosFiles(const ByteArray& request_blob) override;

  AccountManager* GetAccountManagerForTesting() { return manager_.get(); }

  // Overrides the directory where data is stored.
  // Must be called before RegisterAsync().
  void set_storage_dir_for_testing(const base::FilePath& dir);

  // Overrides the Krb5Interface instance passed to |manager_|.
  // Must be called before RegisterAsync().
  void set_krb5_for_testing(std::unique_ptr<Krb5Interface> krb5);

  // Overrides the KerberosMetrics instance passed to |manager_|.
  // Must be called before RegisterAsync().
  void set_metrics_for_testing(std::unique_ptr<KerberosMetrics> metrics);

 private:
  using RepeatedAccountField = google::protobuf::RepeatedPtrField<Account>;

  // Calls |manager_|->StartObservingTickets().
  void StartObservingTickets();

  // Gets triggered by when the Kerberos credential cache or the configuration
  // file changes of the given principal. Triggers the KerberosFilesChanged
  // signal.
  void OnKerberosFilesChanged(const std::string& principal_name);

  // Gets called when a Kerberos ticket is about to expire in the next couple of
  // minutes or if it already expired. Triggers the KerberosTicketExpiring
  // signal.
  void OnKerberosTicketExpiring(const std::string& principal_name);

  // Populates the proto repeated field with the list of all existing accounts.
  // This list is retrieved from |manager_->ListAccounts()|.
  void GetAccountsList(RepeatedAccountField* repeated_accounts);

  std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object_;

  // For collecting UMA stats.
  // Must be before |manager_| since that keeps a pointer to |metrics_|.
  std::unique_ptr<KerberosMetrics> metrics_;

  // Manages Kerberos accounts and tickets.
  std::unique_ptr<AccountManager> manager_;

  // If set, overrides the directory where data is stored.
  std::optional<base::FilePath> storage_dir_for_testing_;

  // If set, overrides the Krb5Interface instance passed to |manager_|.
  std::unique_ptr<Krb5Interface> krb5_for_testing_;

  base::WeakPtrFactory<KerberosAdaptor> weak_ptr_factory_{this};
};

}  // namespace kerberos

#endif  // KERBEROS_KERBEROS_ADAPTOR_H_
