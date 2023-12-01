// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SYSTEM_PROXY_KERBEROS_CLIENT_H_
#define SYSTEM_PROXY_KERBEROS_CLIENT_H_

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <dbus/bus.h>
#include <dbus/object_proxy.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

namespace system_proxy {

// KerberosClient manages a Kerberos users' kr5conf and krb5ccache files,
// keeping a copy under /tmp/krb5.conf and /tmp/ccache. The files are kept in
// sync by connecting to the Kerberos dbus signal |KerberosFileChanged|.
class KerberosClient {
 public:
  explicit KerberosClient(scoped_refptr<dbus::Bus> bus);

  KerberosClient(const KerberosClient&) = delete;
  KerberosClient& operator=(const KerberosClient&) = delete;
  virtual ~KerberosClient() = default;

  // Sets the principal name and requests the kerberos files from kerberosd.
  void SetPrincipalName(const std::string& principal_name);

  // If Kerberos is disabled, it will delete the kerberos files.
  void SetKerberosEnabled(bool enabled);

  // Location of the kerberos credentials (ticket) cache.
  std::string krb5_ccache_path();
  // Location of the kerberos configuration file.
  std::string krb5_conf_path();

 protected:
  // Requests the files from kerberosd via the dbus method
  // |GetUserKerberosFiles|.
  virtual void GetFiles();

  // Response handler for |GetUserKerberosFiles|.
  void OnGetFilesResponse(dbus::Response* response);

 private:
  friend class KerberosClientTest;
  friend class SystemProxyAdaptorTest;
  FRIEND_TEST(KerberosClientTest, KerberosEnabled);
  FRIEND_TEST(KerberosClientTest, SignalHandling);
  FRIEND_TEST(SystemProxyAdaptorTest, KerberosEnabled);

  // Writes |krb5_ccache_data| and |krb5_conf_data| to |krb5_ccache_path_| and
  // |krb5_conf_path_| respectively.
  void WriteFiles(const std::string& krb5_ccache_data,
                  const std::string& krb5_conf_data);

  // Writes |kerberos_file| to |path|.
  bool WriteFile(const base::FilePath& path, const std::string& kerberos_file);

  void DeleteFiles();

  void ConnectToKerberosFilesChangedSignal();

  // Callback for 'KerberosFilesChanged' dbus signal.
  void OnKerberosFilesChanged(dbus::Signal* signal);

  // Called after connecting to 'KerberosFilesChanged' signal. Verifies
  // that the signal connected successfully.
  void OnKerberosFilesChangedSignalConnected(const std::string& interface_name,
                                             const std::string& signal_name,
                                             bool success);
  void OnKerberosServiceAvailable(bool is_available);

  std::string UpdateKrbConfig(const std::string& config_content);

  base::FilePath krb5_conf_path_;
  base::FilePath krb5_ccache_path_;
  // Principal name in the format user@REALM.COM.
  std::string principal_name_;
  bool kerberos_enabled_;
  dbus::ObjectProxy* const kerberos_object_proxy_;
  base::WeakPtrFactory<KerberosClient> weak_ptr_factory_{this};
};

}  // namespace system_proxy

#endif  // SYSTEM_PROXY_KERBEROS_CLIENT_H_
