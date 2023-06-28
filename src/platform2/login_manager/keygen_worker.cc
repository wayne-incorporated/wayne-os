// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/keygen_worker.h"

#include <sys/types.h>
#include <unistd.h>

#include <memory>
#include <set>
#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/optional.h>
#include <crypto/rsa_private_key.h>
#include <crypto/scoped_nss_types.h>

#include "login_manager/nss_util.h"
#include "login_manager/policy_key.h"
#include "login_manager/system_utils.h"

namespace login_manager {

namespace keygen {

int GenerateKey(const base::FilePath& file_path,
                const base::FilePath& user_homedir,
                NssUtil* nss) {
  PolicyKey key(file_path, nss);
  if (!key.PopulateFromDiskIfPossible())
    LOG(FATAL) << "Corrupted key on disk at " << file_path.value();
  if (key.IsPopulated())
    LOG(FATAL) << "Existing owner key at " << file_path.value();
  base::FilePath nssdb = user_homedir.Append(nss->GetNssdbSubpath());
  PLOG_IF(FATAL, !base::PathExists(nssdb))
      << nssdb.value() << " does not exist!";
  if (!base::VerifyPathControlledByUser(file_path.DirName(), nssdb, getuid(),
                                        std::set<gid_t>())) {
    PLOG(FATAL) << nssdb.value() << " cannot be used by the user!";
  }
  // This program will be executed in the correct mount namespace so
  // |ns_mnt_path| can be nullopt.
  ScopedPK11SlotDescriptor desc(nss->OpenUserDB(user_homedir, base::nullopt));
  PLOG_IF(FATAL, !desc) << "Could not open/create user NSS DB at "
                        << nssdb.value();
  LOG(INFO) << "Generating Owner key.";

  std::unique_ptr<crypto::RSAPrivateKey> pair(
      nss->GenerateKeyPairForUser(desc.get()));
  if (pair.get()) {
    if (!key.PopulateFromKeypair(pair.get()))
      LOG(FATAL) << "Could not use generated keypair.";
    LOG(INFO) << "Writing Owner key to " << file_path.value();
    return (key.Persist() ? 0 : 1);
  }
  LOG(FATAL) << "Could not generate owner key!";
  return 0;
}

}  // namespace keygen

}  // namespace login_manager
