// Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_KEY_GENERATOR_H_
#define LOGIN_MANAGER_KEY_GENERATOR_H_

#include <signal.h>
#include <sys/types.h>

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <base/macros.h>
#include <base/optional.h>
#include <base/time/time.h>

#include "login_manager/child_exit_handler.h"
#include "login_manager/generator_job.h"

namespace login_manager {

class SystemUtils;

class KeyGenerator : public ChildExitHandler {
 public:
  class Delegate {
   public:
    virtual ~Delegate();
    virtual void OnKeyGenerated(const std::string& username,
                                const base::FilePath& temp_key_file) = 0;
  };

  KeyGenerator(uid_t uid, SystemUtils* utils);
  KeyGenerator(const KeyGenerator&) = delete;
  KeyGenerator& operator=(const KeyGenerator&) = delete;

  ~KeyGenerator() override;

  void set_delegate(Delegate* delegate) { delegate_ = delegate; }

  // Start the generation of a new Owner keypair for |username| as |uid|.
  // |username|'s data directory will optionally exist in the mount namespace
  // identified by |ns_path|.
  // Upon success, hands off ownership of the key generation job to |manager_|
  // and returns true.
  // The username of the key owner and temporary storage location of the
  // generated public key are stored internally until Reset() is called.
  virtual bool Start(const std::string& username,
                     const base::Optional<base::FilePath>& ns_path);

  // Ask the managed job to exit. |reason| is a human-readable string that may
  // be logged to describe the reason for the request.
  void RequestJobExit(const std::string& reason);

  // The job must be destroyed within the timeout.
  void EnsureJobExit(base::TimeDelta timeout);

  // ChildExitHandler overrides.
  bool HandleExit(const siginfo_t& status) override;

  void InjectJobFactory(std::unique_ptr<GeneratorJobFactoryInterface> factory);

 private:
  static const char kTemporaryKeyFilename[];

  // Clear per-generation state.
  void Reset();

  uid_t uid_;
  SystemUtils* utils_;
  Delegate* delegate_ = nullptr;

  std::unique_ptr<GeneratorJobFactoryInterface> factory_;
  std::unique_ptr<GeneratorJobInterface> keygen_job_;
  bool generating_ = false;
  std::string key_owner_username_;
  std::string temporary_key_filename_;
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_KEY_GENERATOR_H_
