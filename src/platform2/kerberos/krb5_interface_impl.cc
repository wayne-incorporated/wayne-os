// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "kerberos/krb5_interface_impl.h"

#include <algorithm>
#include <utility>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <krb5.h>
#include <profile.h>

#include "kerberos/error_strings.h"

namespace kerberos {

namespace {

// Environment variable for the Kerberos configuration (krb5.conf).
constexpr char kKrb5ConfigEnvVar[] = "KRB5_CONFIG";

// Wrapper classes for safe construction and destruction.
struct ScopedKrb5Context {
  ScopedKrb5Context() = default;
  ~ScopedKrb5Context() {
    if (ctx) {
      krb5_free_context(ctx);
      ctx = nullptr;
    }
  }

  // Converts the krb5 |code| to a human readable error message.
  std::string GetErrorMessage(errcode_t code) {
    // Fallback if error happens during ctx initialization (e.g. bad config).
    if (!ctx)
      return base::StringPrintf("Error %ld", code);

    const char* emsg = krb5_get_error_message(ctx, code);
    std::string msg = base::StringPrintf("%s (%ld)", emsg, code);
    krb5_free_error_message(ctx, emsg);
    return msg;
  }

  krb5_context get() const { return ctx; }
  krb5_context* get_mutable_ptr() { return &ctx; }

 private:
  krb5_context ctx = nullptr;
};

struct ScopedKrb5CCache {
  // Prefer the constructor taking a context if possible.
  ScopedKrb5CCache() {}
  explicit ScopedKrb5CCache(krb5_context _ctx) { set_ctx(_ctx); }

  ~ScopedKrb5CCache() {
    if (ccache) {
      DCHECK(ctx);
      krb5_cc_close(ctx, ccache);
      ccache = nullptr;
    }
  }

  // The context must be set if |ccache| is set (though get_mutable_ptr())
  // before this object is destroyed.
  void set_ctx(krb5_context _ctx) {
    ctx = _ctx;
    DCHECK(ctx);
  }

  krb5_ccache get() const { return ccache; }
  krb5_ccache* get_mutable_ptr() { return &ccache; }

 private:
  // Pointer to parent data, not owned.
  krb5_context ctx = nullptr;
  krb5_ccache ccache = nullptr;
};

// Maps some common krb5 error codes to our internal codes. If something is not
// reported properly, add more cases here.
ErrorType TranslateErrorCode(errcode_t code) {
  switch (code) {
    case KRB5KDC_ERR_NONE:
      return ERROR_NONE;

    case KRB5_KDC_UNREACH:
      return ERROR_NETWORK_PROBLEM;

    case KRB5_CONFIG_BADFORMAT:
    case PROF_BAD_BOOLEAN:
    case PROF_BAD_INTEGER:
      return ERROR_BAD_CONFIG;

    case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
      return ERROR_BAD_PRINCIPAL;

    case KRB5KRB_AP_ERR_BAD_INTEGRITY:
    case KRB5KDC_ERR_PREAUTH_FAILED:
      return ERROR_BAD_PASSWORD;

    case KRB5KDC_ERR_KEY_EXP:
      return ERROR_PASSWORD_EXPIRED;

    // TODO(b/259178385): Verify this mapping.
    case KRB5_KPASSWD_SOFTERROR:
      return ERROR_PASSWORD_REJECTED;

    // TODO(b/259178385): Verify this mapping.
    case KRB5_FCC_NOFILE:
      return ERROR_NO_CREDENTIALS_CACHE_FOUND;

    // TODO(b/259178385): Verify this mapping.
    case KRB5KRB_AP_ERR_TKT_EXPIRED:
      return ERROR_KERBEROS_TICKET_EXPIRED;

    case KRB5KDC_ERR_ETYPE_NOSUPP:
      return ERROR_KDC_DOES_NOT_SUPPORT_ENCRYPTION_TYPE;

    case KRB5_REALM_UNKNOWN:
    case KRB5KDC_ERR_WRONG_REALM:
      return ERROR_CONTACTING_KDC_FAILED;

    default:
      return ERROR_UNKNOWN_KRB5_ERROR;
  }
}

// Returns true if the string contained in |data| matches |str_to_match|.
bool DataMatches(const krb5_data& data, const char* str_to_match) {
  // It is not clear whether data.data is null terminated, so a strcmp might
  // not work.
  return strlen(str_to_match) == data.length &&
         memcmp(str_to_match, data.data, data.length) == 0;
}

// Returns true if |creds| has a server that starts with "krbtgt".
bool IsTgt(const krb5_creds& creds) {
  return creds.server && creds.server->length > 0 &&
         DataMatches(creds.server->data[0], "krbtgt");
}

enum class Action { AcquireTgt, RenewTgt };

struct Options {
  std::string principal_name;
  std::string password;
  std::string krb5cc_path;
  std::string config_path;
  Action action = Action::AcquireTgt;
};

// Encapsulates krb5 context data required for kinit.
class KinitContext {
 public:
  explicit KinitContext(Options options) : options_(std::move(options)) {
    memset(&k5_, 0, sizeof(k5_));
  }

  // Runs kinit with the options passed to the constructor. Only call once per
  // context. While in principle it should be fine to run multiple times, the
  // code path probably hasn't been tested (kinit does not call this multiple
  // times).
  ErrorType Run() {
    DCHECK(!did_run_);
    did_run_ = true;

    ErrorType error = Initialize();
    if (error == ERROR_NONE)
      error = RunKinit();
    Finalize();
    return error;
  }

 private:
  // The following code has been adapted from kinit.c in the mit-krb5 code base.
  // It has been formatted to fit this screen.

  struct Krb5Data {
    krb5_principal me;
    char* name;
  };

  // Wrapper around krb5 data to get rid of the gotos in the original code.
  struct KInitData {
    // Pointer to parent data, not owned.
    const krb5_context ctx = nullptr;
    // Pointer to parent data, not owned.
    const Krb5Data* k5 = nullptr;
    krb5_creds my_creds;
    krb5_get_init_creds_opt* options = nullptr;

    // The lifetime of the |k5| pointer must exceed the lifetime of this object.
    explicit KInitData(const krb5_context ctx, const Krb5Data* k5)
        : ctx(ctx), k5(k5) {
      memset(&my_creds, 0, sizeof(my_creds));
    }

    ~KInitData() {
      if (options)
        krb5_get_init_creds_opt_free(ctx, options);
      if (my_creds.client == k5->me)
        my_creds.client = nullptr;
      krb5_free_cred_contents(ctx, &my_creds);
    }
  };

  // Initializes krb5 data.
  ErrorType Initialize() {
    krb5_error_code ret = krb5_init_context(ctx.get_mutable_ptr());
    if (ret) {
      LOG(ERROR) << ctx.GetErrorMessage(ret) << " while initializing context";
      return TranslateErrorCode(ret);
    }

    out_cc.set_ctx(ctx.get());
    ret = krb5_cc_resolve(ctx.get(), options_.krb5cc_path.c_str(),
                          out_cc.get_mutable_ptr());
    if (ret) {
      LOG(ERROR) << ctx.GetErrorMessage(ret) << " resolving ccache";
      return TranslateErrorCode(ret);
    }

    ret = krb5_parse_name_flags(ctx.get(), options_.principal_name.c_str(),
                                0 /* flags */, &k5_.me);
    if (ret) {
      LOG(ERROR) << ctx.GetErrorMessage(ret) << " when parsing name";
      return TranslateErrorCode(ret);
    }

    ret = krb5_unparse_name(ctx.get(), k5_.me, &k5_.name);
    if (ret) {
      LOG(ERROR) << ctx.GetErrorMessage(ret) << " when unparsing name";
      return TranslateErrorCode(ret);
    }

    options_.principal_name = k5_.name;
    return ERROR_NONE;
  }

  // Finalizes krb5 data.
  void Finalize() {
    krb5_free_unparsed_name(ctx.get(), k5_.name);
    krb5_free_principal(ctx.get(), k5_.me);
    memset(&k5_, 0, sizeof(k5_));
  }

  // Runs the actual kinit code and acquires/renews tickets.
  ErrorType RunKinit() {
    krb5_error_code ret;
    KInitData d(ctx.get(), &k5_);

    ret = krb5_get_init_creds_opt_alloc(ctx.get(), &d.options);
    if (ret) {
      LOG(ERROR) << ctx.GetErrorMessage(ret) << " while getting options";
      return TranslateErrorCode(ret);
    }

    ret = krb5_get_init_creds_opt_set_out_ccache(ctx.get(), d.options,
                                                 out_cc.get());
    if (ret) {
      LOG(ERROR) << ctx.GetErrorMessage(ret) << " while getting options";
      return TranslateErrorCode(ret);
    }

    // To get notified of expiry, see
    // krb5_get_init_creds_opt_set_expire_callback

    switch (options_.action) {
      case Action::AcquireTgt:
        ret = krb5_get_init_creds_password(
            ctx.get(), &d.my_creds, k5_.me, options_.password.c_str(),
            nullptr /* prompter */, nullptr /* data */, 0 /* start_time */,
            nullptr /* in_tkt_service */, d.options);
        break;
      case Action::RenewTgt:
        ret =
            krb5_get_renewed_creds(ctx.get(), &d.my_creds, k5_.me, out_cc.get(),
                                   nullptr /* options_.in_tkt_service */);
        break;
    }

    if (ret) {
      LOG(ERROR) << ctx.GetErrorMessage(ret);
      return TranslateErrorCode(ret);
    }

    if (options_.action != Action::AcquireTgt) {
      ret = krb5_cc_initialize(ctx.get(), out_cc.get(), k5_.me);
      if (ret) {
        LOG(ERROR) << ctx.GetErrorMessage(ret) << " when initializing cache";
        return TranslateErrorCode(ret);
      }

      ret = krb5_cc_store_cred(ctx.get(), out_cc.get(), &d.my_creds);
      if (ret) {
        LOG(ERROR) << ctx.GetErrorMessage(ret) << " while storing credentials";
        return TranslateErrorCode(ret);
      }
    }

    return ERROR_NONE;
  }

  ScopedKrb5Context ctx;
  ScopedKrb5CCache out_cc;
  Krb5Data k5_;
  Options options_;
  bool did_run_ = false;
};

// Runs the Kerberos configuration |krb5conf| through the krb5 code to see if it
// can be parsed.
ErrorType ValidateConfigViaKrb5(const std::string& krb5conf) {
  // Since krb5 doesn't accept config passed as string, write it to disk.
  base::FilePath krb5conf_path;
  if (!base::CreateTemporaryFile(&krb5conf_path)) {
    LOG(ERROR) << "Failed to create temp file for validating config";
    return ERROR_LOCAL_IO;
  }

  const int size = static_cast<int>(krb5conf.size());
  if (base::WriteFile(krb5conf_path, krb5conf.data(), size) != size) {
    LOG(ERROR) << "Failed to write config to disk at " << krb5conf_path.value()
               << " for validating config";
    return ERROR_LOCAL_IO;
  }

  // krb5_init_context parses the config file.
  setenv(kKrb5ConfigEnvVar, krb5conf_path.value().c_str(), 1);
  ScopedKrb5Context ctx;
  krb5_error_code ret = krb5_init_context(ctx.get_mutable_ptr());
  unsetenv(kKrb5ConfigEnvVar);
  base::DeleteFile(krb5conf_path);

  if (ret) {
    LOG(ERROR) << ctx.GetErrorMessage(ret) << " while initializing context";
    return TranslateErrorCode(ret);
  }

  return ERROR_NONE;
}

}  // namespace

Krb5InterfaceImpl::Krb5InterfaceImpl() = default;

Krb5InterfaceImpl::~Krb5InterfaceImpl() = default;

ErrorType Krb5InterfaceImpl::AcquireTgt(const std::string& principal_name,
                                        const std::string& password,
                                        const base::FilePath& krb5cc_path,
                                        const base::FilePath& krb5conf_path) {
  Options options;
  options.action = Action::AcquireTgt;
  options.principal_name = principal_name;
  options.password = password;
  options.krb5cc_path = krb5cc_path.value();
  setenv(kKrb5ConfigEnvVar, krb5conf_path.value().c_str(), 1);
  ErrorType error = KinitContext(std::move(options)).Run();
  unsetenv(kKrb5ConfigEnvVar);
  return error;
}

ErrorType Krb5InterfaceImpl::RenewTgt(const std::string& principal_name,
                                      const base::FilePath& krb5cc_path,
                                      const base::FilePath& krb5conf_path) {
  Options options;
  options.action = Action::RenewTgt;
  options.principal_name = principal_name;
  options.krb5cc_path = krb5cc_path.value();
  setenv(kKrb5ConfigEnvVar, krb5conf_path.value().c_str(), 1);
  ErrorType error = KinitContext(std::move(options)).Run();
  unsetenv(kKrb5ConfigEnvVar);
  return error;
}

ErrorType Krb5InterfaceImpl::GetTgtStatus(const base::FilePath& krb5cc_path,
                                          TgtStatus* status) {
  DCHECK(status);

  ScopedKrb5Context ctx;
  krb5_error_code ret = krb5_init_context(ctx.get_mutable_ptr());
  if (ret) {
    LOG(ERROR) << ctx.GetErrorMessage(ret) << " while initializing context";
    return TranslateErrorCode(ret);
  }

  ScopedKrb5CCache ccache(ctx.get());
  std::string prefixed_krb5cc_path = "FILE:" + krb5cc_path.value();
  ret = krb5_cc_resolve(ctx.get(), prefixed_krb5cc_path.c_str(),
                        ccache.get_mutable_ptr());
  if (ret) {
    LOG(ERROR) << ctx.GetErrorMessage(ret) << " while resolving cache";
    return TranslateErrorCode(ret);
  }

  krb5_cc_cursor cur;
  ret = krb5_cc_start_seq_get(ctx.get(), ccache.get(), &cur);
  if (ret) {
    LOG(ERROR) << ctx.GetErrorMessage(ret)
               << " while starting to retrieve tickets";
    return TranslateErrorCode(ret);
  }

  krb5_timestamp now = time(nullptr);

  krb5_creds creds;
  bool found_tgt = false;
  while ((ret = krb5_cc_next_cred(ctx.get(), ccache.get(), &cur, &creds)) ==
         0) {
    if (IsTgt(creds)) {
      if (creds.times.endtime)
        status->validity_seconds =
            std::max<int64_t>(creds.times.endtime - now, 0);

      if (creds.times.renew_till) {
        status->renewal_seconds =
            std::max<int64_t>(creds.times.renew_till - now, 0);
      }

      if (found_tgt) {
        LOG(WARNING) << "More than one TGT found in credential cache '"
                     << krb5cc_path.value() << ".";
      }
      found_tgt = true;
    }
    krb5_free_cred_contents(ctx.get(), &creds);
  }
  if (!found_tgt) {
    LOG(WARNING) << "No TGT found in credential cache '" << krb5cc_path.value()
                 << ".";
  }

  if (ret != KRB5_CC_END) {
    LOG(ERROR) << ctx.GetErrorMessage(ret) << " while retrieving a ticket";
    return TranslateErrorCode(ret);
  }

  ret = krb5_cc_end_seq_get(ctx.get(), ccache.get(), &cur);
  if (ret) {
    LOG(ERROR) << ctx.GetErrorMessage(ret)
               << " while finishing ticket retrieval";
    return TranslateErrorCode(ret);
  }

  return ERROR_NONE;
}

ErrorType Krb5InterfaceImpl::ValidateConfig(const std::string& krb5conf,
                                            ConfigErrorInfo* error_info) {
  *error_info = config_parser_.Validate(krb5conf);
  if (error_info->code() != CONFIG_ERROR_NONE)
    return ERROR_BAD_CONFIG;

  // Also try the mit krb5 code to parse the config.
  error_info->Clear();
  ErrorType error = ValidateConfigViaKrb5(krb5conf);
  if (error == ERROR_BAD_CONFIG) {
    error_info->set_code(CONFIG_ERROR_KRB5_FAILED_TO_PARSE);
    return error;
  }

  // Ignore all other errors, they're most likely unrelated. The
  // |config_parser_| should already cover pretty much everything, anyway.
  error_info->set_code(CONFIG_ERROR_NONE);
  if (error != ERROR_NONE) {
    LOG(WARNING) << "Ignoring unrelated error " << GetErrorString(error)
                 << " while validating config";
  }
  return error;
}

}  // namespace kerberos
