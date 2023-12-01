# Generating Seccomp Policies

The seccomp policies are effectively an allow-list of syscalls and their
arguments that a program is allowed to issue. The general idea to creating a
starter policy is to run the program with strace and log the system calls that
the kernel saw. This is a tough job, since there is no guarantee that you can
exercise all code paths and error cases, where additional system calls may
present themselves.

See [Sandboxing Chrome OS system services] for more information.

## Quick Start

See comments in [run_bio_crypto_init_strace.sh](run_bio_crypto_init_strace.sh)
and [run_biod_strace.sh](run_biod_strace.sh).

## Tips

Starting in kernel 4.14, `CROS_EC_DEV_IOC*` symbolic names refer to the EC V2
protocol. These commands appear as `CROS_EC_DEV_IOC*_V2` in the EC codebase. See
the following:

*   https://crrev.com/29b90cb0269d87ad68af54ef8798cbe47c5f044c/drivers/mfd/cros_ec_dev.h#43
*   https://crrev.com/211a0fe46105608f487d303eedd3e23a2e73434c/util/cros_ec_dev.h#87

[Sandboxing Chrome OS system services]: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/sandboxing.md
