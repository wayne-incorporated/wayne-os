#!/bin/sh
# This script is a nasty hack to evade a bad interaction between setuid and
# minijail's privilege-dropping code. To drop privileges, minijail sets up an
# LD_PRELOAD module which is loaded into the target program and drops privs when
# loaded. Normally, this wouldn't work with a setuid binary (as ld.so ignores
# LD_PRELOAD when setuid), but it _does_ work if the running uid is equal to the
# uid we'd be setuid-ing to (e.g., if we are running ping as root). What happens
# when running a setuid binary like ping as a sandboxed user is:
# 1) minijail (as root) forks a child process
# 2) child process sets up LD_PRELOAD, execs ping as root
# 3) setuid applies, ping stays root
# 4) LD_PRELOAD module loads, drops privs
# 5) ping continues, but not running as root, so nothing works.
# The solution is this shell script; with this script, this happens instead:
# 1) minijail (as root) forks a child
# 2) child sets up LD_PRELOAD, execs this as root
# 3) no setuid, LD_PRELOAD still applies
# 4) LD_PRELOAD module drops our resuid to unpriv user
# 5) this module execs ping (or other setuid binary); since we're an unpriv user
#    execing a setuid binary, the LD_PRELOAD is ignored
# 6) ping ends up running as root
exec "$@"
