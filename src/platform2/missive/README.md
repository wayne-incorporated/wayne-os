# Missive Daemon

The Missive Daemon is part of the Encrypted Reporting Pipeline (ERP). It
encrypts, stores, and forwards reporting records enqueued on its DBus interface.
The interface allows other CrOS daemons and Chrome to enqueue records which are
then encrypted and stored on disk. Records are enqueued in different priority
queues, which have different upload periods. Once the storage daemon determines
that a queue is ready for upload (i.e. the requisite period has elapsed), it
sends records to Chrome to be uploaded to the Reporting Server. On successful
upload, records are deleted from disk.

Note: This is a complementary daemon to the
`//chrome/browser/policy/messaging_layer` package in chromium.

## Build and Deploy

```
# HOST (inside chroot)
~$ cros-workon-${BOARD} start missive
~$ emerge-${BOARD} missive
~$ cros deploy ssh://localhost:9222 missive

# DUT
~# start missived
```

To build the package that works with a non-debug image, such as one from
GoldenEye, the debug feature must be disabled:

```
# HOST (inside chroot)
~$ USE=-cros-debug emerge-${BOARD} missive
```

If there are errors on conflicting USE flags, rebuild the dependencies with

```
# HOST (inside chroot)
~$ build_packages --board=${BOARD} --no-withdebug
```

For convenience, if you always work with a non-debug image, consider disabling
debug builds by default by adding `USE="${USE} -cros-debug"` to
`/etc/make.conf.user` (inside chroot).

## Original design docs

Note that aspects of the design may have evolved since the original design docs
were written.

* [Daemon Design](http://go/cros-reporting-daemon)
* [Messaging Layer](http://go/chrome-reporting-messaging-layer)

## Updating From Chromium

### General Guidelines

The code in the following folders originally comes from
chromium://components/reporting:

- compression
- encryption
- proto
- storage
- util

When importing updates from the chromium code you will encounter the following
issues:

1. #include statements in chromium for //base need to be converted as follows:
   #include "base/example.h" -> #include <base/example.h>
2. Protobuf include directory can be converted from chromium as follows:
   "third_party/protobuf/src/google/protobuf/..." -> <google/protobuf/...>
3. ChromeOS doesn't need to worry about worrying on multiple operating systems,
   so doesn't require FILE_PATH_LITERAL, base::FilePath::CharType, or
   base::FilePath::StringType. It can be assumed that these are simple char or
   std::strings.
4. Files that end with `_unittest.cc` should be renamed to end with `_test.cc`.

### Specific Files

- chromium://components/reporting/util/status.proto has been moved to
  .../missive/proto/status.proto. This is due to difficulties in including
  protos within protos on ChromeOS.

### Test tool for manual Enqueue and Flush operations.

The tool is built as part of missive when running tests.

```
# HOST (inside chroot)
~$ FEATURES=test emerge-${BOARD} missive
~$ scp -P 9222 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no                      \
       /build/${BOARD}/var/cache/portage/chromeos-base/missive/out/Default/missive_testing_tool \
       root@localhost:/usr/bin/missive_testing_tool
```

(If targeting DUT, replace port in -P parameter - usually with 2222)

```
# VM/DUT
To enqueue event:
~# sudo -u chronos /usr/bin/missive_testing_tool --enqueue="Some record data..." \
   --priority=SLOW_BATCH --destination=HEARTBEAT_EVENTS
To flush all events in a queue:
~# sudo -u chronos /usr/bin/missive_testing_tool --flush \
   --priority=SLOW_BATCH
```
