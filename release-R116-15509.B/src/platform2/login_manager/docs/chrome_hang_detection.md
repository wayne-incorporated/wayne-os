# Chrome hang detection in session\_manager

`session_manager` sends periodic "liveness checks" to Chrome in the form of
D-Bus method calls and kills Chrome if it doesn't respond in a timely manner.
Chrome handles D-Bus messages on its UI thread, so a failure to reply indicates
that the UI thread is blocked.

## Details

`session_manager`'s portion of the implementation lives in
[liveness_checker_impl.h] and [liveness_checker_impl.cc]. By default,
`session_manager` makes an asynchronous `CheckLiveness` D-Bus method call to
`org.chromium.LivenessService` every 60 seconds. If a response hasn't been
received for the previous call at this point, `session_manager` sends a
`SIGABRT` signal to Chrome's browser process.

Chrome exports the `org.chromium.LivenessService` D-Bus service and replies
immediately to `CheckLiveness` method calls.

On developer systems (as indicated by the `is_developer_end_user` command),
Chrome will not be killed by the hang detector since it may be unresponsive due
to having been stopped by a debugger.

## Intepreting crashes

When `session_manager` detects that Chrome is hanging, messages similar to the
following should be logged to `/var/log/messages` (timestamps omitted):

```
WARNING session_manager[1492]: [WARNING:liveness_checker_impl.cc(64)] Browser hang detected!
WARNING session_manager[1492]: [WARNING:liveness_checker_impl.cc(68)] Aborting browser process.
INFO session_manager[1492]: [INFO:browser_job.cc(164)] Terminating process: Browser did not respond to DBus liveness check.
INFO session_manager[1492]: [INFO:system_utils_impl.cc(93)] Sending 6 to 1529 as 1000
WARNING crash_reporter[4409]: Received crash notification for chrome[1529] user 1000 (called directly)
WARNING session_manager[1492]: [WARNING:browser_job.cc(172)] Aborting child process 1529's process group 3 seconds after sending signal
INFO session_manager[1492]: [INFO:browser_job.cc(156)] Terminating process group: Browser took more than 3 seconds to exit after signal.
INFO session_manager[1492]: [INFO:system_utils_impl.cc(93)] Sending 6 to -1529 as 1000
...
INFO session_manager[1492]: [INFO:child_exit_handler.cc(77)] Handling 1529 exit.
ERR session_manager[1492]: [ERROR:child_exit_handler.cc(85)]   Exited with signal 6
INFO session_manager[1492]: [INFO:session_manager_service.cc(289)] Exiting process is chrome.
INFO session_manager[1492]: [INFO:browser_job.cc(156)] Terminating process group: Ensuring browser processes are gone.
```

[Breakpad] handles `SIGABRT` within Chrome, and if crash reporting is enabled, a
crash report should be sent. The browser process's stack trace will hopefully
indicate the reason for the hang.

Note also that the `chrome.txt` file linked in the crash report (which is
actually a gzipped text file) includes the tail portions of the
`session_manager` and Chrome user and system log files. If a `SIGABRT` crash was
caused by the hang detector, you'll probably see the above log messages in
`chrome.txt`.

## History

Similar code originally lived in `chromeos-wm`, the long-gone Chrome OS X11
window manager. The pings were sent via X11 back then. See [issue 217814] and
other bugs of similar vintage for more details.

The original implementation of this within `session_manager` was tracked by
[issue 217825], and the code hasn't changed much since then. The feature was
briefly disabled in 2013 and before being reenabled ([issue 221008]) and updated
to send `SIGFPE` rather than `SIGABRT` (to make it easier to distinguish between
hangs and `CHECK`s or `LOG(FATAL)`s within Chrome). In 2015, `session_manager`
was updated to send `SIGABRT` rather than `SIGFPE` ([issue 284601]). The
`CheckLiveness` D-Bus method was moved from `org.chromium.LibCrosService` into a
new `org.chromium.LivenessService` service also provided by Chrome ([issue
644322]).

[liveness_checker_impl.h]: ../liveness_checker_impl.h
[liveness_checker_impl.cc]: ../liveness_checker_impl.cc
[Breakpad]: https://chromium.googlesource.com/breakpad/breakpad/
[issue 217814]: https://crbug.com/217814
[issue 217825]: https://crbug.com/217825
[issue 221008]: https://crbug.com/221008
[issue 284601]: https://crbug.com/284601
[issue 644322]: https://crbug.com/644322
