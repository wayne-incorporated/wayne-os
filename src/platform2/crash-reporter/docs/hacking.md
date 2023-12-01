# Developing, Breaking, Fixing, and Testing

When developing crash-reporter, or even simply running a dev or test image,
there's a few settings to be aware of that control/override runtime behavior.

If testing via ssh, or you otherwise skipped setting up consent, you can opt-in
to crash collection by running:
```sh
# metrics_client -C
```

By default, coredumps will be removed after creating minidumps.
You can `touch /root/.leave_core` to change that behavior.

Similarly, if you want Chrome coredumps to be retained, you can `touch
/mnt/stateful_partition/etc/collect_chrome_crashes`.

Crash uploading is disabled on test images.
You can force them to be uploaded by running:
```sh
# crash_sender --dev --max_spread_time=0
```

The `--max_spread_time=0` option is to make `crash_sender` upload right away.
Otherwise it'll sleep a random amount of time (up to 10 minutes) between
reports.

Crash reports uploaded with the `--dev` flag will be sent to the staging crash
server which can be access at http://go/crash-staging.
