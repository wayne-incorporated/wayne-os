# UMAs in postinst

Traditionally, postinstall (run at the end of installs and updates) hasn't had a
need for metrics. There are several reasons for this, including:
* Chromebook/Chromebox install happens mostly at the factory, with no need for
  metrics there.
* The update engine has its own set of metrics, which can include failure at the
  postinstall step.
* When running with Chromebook firmware, postinst doesn't do all that much.
* UMA metrics recorded during install may not be sent (covered below).

ChromeOS Flex, however, supports installation in schools/businesses and homes,
and does more in postinst to support the variety of firmware seen on generic
consumer devices. To support this, it makes sense to add some metrics to
postinstall.

Postinst (and other installer histograms) defined
[here](https://source.chromium.org/chromium/chromium/src/+/main:tools/metrics/histograms/metadata/installer/histograms.xml).

## UMA loss during install

On ChromeOS metrics sent by non-browser processes are normally recorded in
`/var/lib/metrics/uma-events`. Every few minutes the browser moves the contents
of that file into its internal metrics log, and every half hour the browser
sends its internal log to the UMA servers. When the browser is shut down it
persists its metrics log to disk, to be sent on the next startup.

ChromeOS Flex style installs complicate this. There are two copies of the OS:
the live-booted 'installer' (e.g. ChromeOS running from a USB), and the 'target'
OS (being written to the device itself). Any metrics recorded while running the
live booted OS will remain on the USB which may never be booted again. There's a
[ticket for fixing this](https://buganizer.corp.google.com/issues/180948279),
possibly by copying metrics from the installer to the target.

If the install fails, however, there's no target OS to send the metrics.
Further, users running the installer may not bother connecting to the internet,
so install failure metrics are very likely to be lost. There's a ticket for
[encouraging users to connect to the internet](https://buganizer.corp.google.com/issues/243405822)
when an install fails.

A failed update, however, should be able to send metrics most of the time. The
one failure case would be an update that causes unrecoverable boot failure, and
where the user reboots within the (< 30 minute) window after the update is
applied and before the browser sends the metrics.
