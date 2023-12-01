# ChromeOS on-device Health Service (healthd)

Health Service (a.k.a healthd) aims to provide
[one-stop APIs](./mojom/public/cros_healthd.mojom), including diagnostic and
telemetry, for Chromium and non-Chromium clients. It is _strongly_ suggested
that anyone with requests in [telemetry](./docs/telemetry.md) or
[diagnostic](./docs/diagnostic.md) to [contact us][team-contact] for a quick
check on the latest status just in case the documentation is behind the
reality.

By using healthd's APIs, the following benefits could be brought instantly with
only **one-time integration effort**:
* Unified data source: Necessary assembling is required to get a generic data,
  since it is common that a data from the certain source is only valid under
  some constraint. We provide a trusted and unified data source, and hide the
  complicate logics from our clients. Moreover, with the visions that more and
  more clients utilize our service, unified data source will help the data to
  be processed on the server side. Especially when it needs to perform
  join-like operations.
* Single endpoint: Different components data are usually scattered across
  varies services and processes. Our clients could save the work of
  communicating over IPC (e.g. DBus and Mojo), dealing with varies API flow
  designs. We wrap all the things under a simple API endpoint.
* Easier lifetime management: Our clients only need to handle/test the standard
  behavior on the Mojo channels. The common practices are well explored.
  Maintaining the lifetime to different services is a common difficulty.
* Sandboxed: healthd enforces least privilege needed for each information
  listed. The ChromeOS security policy requires applying sandbox when accessing
  privileged APIs (e.g. `ioctl` syscall) or files. This is a common challenge
  when accessing platform related information if building from scratch.
* Focused test coverage: We have team members rotating to monitor the alarm
  from labs. This will ease our clients to focus test effort on their own
  application. Our clients are also free from the effort of triage the lab
  hardware failure. It is another common pain point if building from scratch.

Here are more benefits for the whole ChromeOS ecosystem:
* One-time work benefits everyone: All clients get benefited once one of their
  new request is implemented by [us][team-contact].
* Lower system's loading: healthd _plans_ to cache information in a feasible
  time frame. Multiple requests from different clients will be benefited by
  those caching.


## Documentation

* The [docs/](./docs) subdirectory contains all other documentations.
* [internal team doc][g3doc] could give more information for internal contributors.

## Code structure

The repository hosts the core ChromeOS Health Service components, including:
* [interface definitions](./mojom/public) for other on-device services to
  access.
* [core health service daemon](./cros_healthd) (a.k.a. `cros_healthd`) provides
  core functionalities.
* [Legacy Wilco services](./docs/wilco_dtc.md) provide telemetry and
  diagnostics on Wilco devices.

[g3doc]: go/cros-tdm-g3doc
[team-contact]: mailto:cros-tdm-tpe-eng@google.com
