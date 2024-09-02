## Development process
1) The Chrome OS stable version is released every 4 weeks.
2) The Chrome OS stable version is released after the Chrome stable version is released.
3) The Chrome OS LTS version is released for every 6 Chrome OS stable versions.
4) The Chromium OS LTS version src is released on the *release* branch of Chromium OS project.
5) Wayne OS project maintainers download the src and develop (verify/modify/add) it.
6) The developing sources are maintained on *stabilize* branch of Wayne OS project.
7) The finalized sources are maintained on *release* branch of Wayne OS project.
8) The development information for each Wayne OS version is documented in [version_details.md](https://github.com/wayne-incorporated/wayne-os/blob/stabilize-R120-15662.B/docs/en/release/version_details.md).
9) The Wayne OS binaries are released after simple alpha tests.

## Release schedules
All dates are approximate and are subject to change without notice.
#### Milestone 126
- Feature freeze: 2024-04-29
- Branch: 2024-05-13
- Chrome (Chromium) stable release: 2024-06-11
- Chrome OS (Chromium OS) stable release: 2024-06-25
- Chrome OS (Chromium OS) LTS release: 2024-10-01
- Chrome OS (Chromium OS) LTS last refresh: 2025-04-15
- Wayne OS release: 2024-10-01 - 2024-12-31
#### Milestone 132
- Feature freeze: 2024-10-28
- Branch: 2024-11-11
- Chrome (Chromium) stable release: 2025-01-07
- Chrome OS (Chromium OS) stable release: 2025-01-14
- Chrome OS (Chromium OS) LTS release: 2025-04-08
- Chrome OS (Chromium OS) LTS last refresh: 2025-10-07
- Wayne OS release: 2025-04-08 - 2025-07-07
#### Milestone 138
- Feature freeze: 2025-05-12
- Branch: 2025-05-26
- Chrome (Chromium) stable release: 2025-06-24
- Chrome OS (Chromium OS) stable release: 2025-07-22
- Chrome OS (Chromium OS) LTS release: 2025-10-14
- Chrome OS (Chromium OS) LTS last refresh: 2026-04-21
- Wayne OS release: 2025-10-14 - 2026-01-13

## Reference
- https://support.google.com/chrome/a/answer/11333726?hl=en
- https://chromium.googlesource.com/chromium/src/+/master/docs/process/release_cycle.md
- https://chromiumdash.appspot.com/schedule
- https://chromium.googlesource.com/chromiumos/manifest/+refs

## TL;DR
Wayne OS is generally released every 6 months, based on the Chromium OS LTS version.
