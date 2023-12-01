# Analytics

This directory contains implementation of internal analytics of Missive via UMA.

To see the analytics results, visit the
[UMA Dashboard](https://uma.googleplex.com/p/chrome/timeline_v2). Select "Chrome
OS" as the platform and the channel of your interest. Then, click on
"Metrics/Formula +" and search for "Platform.Missive.". All items shown are
analytics of the Missive daemon recorded and uploaded by this directory.

## Add an Analytics Resource

To add a new analytics resource:

1. Create a new class `ResourceCollectorMyResource` that inherits
   `ResourceCollector`.

2. Implement the virtual method `ResourceCollectorMyResource::Collect` according
   to the document of `ResourceCollector::Collect`. Here, you likely need to use
   [libmetrics](../../metrics/README.md). Check out their documentation for
   guidance.

3. Register it to the registry in the `MissiveDaemon` constructor by calling

   ```
   analytics_registry_.Add("MyResource",
                           std::make_unique<ResourceCollectorMyResource>(base::Minutes(10)))
   ```

   Feel free to replace `base::Minutes(10)` above with any reasonable time
   interval.

See `ResourceCollectorStorage` for an example.

## Dependency on This Directory

Generally speaking, only `MissiveDaemon` should contain code that depends on
this directory. The reason is twofold:

1. This directory is not synced to `components/`. It will become burdensome to
   sync the part of Missive that need to be synced to `components/` if they
   depend on this directory.

2. It is generally good engineering practice to not spill analytics code into
   implementation details. Otherwise, a simple change in implementation details
   or a small refactoring may unnoticeably introduce inconsistency into
   analytics.

## The Terms "Analytics," "Metrics," and "Telemetry"

The three words are quite confusing in the context of Encrypted Reporting
Pipeline (ERP). Metrics or telemetry in ERP typically refers to monitoring data
on device that are collected to directly benefit the admins and usually made
accessible to them. Metrics or telemetry in Chrome, as referred to by UMA, are
monitoring data on device that are collected to directly benefit developers,
usually for better understanding the behavior of the software in production. To
distinguish from metrics or telemetry in ERP, we refer to the term corresponding
to metrics and telemetry in Chrome as analytics.

A quick summary:

- Metrics and telemetry in ERP: To the benefit of admins (our customers)
- Analytics in ERP, metrics and telemetry in Chrome: To the benefit of
  developers
