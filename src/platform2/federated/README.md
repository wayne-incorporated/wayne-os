# Chrome OS Federated Computation Service

## Summary

The federated computation service provides a common runtime for federated
analytics (F.A.) and federated learning (F.L.). The service wraps the [federated
computation client] which communicates with the federated computation server,
receives and manages examples from its clients (usually in Chromium) and
schedules the learning/analytics plan. See [go/cros-federated-design] for a
design overview.

## Privacy and Security Review

Each client should have its own privacy & security reviewed launch for usage of
Mojo API to store training data. That's because:

1. Each federated computation method has different security/privacy properties,
   e.g. whether the task has Secure Aggregation enabled.
2. Each type of training data has different privacy considerations when stored
   on the cryptohome, potentially with different TTL requirements.

## Step by step guide

Each federated client consists of two major parts: a task that is deployed on
Brella server (server side), and the ability to collect examples and schedule
jobs for this task (ChromeOS/Chrome side).

### Server side

#### Create a task group

Federated computations are packaged as "tasks" inside of a [brella_task_group]
build rule. How to creating such task groups is not the focus of this doc,
please refer to brella team's tutorials:

- [go/brella-analytics-codelab] and
- [go/brella-modeling-codelab]

ChromeOS federated service requires task groups to set `runtime = chromeos`.
The runtime indicates a task_group's targeted platform. The rule
"brella_task_group" will generate a bunch of compatibility tests based on the
runtime setting to make sure the task group is compatible with the platform.
For ChromeOS this helps verify the brella client library (libfcp.so) contains
all necessary TF ops.
See [Fix selective ops registration](#fix-selective-ops-registration) for more
details.

#### Deploy the task_group to Brella server

In order to use Brella to execute federated tasks, owners must check-in an
instance of the [FederatedTasksConfig proto message] in a file named
`federated_tasks.pbtxt`. See [go/brella-comp-onboarding].

For ChromeOS platform clients, a new folder should be created in
[google3/intelligence/brella/config/prod/chromeos/]. And inside the folder there
can be several sub-directories indicating various **launch stages**, e.g. "dev",
"dogfood", "prod". The `federated_tasks.pbtxt` files are located inside
launch_stage path with population_name="chromeos/<client_name>/<launch_stage>".
See client ["timezone_code_phh"] as an example.

Each `federated_tasks.pbtxt` file in the launch stage directories represents a
deployed task, although the task group field can be the same or be derived from
a common base task group by setting the `extends` field of brella_task_group
rule, which allows tuning the configuration of the task in different launch
stages, e.g. report_goal could be a smaller number when launch stage is dev or
dogfood.

`federated_tasks: "chromeos/<client_name>"` should be also added to the ChromeOS
entry of [google3/intelligence/brella/config/prod/registry.pbtxt].
After that, new launch_stage directories created in this path can be
auto-detected and deployed to the server.

### ChromeOS/Chrome side

#### Collect examples

Code to collect examples for the new clients usually lives in Chrome side. The
owners of the client are responsible to implement the logic to collect info and
generate examples, and report them to federated service via [mojo interface].

#### Register new client

Add the new client to federated_metadata.cc::kClientMetadata in [this repo]. The
metadata is pretty simple, it only contains the unique client name, a
retry_token which is usually an empty string, and a launch_stage.

At the start, the launch_stage can be set to "dev" and it can be configured
through Finch (In [this Finch example], client "timezone_code_phh" set
launch_stage to "dogfood" for the dogfood group). Once the project becomes
stable, the parameter can be changed to "prod".

#### Fix selective ops registration

To optimize the size of brella client library, we use TensorFlow selective ops
registration approach when building libfcp.so, which means the built-in
TensorFlow does not contain all ops, and therefore it may not support the new
task groups. These failures can be captured when creating task groups and
setting `runtime = chromeos`. This doc [Selective op registration of ChromeOS
fcp build] describes how to find the missing ops and add them to ChromeOS
libfcp.so.

#### Fix the seccomp

Because federated-service runs inside sandbox, sometimes the tasks introduced by
new clients may require new syscalls that are blocked by minijail. Reach out to
cros-federated-team@google.com when running into such issues.

#### Rollout with Finch

New clients should define their Finch flags in ash/constants/ash_features.h/cc,
and add an entry to [kClientFeatureMap]. After that, owners can use the Finch
flag and associated feature parameter "launch_stage" to control whether the
client is enabled and its launch_stage. See [go/finch-slides] for details.

[federated computation client]: http://go/fcp
[go/cros-federated-design]: http://go/cros-federated-design
[brella_task_group]: http://go/brella-build#brella_task_group
[go/brella-analytics-codelab]: http://go/brella-analytics-codelab
[go/brella-modeling-codelab]: http://go/brella-modeling-codelab
[selective op registration of chromeos fcp build]: http://g3doc/chrome/knowledge/federated/tools/README
[federatedtasksconfig proto message]: http://google3/intelligence/micore/training/config/brella_server_config.proto
[go/brella-comp-onboarding]: http://go/brella-comp-onboarding#federated_tasks_config
[google3/intelligence/brella/config/prod/chromeos/]: http://google3/intelligence/brella/config/prod/chromeos/
["timezone_code_phh"]: http://google3/intelligence/brella/config/prod/chromeos/timezone_code_phh/
[google3/intelligence/brella/config/prod/registry.pbtxt]: http://google3/intelligence/brella/config/prod/registry.pbtxt
[mojo interface]: https://crsrc.org/c/chromeos/ash/services/federated/public/cpp/service_connection.h
[this repo]: ./
[this finch example]: http://cl/503838903
[kclientfeaturemap]: https://crsrc.org/c/ash/system/federated/federated_service_controller_impl.cc
[go/finch-slides]: http://go/finch-slides
