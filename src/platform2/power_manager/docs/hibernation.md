# Hibernation in powerd

## Introduction

Hibernation, also known as suspend-to-disk, or S4, describes a system power
state transition wherein RAM is saved to disk and the system is put into a low
power state. It can achieve the same fidelity of user state restoration as
suspend-to-RAM, but with power consumption closer (and oftentimes identical to)
a shut down system. The improved power usage over suspend-to-RAM comes with the
tradeoff of disk usage and increased latency. Hibernation can be thought of as a
middle ground between suspend and shutdown, taking some attributes from each.

## Powerd's role in hibernation

Powerd acts as a policy engine and initiator of hibernate, just as it does for
system suspend and shutdown-from-idle transitions. Powerd determines at startup
if the system is capable of hibernation. It may initiate a hibernation as part
of an explicit SuspendRequest to suspend to disk, or passively as a substitute
for shutdown-after-x.

All of the documentation for suspend/resume applies to going down for
hibernation as well. From the application perspective, to first order there is
no detectable difference between the two. Like suspend/resume, powerd emits a
`SuspendImminent` signal when the system is going to transition to hibernate,
and a `SuspendDone` signal when the resume transition is complete. Users of the
`SuspendDone` signal can look at the deepest_state member to determine whether
or not a hibernation occurred.

The actual mechanics of hibernate are handled by a separate service, [hiberman].
See the hiberman documentation for the gritty details of how the system goes
down for and comes up from hibernation.

## Powerd and hibernation resume

Resume from hibernation works by first doing a cold boot, then loading the
hibernation image from disk and jumping back into it. That means there is a
point at which ChromeOS is running, but then the current execution environment
abruptly ends as control is returned to the hibernated system. This event is
known as a resume from hibernation.

Resume from hibernation is initiated and mostly coordinated by hiberman rather
than powerd. Powerd still participates in this transition however in terms of
emitting the `SuspendImminent` signal and executing suspend dbus callbacks
before letting the resume transition proceed.

To allow daemons to prepare for an imminent resume from hibernation, powerd
sends out the `SuspendImminent` dbus signal, with the action member set to
`HIBERNATE_RESUME`. Daemons already registered for `SuspendImminent` signals
that are unaware of the action member will end up doing the same thing they
would do for a suspend-to-RAM, which almost always ends up being the right
behavior anyway.

If for some reason the resume transition fails, then the hibernation image is
discarded, and this boot continues as if it were a fresh boot. In this case
powerd sends out a `SuspendDone` corresponding to the `SuspendImminent` it just
sent, hiberman cleans up, and the system proceeds as usual.

### Communication between powerd and hiberman during resume

Powerd and hiberman need to coordinate during the resume transition. Hiberman
initiates resume early in boot and waits for login credentials to arrive. Once
the hibernation image is fully loaded on disk and the resume transition is ready
to execute, hiberman asks powerd to send the `SuspendImminent` signal and run
suspend callbacks. It does this using a new flavor value to RequestSuspend:
`RESUME_FROM_DISK_PREPARE`. This causes powerd to do its callback dbus activity,
but not actually initiate any further transition itself. It instead emits a
`HibernateResumeReady` signal, which lets hiberman know that resume callbacks
have completed. At this point hiberman will trigger the final steps of resume,
ending the execution environment upon success.

In the abort scenario, hiberman initiates a rollback of the resume within powerd
by using yet another new flavor value of `RequestSuspend`:
`RESUME_FROM_DISK_ABORT`. Upon receiving this, powerd emits its `SuspendDone`
signal corresponding to the `SuspendImminent` it sent out earlier, and resets
its state machine back to idle.

The period where powerd is braced for an imminent resume from hibernation is
meant to be brief, just a few seconds at most. While in this state, other powerd
suspend requests are ignored, as only one power state transition is expected to
be occurring at a time.

The new RequestSuspend flavors (`RESUME_FROM_DISK_PREPARE` and
`RESUME_FROM_DISK_ABORT`) as well as the `HibernateResumeReady` signal are meant
to be internal communication mechanisms between powerd and hiberman.
Applications and other system daemons should not use these mechanisms directly,
as they are subject to change without notice.

[hiberman]: https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/hiberman
