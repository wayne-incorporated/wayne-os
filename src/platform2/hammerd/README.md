# hammerd: A daemon to update hammer

## Summary

hammer is the base of detachable, connected via USB over pogo pins. hammer runs
its own upgradable firmware (base EC, running EC codebase on STM32F072), is
attached to a touchpad (with its own upgradable FW), and is able to pair with
the detachable.

We need a userspace daemon, running on the AP, that does the following things
related to hammer:

- Waits for a base to be attached on detachable's pogo pins port, and then
  performs the following tasks as required.
  - Base EC FW update
  - Base touchpad FW update
  - Base pairing
  - Tell base to increment its rollback counter (if necessary)
  - Interaction with Chrome:
    - Shows notification during update (EC+touchpad)
    - Shows notification that a new base is connected (pairing)

## Triggered On Boot

Before the UI starts, hammerd is invoked to check whether the base is attached
and need update or not. If so, then hammerd update the base EC firmware and
touchpad firmware.

## Triggered On Attachment

hammerd is also invoked when the base is attached to check whether the base
needs update. But hammerd ONLY send a DBus signal to notify Chrome UI in
critical case (firmware is broken or critical update appears),
NOT updating anything.

## Update Manually

We can also manually update firmware by running:
`start hammerd UPDATE_IF="always"`
It is useful in development or debugging.
