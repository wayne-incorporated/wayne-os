# CrOS RMA executor

An executor daemon that performs root-level tasks that the RMA daemon cannot do
by itself. The executor daemon is run as root in a jailed environment. The API
between the RMA daemon and the executor is defined in mojom/.

Since all codes in rmad/executor can be run as root, please make sure the
changes in this directory go through security reviews.
