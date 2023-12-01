# 9s - [9p] server program

This is a very thin wrapper around the [p9] library crate.  It takes care of
parsing command-line options, accepting incoming client connections, and then
handing things off to the [p9] crate.

[9p]: http://man.cat-v.org/plan_9/5/intro
[p9]: ../p9
