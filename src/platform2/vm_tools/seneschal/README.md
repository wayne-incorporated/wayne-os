# seneschal - steward of the user's /home

The seneschal daemon manages a set of [9P](http://man.cat-v.org/plan_9/5/0intro)
servers that individually provide fine-grained access to specific files and
directories in the user's /home folder.

Clients can request (over DBus) for the seneschal to start a new server, share
specific file paths with that server, and then route consumers that need to
access those paths through the server.  It is also possible to give a server
access to additional paths even after it has been started.
