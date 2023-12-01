# Hacking debugd

[iface]: ../dbus_bindings/org.chromium.debugd.xml
[impl]: implementation.md
[design]: design.md
[makefile]: ../BUILD.gn

If you're reading this doc, you hopefully want to add a new feature to debugd
(or fix a bug). You should have a look at [the implementation doc][impl] and
[the design doc][design], and perhaps the existing [interface][iface].

The first and most important question to ask yourself is whether the thing
you're trying to do belongs in debugd. We sandbox debugd, but it still has
access to many privileged parts of the system, which means any code in debugd
exposes a large attack surface. In general, you should aim to have as little
code as possible in debugd - if you need elevated privileges to get a piece of
data, add an accessor for that piece of data in debugd, and do any analytics you
need elsewhere.

Once you've looked at those documents and pondered that question, here's how
you'd go about adding a new piece of data debugd can return:

1. Decide whether it fits logically with an existing piece of data we return. If
so, you're going to want to hack the tool that returns the existing data; if
not, you're going to need to add a new tool.

2. If you're adding a new tool, add it to the `static_library("libdebugd")`
sources in [`/BUILD.gn`][makefile]. You will also need to add an entry in
[`/dbus_bindings/org.chromium.debugd.xml`][iface] for every method you create.
Tools follow the general pattern of having a header called `/src/foo_tool.h` and
an implementation file called `/src/foo_tool.cc`.

3. If you're doing anything at all complicated, add a helper (see
`/src/helpers`), and use `ProcessWithOutput` (see `/src/process_with_output.h`)
to capture its output before returning it over DBus. Helpers are subprograms
that we can launch in sandboxes.

4. Once you've added your new tool (or hacked an existing one) and added your
new helper (if necessary), write an autotest (or extended the existing
`platform_DebugDaemon` test) to cover the feature you added.

5. Test, review, submit.

6. Hack the debugd ebuild to install your new helper (if applicable).
