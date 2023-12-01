# Hacking on shill

To keep the shill source code consistent, please follow the conventions below:

*   Follow the [Chromium C++ style guide](https://chromium.googlesource.com/chromium/src/+/HEAD/styleguide/c++/c++.md)

    If you use Emacs, the Google C Style mode will help you with the formatting
    aspects of style. (Chromium Style generally follows Google Style). Get the
    Emacs mode at
    https://github.com/google/styleguide/blob/gh-pages/google-c-style.el

*   When deferring work from a signal handler (e.g. a D-Bus callback) to
    the event loop, name the deferred work function by adding `Task` to
    the name of the function deferring the work. E.g.

    ```c++
    void Modem::Init() {
      dispatcher_->PostTask(FROM_HERE,
                            task_factory_.NewRunnableMethod(&Modem::InitTask));
    }
    ```

    RATIONALE: The naming convention makes the relationship between the signal
    handler and the task function obvious, at-a-glance.

*   When adding verbose log messages for debug purposes, use the `SLOG` macro
    and its variants (see `logging.h` for details).

    *   Choose the appropriate scope and verbose level for log messages. E.g.

        ```c++
        SLOG(WiFi, 1) << message;  // for WiFi related code
        ```

    *   Before defining a new scope, check if any existing scope defined in
        `scope_logger.h` already fulfills the needs.

    *   To add a new scope:
        1.  Add a new value to the `Scope` enumerated type in `scope_logger.h`.
            Keep the values sorted as instructed in the header file.
        2.  Add the corresponding scope name to the `kScopeNames` array in
            `scope_logger.cc`.
        3.  Update the `GetAllScopeNames` test in `scope_logger_test.cc`.

*   When adding externally visible (i.e. via RPC) properties to an object,
    make sure that a) its setter emits any change notification required by
    Chrome, and that b) its setter properly handles no-op changes.

    Test that the property changes are handled correctly by adding test
    cases similar to those in `CellularServiceTest.PropertyChanges`, and
    `CellularServiceTest.CustomSetterNoopChange`.

*   When performing trivial iteration through a container, prefer using
    range based for loops, preferably:

    ```c++
    for (const auto& element : container) {
    ```

    Remove `const` where necessary if the element will be modified during
    the loop.  Removal of the `const` and reference for trivial types is
    allowed but not necessary.
