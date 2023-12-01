# sirenia-rpc-macros

This module provides a procedural macro for automatically implementing the RPC
boilerplate given a Rust trait. For an example see the [smoke test]. It
currently uses RefCell, so single threaded usage is assumed (This can change if
needed, but we would want to specify single vs multi-threaded).

To apply the macro:
* Add `#[sirenia_rpc]` before the trait definition.
* Ensure the trait has a `type Error` field.
* Ensure all the parameters and return types of all trait member functions:
  - Implement `Clone`, `Debug`, `Deserialize`, and `Serialize` (`Clone` can
    possibly be dropped in the future).
  - Are types without non-static lifetimes (this can possibly be relaxed in
    the future if needed).

Once applied to a trait `MyTrait` the macro provides:
* A `MyTraitServer` trait
* A `MyTraitClient` struct that wraps a `libsirenia::transport::Transport` object.
* Corresponding implementations of `libsirenia::rpc::MessageHandler` for
  `Box<dyn MyTraitServer>` and `MyTrait` for `MyTraitClient`.

[smoke test]: tests/smoke.rs
