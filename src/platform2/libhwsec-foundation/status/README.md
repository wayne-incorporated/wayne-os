# Error and StatusChain

The error objects framework consists of two main components:

* `Error` is a base type for actual errors, that code can generate
* `StatusChain` is a holder object for those Errors.

Error objects are default, copy and move constructible, and also provide an
explicit constructor from a `std::string`. They also have three customization
points:

1. `std::string ToString()` const - by default returns the message the `Error`
   was constructed with (or std::string() in the case of default constructor).
   Can be overridden to provide a custom behaviour.
2. `void WrapTransfor(StatusChain<BaseErrorType>::const_iterator_range range)` -
   a method, that is invoked upon the error being wrapped. The argument of it is
   an iterable view of the stack the error intends to wrap. Can be overloaded to
   provide custom behaviour. Defaulted to a no-op.
3. `struct MakeStatusTrait` subtype. This trait allows to customize creation
   behaviour of the Error. Two pre-defined types are `DefaultMakeStatus` and
   `ForbidMakeStatus`, for the default behaviour and creation prohibition.
4. `BaseErrorType` allows to specify the base error type of the stack. Only
   errors with the exactle same `BaseErrorType` can be in one chain. Defaulted
   to `Error`.

`StatusChain` object is effectively a unique pointer to an `Error`. It inherits
`StackablePointer`, and thus manages a stack of `Error` objects. The access to
the head of the stack can be done through get/operator-\>/operator\*/error().
To iterate over the stack with `for (auto error_obj_ptr : stack.range())` or
`for (const auto error_obj_ptr : stack.const_range())` for the const view, or
by using iterators manually, as in
`for (auto it = stack.range().begin(); it != stack.range().eng(); ++it)`
`error_obj_ptr` is a raw pointer, managed by the stack. `it` is an iterator,
where `error_obj_ptr == *it`, and `it->something` is equivalent to
`error_obj_ptr->something`.

The success is marked with `OkStatus<T>()` object.

## How to add a new error type?

1. The custom error object has to inherit `Error`.
2. It needs to specify public `struct MakeStatusTrait` (see details in
   `status/status_chain.h`)
3. It needs to implement a constructor. Ideally it has to excerxise the fully
   qualified base class constructor, but it is not necessary. It is recommended
   that at least `error_message` setting constructor of the base class is
   invoked.
4. It needs to override the destructor.
5. It can override `ToString` to customize printing behaviour.
6. It can overload `WrapTransform` to modify wrapping error during Wrap
   operation.
7. It can overload `BaseErrorType` to specify which type of iterable it will
   produce from the chain. Only errors with the same |BaseErrorType| can be
   stored in one chain.

```C++
class CustomError : public Error {
 public:
  using MakeStatusTrait = hwsec::DefaultMakeStatus<CustomError>;

  explicit CustomError(const std::string& error_message)
      : Error(error_message) {}
  ~CustomErroj() override = default;

  std::string ToString() const override {
    return "AWESOME PREFIX: " + Error::ToString();
  }

  void WrapTransform(StatusChain<Error>::const_iterator_range range) override {
    for (const auto error_obj_ptr : range) {
      // do something with the base error.
    }
  }
};
```

## StatusChainOr

StatusChainOr allows you to return either a value or a non-ok status.

Note: you should never convert an `OkStatus` into the StatusChainOr.

## How to return an error

1. If you need to interact with non-libhwsec errors - define MakeStatusTrait
   for your custom error to convert external error to a StatusChain object.
2. If you need to return a new error, use
   `return MakeStatus<CustomError>(<custom error ctor args>)`.
3. If you need to wrap a previously returned error with a new one
   `return MakeStatus<CustomError>(<custom error ctor args>).Wrap(std::move(old_chain))`.

## Customizing MakeStatus

To define a custom MakeStatus behaviour, the Error object needs to defaine
MakeStatusTrait substruct, which define operator(). The return type is not
enforced, but it should be `StatusChain<ErrorType>` unless you have intermediate
stub objects. Any intermediate stub object should implement Wrap to return
`StatusChain<CustomError>` type - Wrap should convert stub back to status.
An important note:

* Within `MakeStatusTrait`, new `StatusChain` should be created with a
  `NewStatus`, instead of `MakeStatus`. Using `MakeStatus` will cause an
  infinite recursion.

```C++
class CustomError : public Error {
 public:
  using MakeStatusTrait {
    struct Stub {
      StatusChain<CustomError> Wrap(StatusChain<Error> error) {
        return NewStatus(<ctor args>)
      }
    }
    auto operator()(<some args>) {
      return Stub();
    }
    auto operator()(<some args>) {
      return NewStatus(<ctor args>);
    }
  };
};
```

## Customizing Wrap behaviour

To add additional actions upon Wrap, the object can override WrapTransform function,
that receives an iterable range of the wrapped stack (excluding current error).
Client code can iterate over the range and use the info from it. It can not
modify the stack.

# Recommended coding style

1. When should we use `auto`? Similar to [the style of unique_ptr](https://google.github.io/styleguide/cppguide.html#Type_deduction).
    1. Use `auto` when the error is created by MakeStatus.
        ```C++
        if (auto status = MakeStatus<TPM1Error>(0x99); !status.ok()) {
          /* Do some error handlings... */
        }
        ```
    2. Specify the error type in other cases.
        ```C++
        if (StatusChain<TPM1Error> status = SomeMagicFunction(); !status.ok()) {
          /* Do some error handlings... */
        }
        ```
2. Use of `StatusChain` in the `if` expression:
    1. Prefer using `RETURN_IF_ERROR` if possible and readable.
       ```C++
       RETURN_IF_ERROR(SomeMagicFunction(), AsStatus<TPMErrpr>("some error"));
       ```
    2. Otherwise prefer explicitly checking the status of the return object.
        ```C++
        if (StatusChain<TPM1Error> status = SomeMagicFunction(); !status.ok()) {
          /* Do some error handlings... */
        }
        ```
    3. It's acceptable to do implicit bool conversions when the error is declared inside the if expression.
       Note, that eventually the implicit conversion might be deprecated.
        ```C++
        if (StatusChain<TPM1Error> status = SomeMagicFunction()) {
          /* Do some error handlings... */
        }
        ```
    4. We should prevent doing implicit bool conversions when the error isn’t declared in the if expression.
        ```C++
        if (SomeMagicFunction()) {
          /* Don’t do this. */
        }
        ```
        Please use:
        ```C++
        if (!SomeMagicFunction().ok()) {
            /* This it better */
            /* But should think about why we need to drop the extra error information in this case. */
            /* For example: Should we log more messages in this case? */
        }
        ```
