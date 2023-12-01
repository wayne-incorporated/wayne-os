# ErrorBase object

An error object with error information in it.

It supports multiple layers of error messages, custom contents, custom function and printable.

This would be helpful to convert the error into some actions and logging the error message.

## How to add a new error type?

1. The custom error object needs to inherit the `ErrorBaseObj`.
2. It needs to implement the constructor.
3. It needs to implement `ToReadableString` to convert the error object to a readable string.
4. It needs to implement `SelfCopy` to copy itself.
5. Optional: Define `CustomError` to simplify the usage.
6. Optional: Override the `CreateError` helper function to create some special error type, for example: `nullptr`.
7. Optional: Override the `WrapError` helper function to create some special error.
8. Optional: Implement the move operator to add the support of caller info.

```C++
class CustomErrorObj : public ErrorBaseObj {
 public:
  explicit ErrorObj(const std::string& error_message)
      : error_message_(error_message) {}
  explicit ErrorObj(std::string&& error_message)
      : error_message_(std::move(error_message)) {}
  virtual ~ErrorObj() = default;

  hwsec_foundation::error::ErrorBase SelfCopy() const {
    return std::make_unique<ErrorObj>(error_message_);
  }

  std::string ToReadableString() const { return error_message_; }

 protected:
  ErrorObj(ErrorObj&&) = default;

 private:
  const std::string error_message_;
};
using CustomError = std::unique_ptr<CustomErrorObj>;

template <typename ErrorType,
          typename T,
          typename std::enable_if<
              std::is_same<ErrorType, CustomError>::value>::type* =
              nullptr,
          decltype(CustomErrorObj(
              std::forward<T>(std::declval<T&&>())))* = nullptr>
CustomError CreateError(T&& error_msg) {
  if (error_msg == "") {
      return nullptr;
  }
  return std::make_unique<CustomError>(std::forward<T>(error_msg));
}
```

# Recommended coding style

1. When should we use `auto`? Similar to [the style of unique_ptr](https://google.github.io/styleguide/cppguide.html#Type_deduction).
    1. Use `auto` when the error is created by `CreateError<>` or `WrapError<>`
        ```C++
        if (auto err = CreateError<TPM1Error>(0x99)) {
          /* Do some error handlings... */
        }
        ```
    2. Specify the error type in other cases.
        ```C++
        if (TPM1Error err = SomeMagicFunction()) {
          /* Do some error handlings... */
        }
        ```
2. Use Error in the `if` expression:
    1. It's fine to do implicit bool conversions when the error is declared inside the if expression.
        ```C++
        if (TPM1Error err = SomeMagicFunction()) {
          /* Do some error handlings... */
        }
        ```
    2. But we should prevent doing implicit bool conversions when the error isn’t declared in the if expression.
        ```C++
        if (SomeMagicFunction()) {
          /* Don’t do this. */
        }
        ```
        Please use:
        ```C++
        if (SomeMagicFunction() != nullptr) {
            /* This it better */
            /* But should think about why we need to drop the extra error information in this case. */
            /* For example: Should we log more messages in this case? */
        }
        ```
