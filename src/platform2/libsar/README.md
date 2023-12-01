# ChromeOS Sar Sensor Config Reader Library

`SarConfigReader` is the main class being used. Users should mostly choose an
implementation of `SarConfigReader::Delegate`, either
`SarConfigReaderDelegateImpl` or `FakeSarConfigReaderDelegate`. Both provided
in this library.
