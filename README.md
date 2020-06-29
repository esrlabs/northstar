# Northstart

`Northstar` is a isolated process supervisor.

## Getting started

Developing with north requires some tooling. A good starting point is installing `Rust` via `https://rustup.rs`.
Next run `bootstrap.rb` to add additional tools and libraries.

### MacOS

TODO

### Linux

TODO

### Android

TODO

## Checks & Tests

To execute all `tests` and `checks` that will also be executed in the CI:

```shell
rake check
```

## Unit tests code coverage

Generate a report of the unit tests code coverage with the following command:

```shell
rake coverage
```

### Prerequisites

#### Rust nightly toolchain

```shell
rustup toolchain install nightly
```

Or see <https://github.com/rust-lang/rustup#working-with-nightly-rust> for details.

#### install grcov

```shell
cargo install grcov
```

More information on <https://github.com/mozilla/grcov>
