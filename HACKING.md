## Rust environment

### Install Rust nightly toolchain

```shell
rustup toolchain install nightly
```

### Setup ruby env

Next run `rake setup_environment` to add additional tools and libraries.

### install grcov

```shell
cargo install grcov
```

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
