## Rust environment

Developing with north requires some tooling. The first starting point is to install `Rust` via `https://rustup.rs`.

### Install Rust nightly toolchain

```shell
rustup toolchain install nightly
```

## Squashfs-support

Install the squashfs-tools (available on most linux-distros and also MacOS).

## Docker

A recent version of `docker` is needed for some of the cross-compilations we are doing.

### Setup ruby env

A recent ruby version is needed for using the tooling and running the rake-scripts within this
project.

When `ruby` is installed on the system, run `rake setup_environment` to add additional tools and libraries.

## Checks & Tests

To execute all `tests` and `checks` that will also be executed in the CI:

```shell
rake check
```

## Unit tests code coverage

### install grcov

```shell
cargo install grcov
```


Generate a report of the unit tests code coverage with the following command:

```shell
rake coverage
```
