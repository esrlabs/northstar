## Rust environment

Developing with northstar requires some tooling. The first starting point is to install `Rust` via `https://rustup.rs`.

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

When `ruby` is installed on the system, run `rake setup` to add additional tools and libraries.

## Checks & Tests

To execute all `tests` and `checks` that will also be executed in the CI:

```shell
rake check
```

## Unit tests code coverage

### Install grcov

```shell
cargo install grcov
```

Generate a report of the unit tests code coverage with the following command:

```shell
rake coverage
```

## Tests

Integration tests can be run on `Linux` targets:

```shell
./examples/build_examples.sh
cargo test -p northstar_tests -- --test-threads 1 --ignored
```

These tests evaluate the functionality at the user level. Typically, each test
start a `northstar` runtime in which containers are started, stopped and certain
conditions are asserted. As a consequence of this, `sudo` privileges are
required for execution.

The integration tests are kept separated in the `northstar_tests` crate under
the `northstar_tests/tests` directory. Each test is defined using a custom
`test!` macro. Inside each test, there is commonly a single instance of
`northnorthstar_tests::Runtime`. This type acts as a proxy to the `northstar`
runtime. It offers a limited set of `API` requests with the possibility to
perform assertions on them.

To add a new test, extend the `northstar_tests/tests/integration_tests.rs` file
with a new instance of the `test!` macro, like for example:

```rust
// northstar_tests/tests/integration_tests.rs
// ...

test!(my_new_test, {
    let mut runtime = Runtime::launch().await?;

    runtime.install("my/test/container.npk").expect_ok()?;
    northstar.start("my_test_container").expect_ok()?;

    // assertions on my container IO

    northstar.stop("my_test_container").expect_ok()?;

    runtime.shutdown()
});
```
