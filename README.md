<img src="doc/images/box.png" class="inline" width=100/>

# Minimal and secure containers for edge computing

Northstar is an open source technology for securly running self sufficient sandboxed containers in a ressource constraint environment. It offers a runtime that monitors isolated containers. In addition it provides tooling to create and manage those containers.

At its core, Northstar makes extensive use of sandboxing to isolate applications from the rest of the system while at the same time orchestrating efficient startup and secure update scenarios. Such applications run inside Northstar-containers and only rely on system services and ressource containers provided by the Northstar-platform. Similar sandboxing techniques were selected and used as are found in Docker and other containerization approaches to reach maximum isolation. To build the most efficient and robust solution, Northstar is completely developed in Rust, a language designed to afford the performance of C++ while at the same time guaranteeing memory safety.

<br/><img src="doc/images/prison.png" class="inline" width=100/>

## Supported Sandboxing features

* limited read/write access: a container can only access it's own data
* restrict memory usage of a container
* restrict CPU usage
* limitation of network communication
* containerized applications can only use whitelisted syscalls

## Integrity features

* secure update of verified packages
* secure boot
* verification on each read access prevents manipulation

<br/><img src="doc/images/work.png" class="inline" width=100/>

## Getting started

Developing with north requires some tooling. A good starting point is installing `Rust` via `https://rustup.rs`.

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
