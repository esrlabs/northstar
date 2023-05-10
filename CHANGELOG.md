# 0.8.1 (Unreleased)

This release lowers the MSRV of Northstar to 1.65.0. ([#975]).

## Changed

- proj: Lower MSRV to 1.65.0 ([#975])

[#975]: https://github.com/esrlabs/northstar/pull/975

# 0.8.0 (May 10th, 2023)

This release bumps the MSRV of Northstar to 1.66.1. ([#884]).

## Added

- doc: Add changelog ([#972])
- proj: Add dependabot for gh actions ([#963])
- runtime: Android init like socket configuration for containers ([#932])
- runtime: Scheduling policy by manifest ([#970])
- tests: Patch manifest of prebuilt container (`northstar_tests::containers::with_manifest`)
  ([#973])
- ci: Add [cargo-hack](https://github.com/taiki-e/cargo-hack) ([#974])

## Changed

- runtime: Refactor debug commands ([#948])
- doc: Remove example configuration from readme. ([#946])
- all: Remove unused dependencies ([#949])
- tests: Replace nasty global mut with local variable ([#950])
- runtime: Split console configuration into runtime and container parts ([#962])
- runtime: Synchronize logs ([#947])
- doc: Add md lint exceptions MD024 and MD025 ([#972])

## Fixed

- runtime: Avoid reimport error of strum::EnumCount ([#931])

## Dependencies

- deps: Bump android-logd-logger to 0.4.1 ([#960])
- deps: Bump anyhow to 1.0.71 ([#959])
- deps: Bump async-trait to 0.1.68 ([#937])
- deps: Bump bindgen to 0.65.1 ([#957])
- deps: Bump bitflags to 2.2.1 ([#967])
- deps: Bump clap to 4.2.7 ([#968])
- deps: Bump clap_complete to 4.2.1 ([#956])
- deps: Bump github/codeql-action to 2 ([#964])
- deps: Bump human_bytes to 0.4.2 ([#953])
- deps: Bump proc-macro2 to 1.0.56 ([#944])
- deps: Bump regex to 1.7.3 ([#934])
- deps: Bump serde to 1.0.162 ([#969])
- deps: Bump serde_json to 1.0.95 ([#935])
- deps: Bump serde_with to 3.0.0 ([#966])
- deps: Bump syn to 2.0.12 ([#938])
- deps: Bump tempfile to 3.5.0 ([#939])
- deps: Bump tokio to 1.28.0 ([#958])
- deps: Bump tokio-stream to 0.1.14 ([#961])
- deps: Bump tokio-util to 0.7.8 ([#965])
- deps: Bump uuid to 1.3.2 ([#955])
- deps: Bump zeroize to 1.6.0 ([#941])

[#931]: https://github.com/esrlabs/northstar/pull/931
[#932]: https://github.com/esrlabs/northstar/pull/932
[#934]: https://github.com/esrlabs/northstar/pull/934
[#935]: https://github.com/esrlabs/northstar/pull/935
[#937]: https://github.com/esrlabs/northstar/pull/937
[#938]: https://github.com/esrlabs/northstar/pull/938
[#939]: https://github.com/esrlabs/northstar/pull/939
[#941]: https://github.com/esrlabs/northstar/pull/941
[#944]: https://github.com/esrlabs/northstar/pull/944
[#946]: https://github.com/esrlabs/northstar/pull/946
[#947]: https://github.com/esrlabs/northstar/pull/947
[#948]: https://github.com/esrlabs/northstar/pull/948
[#949]: https://github.com/esrlabs/northstar/pull/949
[#950]: https://github.com/esrlabs/northstar/pull/950
[#953]: https://github.com/esrlabs/northstar/pull/953
[#955]: https://github.com/esrlabs/northstar/pull/955
[#956]: https://github.com/esrlabs/northstar/pull/956
[#957]: https://github.com/esrlabs/northstar/pull/957
[#958]: https://github.com/esrlabs/northstar/pull/958
[#959]: https://github.com/esrlabs/northstar/pull/959
[#960]: https://github.com/esrlabs/northstar/pull/960
[#961]: https://github.com/esrlabs/northstar/pull/961
[#962]: https://github.com/esrlabs/northstar/pull/962
[#963]: https://github.com/esrlabs/northstar/pull/963
[#964]: https://github.com/esrlabs/northstar/pull/964
[#965]: https://github.com/esrlabs/northstar/pull/965
[#966]: https://github.com/esrlabs/northstar/pull/966
[#967]: https://github.com/esrlabs/northstar/pull/967
[#968]: https://github.com/esrlabs/northstar/pull/968
[#969]: https://github.com/esrlabs/northstar/pull/969
[#970]: https://github.com/esrlabs/northstar/pull/970
[#972]: https://github.com/esrlabs/northstar/pull/972
[#973]: https://github.com/esrlabs/northstar/pull/973
[#974]: https://github.com/esrlabs/northstar/pull/974

# 0.7.1 (March 21th, 2023)

## Added

- examples: Android: add acct cgroup to android init script ([#876])
- runtime: Configure cgroup parent group ([#881])
- npk: Add cargo-npk subcommand ([#884])

## Changed

- proj: Merge Dockerfiles into Cross.toml ([#878])
- runtime: Refactor module layout of runtime ([#877])
- runtime: Remove devicemapper crate dependency ([#929])
- examples: Remove explicit linker set for target aarch64-linux-android ([#894])
- proj: Remove explicit release profile ([#882])
- ci: Use mold in GH actions for tests and tools ([#875])
- runtime: Remove TryFrom<&Container> for Container and fix bound ([#873])

## Fixed

- chore: Fix clippy warnings for clippy 1.63.0 ([#914])
- runtime: Fix error log about resource directories. ([#927])

## Dependencies

- deps: Bump async-stream to 0.3.4 ([#923])
- deps: Bump base64 to 0.21.0 ([#924])
- deps: Bump bindgen to 0.63.0 ([#895])
- deps: Bump caps to to 0.5.5 ([#887])
- deps: Bump cgroups-rs to 0.3.0 ([#912])
- deps: Bump env_logger to 0.10.0 ([#892])
- deps: Bump memoffset to 0.8.0 ([#905])
- deps: Bump nix to 0.26.2 ([#922])
- deps: Bump prettytable-rs 0.10.0 ([#896])
- deps: Bump proc-macro2  1.0.51 ([#916])
- deps: Bump regex 1.7.1 ([#906])
- deps: Bump rlimit 0.9.0 ([#898])
- deps: Bump serde 1.0.148 ([#885])
- deps: Bump serde_with to 2.1.0 ([#891])
- deps: Bump serde_yaml to 0.9.17 ([#911])
- deps: Bump syn to 1.0.107 ([#897])
- deps: Bump tokio to 1.25.0 ([#919])
- deps: Bump uuid to 1.3.0 ([#910])
- deps: Bump zip to 0.6.4 ([#918])

[#873]: https://github.com/esrlabs/northstar/pull/873
[#875]: https://github.com/esrlabs/northstar/pull/875
[#876]: https://github.com/esrlabs/northstar/pull/876
[#877]: https://github.com/esrlabs/northstar/pull/877
[#878]: https://github.com/esrlabs/northstar/pull/878
[#881]: https://github.com/esrlabs/northstar/pull/881
[#884]: https://github.com/esrlabs/northstar/pull/884
[#885]: https://github.com/esrlabs/northstar/pull/885
[#887]: https://github.com/esrlabs/northstar/pull/887
[#891]: https://github.com/esrlabs/northstar/pull/891
[#892]: https://github.com/esrlabs/northstar/pull/892
[#894]: https://github.com/esrlabs/northstar/pull/894
[#895]: https://github.com/esrlabs/northstar/pull/895
[#896]: https://github.com/esrlabs/northstar/pull/896
[#897]: https://github.com/esrlabs/northstar/pull/897
[#898]: https://github.com/esrlabs/northstar/pull/898
[#905]: https://github.com/esrlabs/northstar/pull/905
[#906]: https://github.com/esrlabs/northstar/pull/906
[#910]: https://github.com/esrlabs/northstar/pull/910
[#911]: https://github.com/esrlabs/northstar/pull/911
[#912]: https://github.com/esrlabs/northstar/pull/912
[#914]: https://github.com/esrlabs/northstar/pull/914
[#916]: https://github.com/esrlabs/northstar/pull/916
[#918]: https://github.com/esrlabs/northstar/pull/918
[#919]: https://github.com/esrlabs/northstar/pull/919
[#922]: https://github.com/esrlabs/northstar/pull/922
[#923]: https://github.com/esrlabs/northstar/pull/923
[#924]: https://github.com/esrlabs/northstar/pull/924
[#927]: https://github.com/esrlabs/northstar/pull/927
[#929]: https://github.com/esrlabs/northstar/pull/929
