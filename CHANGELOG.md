
# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Split runtime into lib and bin modules
- Move api and manifest to north crate
- Mounts ands resources are now specified together inside  the manifest's
  `mounts:` section. The format of the entries also changes.

  ```yaml
    mounts:
      - source: /lib
        target: /lib
        type: bind
      - source: /lib64
        target: /lib64
        type: bind
      - target: /data
        type: data
      - target: /data_rw
        type: data
        flags:
          - rw

    resources:
      - name: hello
        version: 0.1.2
        dir: /hello
        mountpoint: /message
  ```

  becomes:

  ```yaml
    mounts:
      /lib:
        host: /lib
      /lib64:
        host: /lib64
      /data: {}
      /data_rw:
        flags:
          - rw
      /message:
        resource: hello:0.1.2/hello
  ```

## [0.2.0] - 2020-09-28
### Added
- JSON based API that allows to control the north runtime remotely
- New command line client based on json api (nstar)
- rake-task to do a debug build

### Changed
- Usage of json api in console
- dcon -> nstar: We now use the uniqu id for start/stop/uninstall
  (no regex is constructed anymore)
  makes it unambigous which component is meant

### Removed
- Old dcon client
