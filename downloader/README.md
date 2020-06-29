# Example North downloader

This downloader works together with northstar and takes over the part of fetching the needed versions from a remote server.

## Get Version Info from North

When the `north-daemon` is running, downloader connects to it and gets a list of currently installed versions.

## Download from backend

Next it will fetch the available versions from a remote repository. These versions are kept as a yaml file on the remote server and look like this:

```yml
---
- name: memeater
version: 0.1.0
file: memeater-aarch64-linux-android-0.1.0.tgz
- name: cpueater1024
version: 0.1.0
file: cpueater1024-aarch64-linux-android-0.1.0.tgz
- name: crashing
version: 0.1.0
file: crashing-aarch64-linux-android-0.1.0.tgz
```

### Find out versions to update

Once the downloader has both the version info from the `north-daemon` and the remote server, it checks which applications have an update on the server and fetches those into the `update-directory`.

1. download `package_versions.yaml` from backend

    ---
    - name: hello
      version: 3.2.0
      file: hello-x86_64-apple-darwin-3.2.0.tgz
    - ...

2. compare local versions from local registry

    │   └── registry
    │       ├── hello-x86_64-apple-darwin-3.0.1.tgz
    │       ├── ...

3. if we found a package with a newer version, download it to `north_downloads` and check signature

    ├── north_downloads
    │   ├── hello-x86_64-apple-darwin-3.2.0.tgz
    │   ├── hello-x86_64-apple-darwin-3.2.0.tgz.asc
    │   └── hello-x86_64-apple-darwin-3.2.0.tgz.checksum_algo

## Triggering the North update

After that it contacts the `north-daemon` and tells it to update using the `update-directory`.
