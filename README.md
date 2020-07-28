<img src="doc/images/box.png" class="inline" width=100/>

# Minimal and secure containers for edge computing

Northstar is an open source technology for securly running self sufficient sandboxed containers in a ressource constraint environment. It offers a runtime that monitors isolated containers. In addition it provides tooling to create and manage those containers.

At its core, Northstar makes extensive use of sandboxing to isolate applications from the rest of the system while at the same time orchestrating efficient startup and secure update scenarios. Such applications run inside Northstar-containers and only rely on system services and ressource containers provided by the Northstar-platform. Similar sandboxing techniques were selected and used as are found in Docker and other containerization approaches to reach maximum isolation. To build the most efficient and robust solution, Northstar is completely developed in Rust, a language designed to afford the performance of C++ while at the same time guaranteeing memory safety.

## Northstar Status

Northstar is still under heavy development. While we already have implemented most of the basic building blocks, Northstar is not production ready.

So far we tested Northstar on

* 32-bit ARM
* 64-bit ARM
* x86_64

### Everything that is checked is implemented

- [x] On-the-fly verification of container content
- [x] Process supervision: memory control
- [x] Process supervision: cpu control
- [x] Limiting system calls (whitelist)
- [x] Shared resource containers
- [ ] User-support of configuring and managing network-namespaces
- [ ] Dedicated UID for each container
- [ ] Management API of the runtime [#64](https://github.com/esrlabs/northstar/issues/64)
- [ ] Signature Check of NPK at install time [#54](https://github.com/esrlabs/northstar/issues/54)
- [ ] PID Namespaces [#51](https://github.com/esrlabs/northstar/issues/51)

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

## How do Northstar images/containers work?

### Northstar Packages (NPK)

Similar as in the docker world, a Northstar **image** is the unit that gets deployed into a system. Once the runtime starts, all images in the registry will be loaded into **containers**. Containers are the entities that are managed by the Northstar runtime.

Images are packaged as **Northstar Packages** or **NPK**s. At it's outer layer, such an NPK is just a plain zip-archive. The content looks like this:

<br/><img src="doc/images/npk.png" class="inline" width=400/>

The `manifest.yaml` contains essential information about the package like id and version.

This is what a typical manifest looks like (taken from the examples)

```yaml
# Use the ferris interpreter from the resouce listed below
name: ferris_says_hello
version: 0.0.1
init: /bin/ferris
# Pass the filename with the hello message
args:
  - /message/hello
resources:
  - name: ferris
    version: 0.0.2
    dir: /
    mountpoint: /bin
  - name: hello_message
    version: 0.1.2
    dir: /
    mountpoint: /message
```

The `signature.yaml` contains signatures that are used to verify the package and the included file system. It is automatically created by the tooling.

Now the actual content is the `fs.img` file, which is a squashfs filesystem image that contains the actual content of what the user puts into a container.
The image is packed a an zip archive with zero compression. Compression takes place via the SquashFS
functionality. Not compression the outer package allows Northstar to access the content without
unpacking the image to disk.

### Installing a package

<br/><img src="doc/images/mounting.png" class="inline" width=600/>

A file system image of a Nortstar package is attached to a loopback device. The loopback device is used to setup a verity check block device with the dm-verity module. The verity hashes are appended to the file system image. The verity block device is finally mounted and used in operation.

## Creating Northstar Packages

In order to use an application in a northstar container, it needs to be packaged in a northstar package (NPK). For that we currently provide a ruby script (`tooling.rb`) that can create such containers.

An example of how to use it can be found in the top level `rakefile.rb`. This is the function that needs to be called:

```ruby
# Create an NPK package
# Params:
# +arch+:: achitecture for which this package will be built
#          e.g. aarch64-linux-android, aarch64-unknown-linux-gnu, x86_64-unknown-linux-gnu
# +arch_dir+:: directory where the architecture specific content is to be found
# +src_dir+:: directory where non-architecture specific content is found
# +out_dir+:: where the npk should be packaged to (usually the registry directory)
def create_arch_package(arch, arch_dir, src_dir, out_dir, pack_config)
```

Once the packages are created, they are stored in a registry directory. This registry needs to be configured later when starting the northstar runtime.

We are currently working on a [more comfortable and user friendly tool.](https://github.com/esrlabs/northstar/issues/7)

## Configuring and Running Northstar

### System Requirements

Northstar is designed to be running a modern linux environment. When the kernel has the required features, it is basically possible to use northstar.
Required Kernel features are:

* device-mapper with dm-verity
* SquashFS
* loopback-blockdevice-support
* PID namespaces
* mount namespaces

### Starting Northstar

The Northstar runtime is an executable and usually run as a daemon started by your system manager of
choice. The configuration of the runtime is done with a `*.toml` configuration file.
Here is an example:

```toml
[directories]
container_dirs= [ "target/north/registry" ]
run_dir = "target/north/run"
data_dir = "target/north/data"

[cgroups]
memory = "/sys/fs/cgroup/memory/north"
cpu = "/sys/fs/cgroup/cpu/north"

[devices]
unshare_root = "/"
unshare_fstype = "ext4"
loop_control = "/dev/loop-control"
loop_dev = "/dev/loop"
device_mapper = "/dev/mapper/control"
device_mapper_dev = "/dev/dm-"
```

The `[directories]` section just tells north what directories to use.

* **`container_dir`** -- list of directories where to find the `*.npk` packages for the correct architecture
  are to be found
* **`run_dir`** -- where the container content will be mounted
* **`data_dir`** -- In data_dir a directory for each container is created. data_dir is not directly exposed (currently only for testing purposes - see global_data_dir settings which will be removed.

The [`cgroups`] optionally configures northstar applications CGroups settings.
Both `memory` and `cpu` will tell northstar where to mount the cgroup hierarchies.

`[devices]`-section:

* **`unshare_root`** -- Set to mountpoint of the fs containing run_dir. The runtime needs this directory to set the mount propagation to MS_PRIVATE.
* **`unshare_fstype`** -- For applying the mount propagation type the fs type is needed.
* **`loop_control`** -- Location of the loopback block device control file
* **`loop_dev`** -- Prefix of preconfigured loopback devices. Usually loopback devices are e.g /dev/block0
* **`device_mapper`** -- Device mapper control file.
* **`device_mapper_dev`** -- Prefix of device mapper mappings.

## Examples

If you want to see how containers can look like, take a look at the examples in the examples directory.
See [our examples README](examples/README.md)

<br/><img src="doc/images/work.png" class="inline" width=100/>

## For Northstar Devs

See [HACKING](HACKING.md) for more on what you might need.
