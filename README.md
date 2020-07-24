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

## How do Northstar images/containers work?

### Northstar Packages (NPK)

Similar as in the docker world, a Northstar **image** is the unit that gets deployed into a system. Once the runtime starts, all images in the registry will be loaded into **containers**. Containers are the entities that are managed by the Northstar runtime.

Images are packaged as **Northstar Packages** or **NPK**s. At it's outer layer, such an NPK is just a plain zip-archive. The content looks like this:

<br/><img src="doc/images/npk.png" class="inline" width=400/>

The `manifest.yaml` contains essential information about the package like id and version.
The `signature.yaml` contains signatures that are used to verify the package and the included file
system.
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

    create_arch_package

Once the packages are created, they are stored in a registry directory. This registry needs to be configured later when starting the northstar runtime.

We are currently working on a [more comfortable and user friendly tool.](https://github.com/esrlabs/northstar/issues/7)

## Configuring and Running Northstar

### System Requirements

Northstar is designed to be running a modern linux environment. When the kernel has the required features, it is basically possible to use northstar.
Required Kernel features are:

* device-mapper with dm-verity
* Squashfs
* loopback-blockdevice-support
* pid namespaces
* mount namespaces

### Starting Northstar

The Northstar runtime is an executable and usually run as a daemon started by your system manager of
choice. The configuration of the runtime is done with a `*.toml` configuration file.
Here is an example:

```
[directories]
container_dirs= [ "target/north/registry" ]
run_dir = "target/north/run"
data_dir = "target/north/data"

[cgroups] where will cgroups be mounted
cgroups mount-point +
memory = "/sys/fs/cgroup/memory/north" => where will the memory cgroups defined
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
* **`container_dir`** -- this is the directory where the `*.npk` packages for the correct architecture
  are to be found
* **`run_dir`** -- where the container content will be mounted
* **`data_dir`** -- r/w directory for the container

The `[cgroups]` section let's northstar know where the cgroups will be organized.
Both `memory` and `cpu` will tell northstar where to mount the cgroup hierarchies.

## Running the Examples

We include runnable examples in the examples directory.
See [our examples README](examples/README.md)

<br/><img src="doc/images/work.png" class="inline" width=100/>

## For Northstar Devs

See [HACKING](HACKING.md) for more on what you might need.


