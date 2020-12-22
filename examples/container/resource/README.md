# Resource Containers

## Example explained

The containers declared here show the resouce container concept and usage.

### ferris

`ferris` is a ressource container. It contains a single binary called `ferris`.
This binary takes one command line argument. If the argument is a file the file
is used as message. If the argument is not a file the argument itself is used as
message. The message is printed to stdout.

### hello_message

A resouce container that prodides a single text file with some nice greeting.

### ferris_says_hello

This container makes use of the resouce container `ferris` and `hello_message`.
It does not contain any binary and make use of the `ferris` binary mounted to
`/bin`. See the `init` option of `manifest.yaml`.
The argument passed to `ferris` is taken from the resouce container `hello_message`.
The hello message is mounted to `/message`.

## Container get installed by the runtime

When northstar starts up, the images in the repository will get installed.
In our example we use 3 containers:
- `ferris_says_hello`
- `ferris`
- `hello_message`

When a container is installed, we
1.Create a new loop device
2.Attach the image file to this the loop device
3.Create a verity device
4.Mount the file-system that we have in our image on the verity device

### Installation of the `ferris_says_hello` image

```
Installing ferris_says_hello-x86_64-unknown-linux-gnu-0.0.3.npk
  Referencing 2 resources:
  - Resource "ferris (0.0.2)"
  - Resource "hello_message (0.1.2)"
-> Created loop device /dev/loop10
-> Attaching ferris_says_hello-x86_64-unknown-linux-gnu-0.0.3.npk to loopback device at /dev/loop10
-> Creating verity device (name: north_ferris_says_hello_0.0.3)
-> Verity-device used: /dev/dm-1
-> Mount read-only squashfs filesystem on device /dev/dm-1 to this location:target/northstar/run/ferris_says_hello/0.0.3
```

### Installation of the `ferris` image

```
Installing ferris-x86_64-unknown-linux-gnu-0.0.2.npk
Created loop device /dev/loop11
Attaching ferris-x86_64-unknown-linux-gnu-0.0.2.npk to loopback device at /dev/loop11
Creating verity device (name: north_ferris_0.0.2)
Verity-device used: /dev/dm-2
Mount read-only squashfs filesystem on device /dev/dm-2 to this location:target/northstar/run/ferris/0.0.2
```

### Installation of the `hello_message` image

```
Installing hello_message-x86_64-unknown-linux-gnu-0.1.2.npk
Created loop device /dev/loop16
Attaching hello_message-x86_64-unknown-linux-gnu-0.1.2.npk to loopback device at /dev/loop16
Creating verity device (name: north_hello_message_0.1.2)
Verity-device used: /dev/dm-7
Mount read-only squashfs filesystem on device /dev/dm-7 to this location:target/northstar/run/hello_message/0.1.2
```


## Running a container that uses resources

This is what the manifest of the `ferris_says_hello` container looks like. It refers to 2 resource containers.

```
name: ferris_says_hello
version: 0.0.3
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

### Mounts created at container startup

- Mounting from src_dir target/northstar/run/ferris/0.0.2/ to target "/bin"
- Mounting from src_dir target/northstar/run/hello_message/0.1.2/ to target "/message"

From now on, the resources are accessible at the predfined mountpoints.
In the manifest we defined the executable from the `ferris` container as init, so this executable will be started. As argument we will use a file from the second resource container (`hello_message`).

```
executing /bin/ferris
 __________________
< Hello once more! >
 ------------------
        \
         \
            _~^~^~_
        \) /  o o  \ (/
          '_   -   _'
          / '-----' \
```
