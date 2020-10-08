# Running the examples

To run the examples, you first need to create the `NPK`s for the architecture you plan to run them on.

In the toplevel rakefile we provide a task to build the `NPK`s for different target architectures.

Once you have the `*.npk` packages in your registry, you can start the northstar process and configure this registry.

When the northstar runtime is up and running, you can issue control commands to it via a socket.
We provide an utility that can easily communicate with the northstar daemon and send it commands (`nstar`)

Build `nstar` by running `cargo install --path nstar`.

After that just start `nstar` (found in `./target/release/nstar`). It is an interactive client that offers this help:

``` shell
➜  northstar git:(master) ✗ ./target/release/nstar
>> help
 Command   | Subcommands | Help
 help      |             | Display help text
 list      |             | List all loaded images
 ps        |             | List running instances
 shutdown  |             | Stop the north runtime
 settings  |             | Dump north configuration
 start     |             | PATTERN Start containers matching PATTERN e.g 'start hello*'. Omit PATTERN to start all containers
 stop      |             | PATTERN Stop all containers matching PATTERN. Omit PATTERN to stop all running containers
 uninstall |             | PATTERN Unmount and remove all containers matching PATTERN
 update    |             | Run update with provided ressources
 versions  |             | Version list of installed applicationsDuration 641ns
>>
```
