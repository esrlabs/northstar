# Running the examples

To run the examples, you first need to create the `NPK`s for the architecture you plan to run them on.

To build the examples, you can use the shell-script in the examples folder.

Once you have the `*.npk` packages in your repository, you can start the northstar process and configure this repository.

To build and run the northstar runtime, you can simple execute a `cargo run` which will start the
runtime.

When the northstar runtime is up and running, you can issue control commands to it via a socket.
We provide an utility that can easily communicate with the northstar daemon and send it commands (`nstar`)

Build `nstar` by running `cargo install --path nstar`.

After that just start `nstar` (found in `./target/release/nstar`). It is an interactive client that offers this help:

``` shell
➜  northstar git:(master) ✗ ./target/release/nstar
>> help

containers:     List installed containers
shutdown:       Stop the northstar runtime
start <name>:   Start application
stop <name>:    Stop application
install <file>: Install/Update npk
uninstall <id>: Unstall npk
```
