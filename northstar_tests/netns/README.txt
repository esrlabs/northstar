To build the tests from the top level:
cargo run --bin sextant -- pack --dir northstar_tests/netns/container/verify_netns --out target --key examples/keys/northstar.key

Copy the container over to the target and restart north.

The test container will run in a network namespace; to verify that the namespace
is different than the host, it must communicate with an MQTT broker running
on the host. This has the side-effect of also testing that MQTT communication
works from within the namespace.

The test script will launch a mosquitto_sub to wait for the container to
publish the identifier of it's namespace (the inode number). It then
verifies that this namespace identifier is different than the root (default)
namespace on the host.
