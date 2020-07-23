The containers declared here show the resouce container concept and usage.

ferris
======

`ferris` is a ressource container. It contains a single binary called `ferris`.
This binary takes one command line argument. If the argument is a file the file
is used as message. If the argument is not a file the argument itself is used as
message. The message is printed to stdout.

hello_message
=============

A resouce container that prodides a single text file with some nice greeting.

ferris_says_hello
=================

This container makes use of the resouce container `ferris` and `hello_message`.
It does not contain any binary and make use of the `ferris` binary mounted to
`/bin`. See the `init` option of `manifest.yaml`.
The argument passed to `ferris` is taken from the resouce container `hello_message`.
The hello message is mounted to `/message`.