# Installing and uninstalling containers

Installing containers is a bit trickier. First a request to install a new
container is sent with the target repository and the size of the container `npk`
file in bytes. Then the file is directly copied into the socket. If successful,
an `Ok` response will be received with a notification of the newly installed
container. The following is the `JSON` structure to signal the installation of a
new container:

```json
{
    "id": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
    "payload": {
        "Request": {
            "Install": [REPOSITORY_NAME, NPK_SIZE]
        }
    }
}
```

The `REPOSITORY_NAME` is the identifier of the target repository where to
install the new container (see [repositories](repositories.md)). `NPK_SIZE` is
the size in bytes of the `.npk` file that will be transfered. The request for
uninstalling a container requires the name and version of the container
specified in `CONTAINER_NAME` and `CONTAINER_VERSION` correspondingly.

```json
{
    "id": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
    "payload": {
        "Request": {
            "Uninstall": [CONTAINER_NAME, CONTAINER_VERSION]
        }
    }
}
```

For the following snippet, we can create a dummy container called `foo`. First,
we create a directory layout for he container that looks like this:

```
foo
├── manifest.yaml
└── root
    └── foo
```

The file `foo` inside the `root` is just a "hello world" binary compiled for the
host architecture but any other file works for this example. The content for the
`manifest.yaml` is the following:

```yaml
name: foo
version: 0.0.1
init: /foo
mounts:
    /lib:
        host: /lib
    /lib64:
        host: /lib64
```

Finally, we use `sextant` to pack the container into a `npk` file.

```sh
sextant pack --dir foo --out . --key examples/keys/northstar.key
```

This will produce a file named `foo-0.0.1.npk` in the current directory. Now we
can install and uninstall the container in Northstar as follows:

```python
import os

npk = "foo-0.0.1.npk"
npk_size = os.path.getsize(npk)

# Request to install the container in the "default" repository
request = {
    'id': str(uuid.uuid4()),
    'payload': {
        'Request': {
            'Install': ["default", npk_size]
        }
    }
}

# Serialize
request = json.dumps(request) + '\n'

# Send the request
s.send(request.encode('utf-8'))

# Now we simply copy the file to the socket
with open(npk, 'rb') as f:
    chunk = f.read(4096)
    while chunk:
        s.send(chunk)
        chunk = f.read(4096)

# Receive an ok response
# {'Response': {'Ok': None}}}
response = s.recv(8000)
print(json.loads(response.decode('utf-8')))

# Get application installed notification
# {'Notification': {'Install': ['foo', '0.0.1']}}}
response = s.recv(8000)
print(json.loads(response.decode('utf-8')))

# Uninstall the container
request = {
    'id': str(uuid.uuid4()),
    'payload': {
        'Request': {
            'Uninstall': ["foo", "0.0.1"]
        }
    }
}

# send the request
request = json.dumps(request) + '\n'
s.send(request.encode('utf-8'))

# Receive an ok response
# {'Response': {'Ok': None}}}
response = s.recv(8000)
print(json.loads(response.decode('utf-8')))

# Get application uninstalled notification
# {'Notification': {'Uninstalled': ['foo', '0.0.1']}}}
response = s.recv(8000)
print(json.loads(response.decode('utf-8')))
```
