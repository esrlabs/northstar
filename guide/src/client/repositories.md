# Northstar Repositories

Repositories are used to group sets of containers. These are specified in
the Northstar configuration (see `northstar.toml`).

Containers can be added or removed from repositories at runtime by
**installing** and **uninstalling** them.

Repositories specified in the configuration are accessed at the start of
Northstar. Currently it is not possible to add or remove repositories at
runtime.

If a repository specifies a signing key in the configuration, the contents of the
containers are checked with their signature information. Otherwise, this step is
skipped. Notice that for the verification step, it is required that the
underlying system has `verity` support enabled. Containers installed at runtime
to repositories with a signing key will also be verified.

The next block shows the `JSON` structure that represents the request for the
repository configuration. It is important to encode this structure without the
new lines. Also a new line has to be appended to the end of the serialized
string.

```json
{
    "id": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
    "payload": {
        "Request": "Repositories"
    }
}
```

Here is an example that sends a request for the repository configuration:

```python
import uuid
import json

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("localhost", 4200))

# API Request for repository information
request = {
    'id': str(uuid.uuid4()),
    'payload': {
        'Request': 'Repositories'
    }
}

# It is required for the API requests to be terminated with a new line '\n'
request = json.dumps(request) + '\n'

# send the request
s.send(request.encode('utf-8'))

# receive the list of repositories
response = s.recv(8000)

# decode the response
response = json.loads(response.decode('utf-8'))

# The response contains a list with the configured repositories
# Currently, only the filesystem path of every repository is provided
# e.g. {'Response': {'Repositories': {'default': {'dir': 'target/northstar/repository'}}}}
print(response['payload'])
```
