# Listing containers

In the same way as [repositories](repositories.md), it is possible to request
the current state of the Northstar containers. Here is the `JSON` structure that
encodes the request for the state of the containers:

```json
{
    "id": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
    "payload": {
        "Request": "Containers"
    }
}
```

The following snippet sends the request for the container information, just as
the previous example requested the repository configuration.

```python
# The request looks like this:
request = {
    'id': str(uuid.uuid4()),
    'payload': {
        'Request': 'Containers'
    }
}

# notice the terminating '\n'
request = json.dumps(request) + '\n'

# send request
s.send(request.encode('utf-8'))

# receive the list of containers
response = s.recv(8000)

# Decode the JSON response
response = json.loads(response.decode('utf-8'))

# The response is a list of containers.
# Each of these containers will come with the following fields:
#   - manifest
#   - process
#   - repository
print(response)
```

The response is quite lengthy and more complex than that of repositories. This
time, we receive a list of objects corresponding to each container. Each
of them provides information about the container's manifest, the repository
where it is installed and possibly information about the system process if it is
currently executing.

Here is an example on how to get a list with names of the available containers:

```python
names = []
for container in response['payload']['Response']['Containers']:
    names.append(container['manifest']['name'])

# e.g. containers: ['cpueater', 'ferris_says_hello', 'seccomp', 'memeater', ...
print(f'containers: {names}')
```

