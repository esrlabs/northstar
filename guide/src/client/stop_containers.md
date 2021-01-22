# Stopping containers

Analogous to [starting containers](start_containers.md), this is the `JSON`
structure to stop a container:

```json
{
    "id": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
    "payload": {
        "Request": {
            "Stop": CONTAINER_NAME
        }
    }
}
```

Stopping containers is very similar to starting them. In the following snippet
we start and subsequently stop the `hello` example container.

```python
# Start hello container
request = {
    'id': str(uuid.uuid4()),
    'payload': {
        'Request': {
            'Start': "hello"
        }
    }
}

# Send the request
request = json.dumps(request) + '\n'
s.send(request.encode('utf-8'))

# get ok response
# {'Response': {'Ok': None}}
response = s.recv(8000)
print(json.loads(response.decode('utf-8')))

# get application started notification
# {'Notification': {'ApplicationStarted': ['hello', '0.0.1']}}
response = s.recv(8000)
print(json.loads(response.decode('utf-8')))

# Stop hello container
request = {
    'id': str(uuid.uuid4()),
    'payload': {
        'Request': {
            'Stop': "hello"
        }
    }
}

# Send the request
request = json.dumps(request) + '\n'
s.send(request.encode('utf-8'))

# Get ok response
# {'Response': {'Ok': None}}
response = s.recv(8000)
print(json.loads(response.decode('utf-8')))

# Get notification for the stopped container
# {'Notification': {'ApplicationStopped': ['hello', '0.0.1']}}
response = s.recv(8000)
print(json.loads(response.decode('utf-8')))
```

