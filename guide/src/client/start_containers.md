# Starting containers and notifications

Northstar has a notification system where messages are sent to the clients with
information about events such as:

- Applications starting
- Applications stopping
- Applications installed
- Applications uninstalled
- Exit status of applications
- Shutdown of the runtime
- Applications running out of memory

Here is the `JSON` structure requesting that Northstar start a container.
`CONTAINER_NAME` is the name of the container specified in the manifest that will be started.

```json
{
    "id": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
    "payload": {
        "Request": {
            "Start": CONTAINER_NAME
        }
    }
}
```

In the following snippet, a request is sent to start the `memeater` example
container. After the container is started, we will receive 2 notifications, one signaling the start of the application, and eventually a second one that signals
the termination of the application (after consuming all the memory, as this example is designed to do).

```python
# start memeater container
request = {
    'id': str(uuid.uuid4()),
    'payload': {
        'Request': {
            'Start': "memeater"
        }
    }
}

# Serialize the request, notice the appended new line
request = json.dumps(request) + '\n'

# Encode and send the request
s.send(request.encode('utf-8'))

# Receive the ok response to the request
# {'Response': {'Ok': None}}
response = s.recv(8000)
print(json.loads(response.decode('utf-8')))

# Receive the first notification for the start of the container
# {'Notification': {'ApplicationStarted': ['memeater', '0.0.1']}}
response = s.recv(8000)
print(json.loads(response.decode('utf-8')))

# Receive the notification for the out of memory
# {'Notification': {'OutOfMemory': 'memeater'}}
response = s.recv(8000)
print(json.loads(response.decode('utf-8')))
```

