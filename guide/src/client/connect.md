# Interation with Northstar

Northstar interacts with clients through a `TCP` socket. The clients exchange
messages with Northstar in the form of requests and responses encoded in
**JSON**. These requests and responses are a direct serialization of the
structures defined in `api/model.rs`.

The first step is to establish a connection with Northstar using a socket.

```python
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("localhost", 4200))
```

Northstar uses the port `4200` by default. Check the configuration (see
`northstar.toml`) for the port used by the target instance.

The messages sent between Northstar and the clients have two fields, `id` and
`payload`.  The `id` field is a generated `UUID` version 4 identifier used to
tag a message exchange.

```json
{
    "id": "UUID",
    "payload": {
        MESSAGE_TYPE: { ... }
    }
}
```

The `MESSAGE_TYPE` can be either `"Request"`, `"Response"`, or `"Notification"`.
Northstar should only send responses and notifications to clients.

