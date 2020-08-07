# Northstar Common Functionality

## Northstar Runtime API

Northstar is a container runtime, not an application modle. It is highly application specific how components running in different northstar containers should behave.
Still, the runtime is in charge of starting/stoping/controlling the containers at runtime.

To make this functionality available to outside components, we offer a socket based API. Applications that want to control the runtime can issues commands to the runtime and receive status information in response.

Requests to the runtime and responses from the runtime are encoded as json objects.

### List installed packages

**REQUEST**:

```.json
{
  "request":"ListContainers",
  "request_id":3
}
```

**RESPONSE**:

```.json
{
  "response":{
    "ContainerList":[
      {
        "name":"cpueater",
        "version":"0.0.1",
        "pid":null,
        "container_type":"APP"
      },
      {
        "name":"crashing",
        "version":"0.0.1",
        "pid":null,
        "container_type":"APP"
      },
      ...
    ]
  },
  "response_id":3
}
```

### Start a container

**REQUEST**:

```.json
{
  "request":{
    "StartContainer":"hello"
  },
  "request_id":4
}
```

**RESPONSE**:

```.json
{
  "response":{
    "StartedList":[
      {
        "id":"hello",
        "success":"Ok",
        "duration_in_ns":1845816
      }
    ]
  },
  "response_id":4
}
```

### List running containers

**REQUEST**:

```.json
{
  "request":{
    "ListProcesses":"hello"
  },
  "request_id":5
}
```

**RESPONSE**:

```.json
{
  "response":{
    "ProcessList":[
      {
        "name":"hello",
        "version":"0.0.2",
        "pid":330106,
        "mem_info":{
          "size":3043328,
          "resident":368640,
          "shared":299008,
          "text":204800,
          "data":364544
        },
        "uptime_in_us":2354498
      }
    ]
  },
  "response_id":5
}
```

### Stop one or all running containers

**REQUEST**:

```.json
{
  "request":{
    "StopContainer":null
  },
  "request_id":6
}
```

**RESPONSE**:

```.json
{
  "response":{
    "StoppedList":[
      {
        "id":"hello",
        "success":"Ok",
        "duration_in_ns":732681
      }
    ]
  },
  "response_id":6
}
```

### Uninstall a package

**REQUEST**:

```.json
{
  "request":{
    "UninstallContainer":"hello"
  },
  "request_id":7
}
```

**RESPONSE**:

```.json
{
  "response":{
    "Uninstall":[
      {
        "name":"hello",
        "uninstalled_version":"0.0.2",
        "result":"OK"
      }
    ]
  },
  "response_id":7
}
```

### List installed packages with versions

**REQUEST**:

```.json
{
  "request": "GetVersions",
  "request_id":9
}
```

**RESPONSE**:

```.json
{
  "response":{
    "Versions":[
      {
        "name":"hello_message",
        "version":"0.1.2",
        "architecture":"x86_64-unknown-linux-gnu"
      },
      {
        "name":"cpueater",
        "version":"0.0.1",
        "architecture":"x86_64-unknown-linux-gnu"
      },
      ...
    ]
  },
  "response_id":9
}
```

### Shutdown the north runtime

**REQUEST**:

```.json
{
  "request": "Shutdown",
  "request_id":10
}
```

**RESPONSE**:

```.json
{
  "response":{
    "StoppedList":[]
  },
  "response_id":10
}
```

To see an example of how to use the json-api, take a look at the `nstar` implementation.
