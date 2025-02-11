# quakenotic
Discord bot for the Quakenotic server

## Dependencies
You need the following packages installed:
    - `discord` python API package if you intend to use the already-provided discord relay,
    - `py-yaml` for configuration files.

## How to use
If you have the packages installed either system-wide or in a virtual environment, don't forget to activate the environment
before you start the program.

You NEED to configure your install with relevant servers, relays and your custom made chat pools. Refer to files in `examples` folder on how to create them.

### Relays
To configure a relay, the following document structure is required: (brackets indicate a custom-named/filled field)
```
{relay name}:
    active: true/false(bool)
    path: {path to file containing relay class}(str)
    classname: {name of relay's class in path}(str)

    args: {arguments passed to class constructor}(list)
    kwargs: {keyword arguments -""-}(dict)

    run:
        args: {arguments passed to class's "run" or "start" method}(list)
        kwargs: {keyword arguments -""-}(dict)
```

You can have as many relays listed in this file as you want. Each relay may be a custom, meaning your own, or stock, if it comes shipped class.
Note: if you plan on adding a keyword that is not of a primitive type, you need to add your own type to `py-yaml`'s settings.

### Servers
To configure a server, the following document structure is required: (brackets indicate a custom-named/filled field)
```
(game name):
    local_addr: unused
    local_port: unused

    protocol:
        name: {protocol's class name}(str)
        path: {class's file path}(str)
        type: tcp/udp/unix (str)

        args: {arguments passed to class constructor}(list)
        kwargs: {keyword arguments -""-}(dict)

        conn:
            args: {arguments passed to asyncio's "create_connection", "create_datagram_endpoint" or "create_unix_connection" functions}(list)
            kwargs: {keyword arguments -""-}(dict)

        servers:
            {server name}:
                active: true/false(bool)
                addr: (str)
                port: (int)
```

You can have as many games listed in the file, and as many servers under them as you want. Each game may use a different, custom, which means your own, or stock, if it comes shipped protocol.

### Chat pools
To configure a server, the following document structure is required: (brackets indicate a custom-named/filled field)
```
{chat pool name}:
    relays:
        {relay name}: {list of intended destinations to forward to, for example discord channel id's}(list)
    servers: {names of servers as listed in sockets.yaml under {server name}}(list)

```

What you supply under a given relay in this chat should be in accordance with how the relay's class works. For example, a discord relay should come with id's (integers) of channels intended to be forwarded information to. You can have as many relays listed in this file under any given chat pool as long as it's defined in `relays.yaml` and its `active` attribute set to `true`.
