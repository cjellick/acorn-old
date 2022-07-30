---
title: Networking
---

Applications will need to be reachable by their users. This can be users on the internet, within the organization, and other application teams. When deploying the Acorn app, there is a lot of flexibility.

### Default

By default Acorn apps run with the Acorn author's default configuration.

`acorn run registry.example.com/myorg/image`

### Selectively publish ports

When publishing specific ports, the operator will need to specify all ports to be published. Any unspecified port will default to internal and be unreachable outside of the Acorn.

To learn which ports are available to publish, look at the image help.

`acorn run registry.example.com/myorg/image --help`

There will be a line `Ports: ...` that outlines the ports. To expose the port run

`acorn run -p 3306:3306/tcp registry.example.com/myorg/image`

### Publish HTTP Ports

To publish an HTTP port on a domain name, you use the `-p` option on the run subcommand.

`acorn run -p my-app.example.com:frontend registry.example.com/myorg/image`

<!-- TODO: add --publish-all -->
<!-- TODO: what about --expose? -->