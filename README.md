# pytacs_plus

![Python App Build](https://github.com/bubbaandy89/pytacs/actions/workflows/python-app-build.yml/badge.svg)
![Pysa](https://github.com/bubbaandy89/pytacs/actions/workflows/pysa.yml/badge.svg)
![Unit Test Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/bubbaandy89/6c31b32f0703d797bb43ed2dc75ce0c0/raw/covbadge.json)

This is a fork of pytacs originally found [here](https://github.com/kjmancuso/pytacs)


[Github-flavored Markdown](https://guides.github.com/features/mastering-markdown/)

## Development

### Building

* Build package and run coverlay:

```bash
tox -p auto
```

* Attempt to start server:

```python
from pytacs.plugins.base.pyt_tacacs_server import PYTacsTACACSServer
from pytacs.structures.models.client import ClientConfiguration
from pytacs.structures.models.server import ServerConfiguration
client1 = ClientConfiguration(name="test", ip_address="127.0.0.1", secret="secret")
server_config = ServerConfiguration(plugin_name="test_server", listening_address="127.0.0.1", listening_port=49, clients=[client1])
server = PYTacsTACACSServer("server", server_config)
```