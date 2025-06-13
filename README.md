# remote-access-tool
[![Build](https://github.com/Serious-senpai/remote-access-tool/actions/workflows/build.yml/badge.svg)](https://github.com/Serious-senpai/remote-access-tool/actions/workflows/build.yml)
[![Lint](https://github.com/Serious-senpai/remote-access-tool/actions/workflows/lint.yml/badge.svg)](https://github.com/Serious-senpai/remote-access-tool/actions/workflows/lint.yml)
[![Test](https://github.com/Serious-senpai/remote-access-tool/actions/workflows/test.yml/badge.svg)](https://github.com/Serious-senpai/remote-access-tool/actions/workflows/test.yml)

Remote access tool for Ubuntu/CentOS

## Setup and running
### Using Docker

Running with [Docker Compose](https://docs.docker.com/compose/) is as easy as:
```bash
$ docker compose up -d
```

This will create 7 containers from 3 images: `ubuntu-server` (1 container), `ubuntu-client` (3 replica containers) and `centos-client` (3 replica containers). You can `exec` into the server to start an interactive session:
```bash
$ docker exec -it ubuntu-server bash
root@ubuntu-server:/# rat-client localhost:22 --admin /host
[*] SSH-2.0-remote-access-tool linux
[*] Host public key is 4B1EEBD7ADEEBBBF2941139385E1AD1EBA25A0713E0932408F27A68A14DE354B
[*] Authentication successful

server>
```

Enter `help` to see a list of available commands.
