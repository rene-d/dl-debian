# dl-debian

Scripts for running an offline Debian mirror.

## Mirroring

The [mirror.sh](mirror.sh) script uses [debmirror](https://linux.die.net/man/1/debmirror) to download all sections of `i386` and `amd64` architectures from [Stretch](https://www.debian.org/releases/stretch/) and [Buster](https://www.debian.org/releases/buster/) distributions.

The mirror will go into `$HOME/data`.

```bash
./mirror.sh [--check]
```

Optionally, the script can sync the `dists` directory then verifies that all files listed in `Packages` and `Sources` have been downloaded with [verif.py](verif.py) script.

## Using the mirror

[nginx](https://www.nginx.com), [Apache](https://httpd.apache.org), [lighttpd](https://www.lighttpd.net), or event `python3 -mhttp.server` can serve files.
