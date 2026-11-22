# Installing `tegrad` on Linux

`install.sh` sets up `tegrad` as an unprivileged systemd service with isolated Minecraft server units and LAN network isolation enabled by default.

## Requirements

- Linux (`x86_64` or `aarch64`)
- `systemd` running as PID 1
- `polkit` with JavaScript rules support (`/etc/polkit-1/rules.d`)
- `sudo` (or root) for the initial installation

## Install or update

From a release tag (downloads the binary and verifies `SHA256SUMS`):

```sh
./install/install.sh --version v0.1.0
```

From a locally built binary:

```sh
./install/install.sh --binary ./dist/tegrad
```

Optional flags:

- `--api-url https://...`: writes `api_url` to `/var/lib/tegrad/config.json` (otherwise created once with `https://api.tegramc.com` and preserved on updates).
- `--allow-lan <cidr>`: allows a private/LAN CIDR in the server network drop-in (can be repeated).

The installer is idempotent: re-running it updates the binary, units, polkit rule, and network drop-in without resetting `/var/lib/tegrad`.

After installation, link the agent and verify the setup:

```sh
tegrad link
tegrad doctor
```

## Network isolation and LAN access

By default, `/etc/systemd/system/tegrad-server@.service.d/10-network.conf` denies private, link-local, CGNAT, and loopback address ranges (`IPAddressDeny`) on `tegrad-server@.service`, and only allows private/loopback DNS resolvers detected on the host.

- **LAN players are blocked by default**: systemd's `IPAddressDeny` applies to both inbound and outbound traffic on the server's sockets. If players on your local network need to connect directly, pass `--allow-lan <cidr>` (for example `--allow-lan 192.168.1.0/24`).
- **Changing DNS resolvers later**: if the host's DNS configuration changes after installation, re-run `install.sh` (with your previous flags) to regenerate `10-network.conf` and reload systemd.

## Uninstall

Remove services, units, polkit rule, wrapper, and binary while keeping `/var/lib/tegrad`, `/var/lib/tegrad-servers`, and system users:

```sh
./install/install.sh --uninstall
```

Remove everything including data and system users (prompts for `yes` unless `--yes` is passed):

```sh
./install/install.sh --uninstall --purge
```
