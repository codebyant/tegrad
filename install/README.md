# Installing `tegrad` on Linux

`install.sh` sets up `tegrad` as an unprivileged systemd service with isolated Minecraft server units and LAN network isolation enabled by default.

## Requirements

- Linux (`x86_64` or `aarch64`)
- `systemd` running as PID 1
- `polkit` with JavaScript rules support (`/etc/polkit-1/rules.d`)
- `sudo` (or root) for the initial installation
- `openssl` (1.1.1+ / 3.x) and `sha256sum` for verifying Ed25519 release signatures (`SHA256SUMS.sig`) on fresh `--version` installs

## Install or update

From a release tag (downloads the binary, verifies the Ed25519 signature of `SHA256SUMS` via `SHA256SUMS.sig`, and checks the SHA-256 digest before executing or installing):

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

The installer is idempotent: re-running it updates the binary, units (`tegrad.service`, `tegrad-update.path`, `tegrad-update.service`, `tegrad-server@.service`, `tegrad-server@.socket`), polkit rule, and network drop-in without resetting `/var/lib/tegrad`.

## Signed auto-updates

`tegrad` checks its configured release channel (`stable`, `beta`, or `nightly`) and stages verified updates into `/var/lib/tegrad/update` (`0700`, owned by `tegrad`). The agent itself never has write access to `/opt/tegrad/bin`. When `/var/lib/tegrad/update/ready.json` appears, `tegrad-update.path` activates the sandboxed `tegrad-update.service`, which runs `/opt/tegrad/bin/tegrad apply-update` as `root`:

1. Copies the staged binary and manifest into a private root-owned temporary directory inside `/opt/tegrad/bin`.
2. Re-verifies the Ed25519 manifest signature and SHA-256 hash on the root-owned copy (preventing TOCTOU tampering).
3. Backs up the existing binary to `/opt/tegrad/bin/tegrad.prev`, swaps the new binary atomically, restarts `tegrad.service`, and automatically rolls back if the service fails to become active.

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
