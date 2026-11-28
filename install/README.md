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
- `--require-network-isolation`: fail the installation with a non-zero exit code if the active `IPAddressDeny` self-test detects that cgroup BPF filtering is not enforced (or cannot run).

The installer is idempotent: re-running it updates the binary, units (`tegrad.service`, `tegrad-update.path`, `tegrad-update.service`, `tegrad-server@.service`, `tegrad-server@.socket`), polkit rule, and network drop-in without resetting `/var/lib/tegrad`.

## Signed auto-updates

`tegrad` checks its configured release channel (`stable`, `beta`, or `nightly`) and stages verified updates into `/var/lib/tegrad/update` (`0700`, owned by `tegrad`). The agent itself never has write access to `/opt/tegrad/bin`. When `/var/lib/tegrad/update/ready.json` appears, `tegrad-update.path` activates the sandboxed `tegrad-update.service`, which runs `/opt/tegrad/bin/tegrad apply-update` as `root`:

1. Copies the staged binary and manifest into a private root-owned temporary directory inside `/opt/tegrad/bin`.
2. Re-verifies the Ed25519 manifest signature and SHA-256 hash on the root-owned copy (preventing TOCTOU tampering).
3. Backs up the existing binary to `/opt/tegrad/bin/tegrad.prev`, swaps the new binary atomically, restarts `tegrad.service`, and automatically rolls back if the service fails to become active.

### Replacing the release signing key (before public release)

Development builds embed a well-known test public key (`TEST_RELEASE_PUBLIC_KEY_BASE64URL`). Auto-update, `verify-update`, and `apply-update` fail closed (`placeholder_release_key`) on test-key builds unless `TEGRAD_ALLOW_TEST_RELEASE_KEY=1` is set in the environment, and the release workflow blocks publishing with the test key.

To switch to the production offline Ed25519 release key:

1. Generate a 32-byte Ed25519 seed offline and store its base64url encoding in the `RELEASE_SIGNING_KEY` GitHub Actions secret.
2. Replace `RELEASE_PUBLIC_KEY_BASE64URL` in `src/update/release-key.ts` with the corresponding base64url public key (removing the `TODO(release-key)` comment).
3. Replace `RELEASE_PUBLIC_KEY_PEM` in `install/install.sh` with the matching Ed25519 SPKI PEM (you can format it with `ed25519PublicKeyToPem`).
4. Run `bun run test` to verify `install/install.sh` and `src/update/release-key.ts` match.

After installation, link the agent and verify the setup:

```sh
tegrad link
tegrad doctor
```

## Network isolation and LAN access

By default, `/etc/systemd/system/tegrad-server@.service.d/10-network.conf` denies private, link-local, CGNAT, and loopback address ranges (`IPAddressDeny`) on `tegrad-server@.service`, and only allows private/loopback DNS resolvers detected on the host.

- **Active self-test**: at the end of installation, `install.sh` opens a temporary local TCP listener on `127.0.0.1` and runs a transient `systemd-run` unit with `IPAddressDeny=any` to confirm the kernel enforces cgroup BPF IP filtering. On LXC containers or kernels without `CONFIG_CGROUP_BPF`, `IPAddressDeny` is silently ignored by systemd; `install.sh` prints a warning to stderr (or fails if `--require-network-isolation` was passed) and records the result in `/var/lib/tegrad/network-isolation.json` (`0600`, owned by `tegrad`).
- **`tegrad doctor` check**: `tegrad doctor` reads `/var/lib/tegrad/network-isolation.json` without root and reports `network_isolation` as `OK` (verified within the last 30 days), `FALHA` (not effective), or `INCONCLUSIVO` (never tested, skipped, or older than 30 days). Re-run `install.sh` to refresh the check.
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
