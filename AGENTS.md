# Repository Guidelines

`tegrad` is the Tegra Agent: a headless service, compiled to a single binary, that installs and runs Minecraft servers on a Linux machine. It is managed remotely from the Tegra apps. It has no user interface.

## Commands

```bash
bun install
bun run dev          # watch mode
bun run build        # bun build --compile -> dist/tegrad
bun run lint         # Biome + license header check
bun run typecheck    # tsc --noEmit
bun run test         # bun test
```

`lint`, `typecheck` and `test` must pass before a change is done. They run in CI.

## Code rules

- Bun and TypeScript with `strict` on. No `any`; narrow `unknown` instead.
- Every code file starts with these two lines, exactly (the lint step checks it):

  ```ts
  // SPDX-License-Identifier: AGPL-3.0-only
  // Copyright (C) 2026 Antônio Miranda <oi@antmiranda.dev>
  ```
- No `console.*` (lint error). Use the project logger once it exists.
- Tests live next to the code as `*.test.ts` and use `bun:test`.
- Prefer small modules with one responsibility. Validate every external input (network messages, files, environment) at the boundary with a schema.
- Name everything `tegra` / `tegrad`. No other project names in identifiers, packages, protocol fields or text.

## Security invariants

These hold for every change. A change that breaks one needs an explicit discussion first.

- The agent never opens an inbound port. It only makes outbound connections.
- There is no remote shell and no arbitrary command execution. The agent exposes Minecraft operations only. Console input goes to the server process stdin; file operations are confined to the servers directory (resolve and check every path, including symlinks).
- The control server is never trusted to authorize actions. Every command that changes state must carry a signature that is verified against keys the agent already trusts.
- The agent runs without root. Servers run as a separate unprivileged user from the agent and cannot read the agent's keys.
- Servers run natively under systemd with resource limits and sandboxing, not in containers.
- Servers cannot reach private network ranges unless that isolation was turned off by a signed, sensitive action.
- Secrets (keys, tokens) are never logged and are stored with `0600` permissions.

## Protocol

Commands, message envelopes, encryption and schemas live in this repository. Other Tegra components consume them as a git dependency pinned to a release tag (`github:codebyant/tegrad#vX.Y.Z`). Changing a schema is a protocol change: keep it backwards compatible or bump the protocol version.

## Platform

Linux only for now. Keep platform-specific code isolated so it can be tested without a real systemd.

## Commits and pull requests

- Conventional commit subjects: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`.
- Branch from `develop` (`feat/<name>`, `fix/<name>`) and target `develop`. `main` holds stable releases.
- Do not commit secrets or `.env` files.
