# Contributing

Thanks for helping improve `tegrad`.

## Setup

Requires [Bun](https://bun.sh) 1.3 or newer.

```bash
bun install
bun run lint
bun run typecheck
bun run test
```

All three must pass before a pull request is merged.

## Branches and pull requests

- `main` holds stable releases. `develop` is the integration branch.
- Branch from `develop` as `feat/<name>` or `fix/<name>` and open the pull request against `develop`.
- Use conventional commit subjects: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`.
- Describe the behavior change and how you verified it.
- Read [AGENTS.md](AGENTS.md) for the technical rules of the codebase.

## Security

Never report vulnerabilities in public issues. See [SECURITY.md](SECURITY.md).

## Contributor License Agreement

Contributions require signing the Contributor License Agreement. A bot comments on your first pull request with a link to sign it. By signing, you:

1. certify that you wrote the contribution or have the right to submit it;
2. license your contribution to the project owner, Antônio Miranda, under the project license (AGPL-3.0-only);
3. grant the project owner a perpetual, worldwide, non-exclusive, royalty-free, irrevocable license to use, modify, sublicense and relicense your contribution, including under other license terms.

You keep the copyright to your contribution. Questions: **legal@tegramc.com**.
