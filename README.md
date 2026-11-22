# tegrad

Tegra Agent: a headless service that installs and runs Minecraft servers on a Linux machine and is managed remotely from the Tegra apps.

> Status: early development. Nothing here is ready for production use.

## Development

Requires [Bun](https://bun.sh) 1.3 or newer.

```bash
bun install
bun run dev        # run with watch mode
bun run build      # compile a single binary to dist/tegrad
bun run lint
bun run typecheck
bun run test
```

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

[AGPL-3.0-only](LICENSE) with the additional terms in [NOTICE](NOTICE). The names and logos are covered by [TRADEMARK.md](TRADEMARK.md).
