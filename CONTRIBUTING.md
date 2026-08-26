# Contributing

Contributions are welcome. This is a small, experimental project — keep
changes focused and the diff easy to review.

## License

By contributing, you agree that your contributions are licensed under the
project's [MIT License](LICENSE) (inbound = outbound). No CLA or DCO
sign-off is required.

## Getting set up

```bash
npm install     # installs deps and builds (via the prepare script)
npm run build   # compile TypeScript to dist/
npm run typecheck   # type-check without emitting
```

The source lives in `src/`:

- `src/client/` — the passive API client (auth, encryption, messaging). No
  MCP dependency; importable on its own.
- `src/mcp/` — the MCP server exposing the client as tools.

Please run `npm run build` before opening a pull request so the TypeScript
compiles cleanly. There is no heavyweight test suite; smoke-test the MCP
entry with `node dist/index.js` (it should print `server ready`).

## A note on scope

The project is provided as-is with no support commitment (see
[SUPPORT.md](SUPPORT.md)), and it depends on Oase's internal API, which can
change without notice. For security-sensitive reports, follow
[SECURITY.md](SECURITY.md) — don't use public issues.
