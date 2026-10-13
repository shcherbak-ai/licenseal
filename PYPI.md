# licenseal

Check dependency-license compatibility against the license your project ships under. Scan Python, JavaScript/TypeScript, Rust, Go, Java/JVM, .NET, PHP, Ruby, Elixir/Erlang, and R projects with one CLI.

```bash
uvx licenseal check
```

- Scans transitive dependencies by default, using lockfiles when available. Development dependencies are included with `--dev`.
- Reads manifests and public registry metadata without installing dependencies, running builds, or downloading package archives.
- Reads the project's license from a manifest in the scanned directory, and assumes `Proprietary` when none declares one.
- Fails by default on unreviewed violations, warnings, and unknown licenses, and on anything it could not read, including a manifest without a lockfile (`--no-require-lockfile` accepts versions estimated from the registry).
- Produces terminal, Markdown, and JSON reports, with checked-in manual review records.

For a persistent installation:

```bash
uv tool install licenseal
```

See the [documentation](https://licenseal.shcherbak.ai/) for options, CI integration, and each ecosystem, the [security model](https://licenseal.shcherbak.ai/security/) for the input and network boundaries, and the [repository](https://github.com/shcherbak-ai/licenseal#readme) for the source.

Licensed under [Apache-2.0](https://github.com/shcherbak-ai/licenseal/blob/main/LICENSE). License classification is a technical aid, not legal advice.
