# bomly-plugin-govulncheck-analyzer

Go reachability analyzer for [Bomly](https://github.com/bomly-dev/bomly-cli).

It runs [govulncheck](https://pkg.go.dev/golang.org/x/vuln) (as a library) over each Go
module in the scan and annotates the vulnerabilities Bomly already found with
reachability data: whether a vulnerable **symbol** is actually called from your
code (symbol tier) and whether the vulnerable **package** is imported (package
tier). Results are cached on disk under `~/.cache/bomly/analyze/govulncheck/`
(24h TTL), keyed by lockfile fingerprint and Go toolchain version.

> **Safety note:** "unreachable" at any tier means the analysis found no path,
> not that the vulnerability is safe to ignore. Use reachability to prioritize,
> not to dismiss.

## Coverage

- **Ecosystem:** Go (`go.mod` modules)
- **Tiers:** symbol, package
- **Requires:** a Go toolchain on `PATH`

## Embedded in the CLI

The Bomly CLI ships this same analyzer built in — `bomly scan --analyze` uses
it without installing anything. This repository packages the identical module
as a standalone managed plugin, for lite builds and for hosts that load
analyzers as external plugins.

## Install

Download the archive for your platform from the
[releases page](https://github.com/bomly-dev/bomly-plugin-govulncheck-analyzer/releases), then:

```sh
bomly plugin install ./bomly-plugin-govulncheck-analyzer_<version>_<os>_<arch>.tar.gz
bomly plugin enable govulncheck
bomly scan --enrich --analyze
```

## Configuration

The analyzer has no configuration keys. Reachability is switched on with the
host's `--analyze` flag (or the matching config key); caching is on by default
and lives under `~/.cache/bomly/analyze/govulncheck/` with a 24-hour TTL.

## Local development

```sh
go build -o bin/bomly-plugin-govulncheck-analyzer ./cmd/bomly-plugin-govulncheck-analyzer

# Install the dev build into Bomly and scan
bomly plugin install ./bin/bomly-plugin-govulncheck-analyzer --dev
bomly plugin enable govulncheck
bomly scan --enrich --analyze
```

Run the tests (unit + SDK conformance + a real gRPC handshake probe):

```sh
go test ./...
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
