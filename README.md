# Spectral

> High-performance secret scanner and API key detector in Go.

Spectral scans filesystems, standard input, and Git commit diffs for credential-like strings. It combines provider-specific regular expressions with placeholder filtering and Shannon-entropy thresholds, and can optionally classify some findings through provider API requests.

## Authorized use

Use Spectral only on repositories, files, credentials, and systems that you own or are explicitly authorized to assess. The `-verify` and `-verified-only` options send detected credentials to provider API endpoints; use them only with the required authorization and with awareness of provider rate limits. Protect generated reports, especially JSON reports, because they include the detected `secret` field.

## Features

- Concurrent directory scanning with a configurable worker count (16 by default).
- Scanning of a directory, a single file, or stdin (`-path -`).
- Git history inspection through added lines in `git log -p -U0` output.
- Provider signature matching with placeholder rejection and Shannon-entropy filtering.
- Optional live verification for OpenAI, Anthropic, Stripe, GitHub, and Hugging Face.
- Terminal output with masked values, JSON output, and SARIF 2.1.0 export.
- Optional exit status 1 when findings remain after scanning (`-fail-on-leak`).
- No external Go modules are declared; the module uses the Go standard library.

## Detection rules

The built-in rules currently cover the following providers and token families:

| Provider | Detection | Live verification |
| --- | --- | --- |
| OpenAI | Project and legacy API keys | Yes |
| Anthropic | Claude API keys | Yes |
| AWS | IAM access key IDs | No |
| Stripe | Live and restricted live secret keys | Yes |
| GitHub | Classic and fine-grained personal access tokens | Yes |
| Hugging Face | User access tokens | Yes |
| Google | AI Studio / Gemini API keys | No |
| Slack | Bot user OAuth tokens | No |
| Groq | Cloud inference API keys | No |
| Pinecone | Vector database API keys | No |
| SendGrid | API authentication tokens | No |
| Resend | Email platform API keys | No |
| Discord | Bot authorization tokens | No |
| Telegram | Bot API tokens | No |
| Postman | API access keys | No |
| Sentry | Authentication user tokens | No |

## Installation

The module declares `go 1.26.5` in `go.mod`. Build from a checkout with a compatible Go toolchain:

```bash
git clone https://github.com/ispectr3/spectral.git
cd spectral
go build -o spectral ./cmd/spectral
```

Or install the command package:

```bash
go install github.com/ispectr3/spectral/cmd/spectral@latest
```

## Usage

### Scan files or stdin

```bash
# Scan the current directory with 16 workers
./spectral -path .

# Scan a path with a custom worker count
./spectral -path /path/to/project -threads 32

# Read content from stdin
cat .env | ./spectral -path -
```

By default, recursive directory scans skip `.git`, `node_modules`, `vendor`, Python virtual environments, `__pycache__`, `dist`, `build`, `target`, `.cache`, `.idea`, and `.vscode`. Files larger than 10 MiB are skipped during directory traversal, and files identified as binary by a NUL byte in the first 512 bytes are not scanned.

### Verify findings

```bash
# Request live checks for supported providers
./spectral -path . -verify

# Keep only findings classified as ACTIVE
./spectral -path . -verified-only
```

### Scan Git history

```bash
# Inspect added lines from commit diffs in a local repository
./spectral -path /path/to/git/repo -git
```

The Git mode requires the `git` command and reads the repository's commit history through `git log -p -U0`.

### Export results

```bash
# Print JSON to stdout
./spectral -path . -json

# Save JSON to a file
./spectral -path . -output findings.json

# Save SARIF 2.1.0 to a file
./spectral -path . -sarif results.sarif
```

Useful command-line options are:

| Option | Default | Purpose |
| --- | --- | --- |
| `-path` | `.` | File, directory, or `-` for stdin |
| `-threads` | `16` | Concurrent scanning workers |
| `-verify` | `false` | Run supported provider API checks |
| `-verified-only` | `false` | Keep only `ACTIVE` findings; also enables verification |
| `-git` | `false` | Scan Git commit history |
| `-json` | `false` | Write findings as JSON to stdout |
| `-output` | empty | Save findings as JSON to the given path |
| `-sarif` | empty | Save a SARIF 2.1.0 report to the given path |
| `-no-banner` | `false` | Suppress the terminal banner |
| `-fail-on-leak` | `false` | Exit with status 1 when findings remain |

## Tests and CI

Run the repository test suite with:

```bash
go test -v -race ./...
```

The GitHub Actions workflow also builds the binary with `go build -v -o spectral ./cmd/spectral` and runs a local self-scan with `./spectral -path . -no-banner`.

## Repository structure

```text
cmd/spectral/       CLI entrypoint and flags
pkg/detector/       Signature rules and match detection
pkg/entropy/        Shannon entropy and placeholder filters
pkg/scanner/        Filesystem, reader, and Git-history scanning
pkg/verifier/       Provider API liveness checks
pkg/output/         Terminal, JSON, and SARIF rendering
```

## Limitations

- Detection is heuristic and limited to the built-in regular expressions; it can produce false positives or miss credentials outside those patterns.
- Placeholder and entropy filters can discard values that look like examples or have low entropy.
- Live verification is implemented for only the five providers listed above and depends on network responses, credentials, and provider rate limits.
- JSON output contains the original detected value in the `secret` field. Store and share reports accordingly; terminal output masks the value and SARIF messages use the masked value.
- Directory traversal applies the built-in ignored-directory and 10 MiB file-size filters. The scanner does not expose a README/configuration option for customizing those rules.
- Git scanning inspects added lines from the available commit patches; it is not a complete guarantee that every historical secret will be found.

## License

MIT License. See [`LICENSE`](LICENSE) for the full text.
