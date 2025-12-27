# SSLCHECK

A command-line tool to analyze SSL/TLS configurations using the SSL Labs API, with handling for long-running scans and polling strategies.

## Overview

SSLCHECK is a CLI tool that performs SSL/TLS assessments for one or more hosts by querying the SSL Labs API.
It is designed to be safe, polite to the API, and transparent about scan progress.

The tool supports:

- **Long-running scans** with automated state management.
- **Retry and backoff** strategies for API errors.
- **Randomized polling intervals** to avoid synchronized requests.
- **Sequential multi-host scanning**.
- **Saving raw API responses** for local analysis.
- **Fine-grained control** over assessment parameters.

---

## Features

- ✅ **Multi-host Support:** Scan one or multiple hosts sequentially.
- ✅ **Error Handling:** Graceful handling of API errors (429, 529, retries, timeouts).
- ✅ **Smart Polling:** Randomized polling intervals to stay under the radar.
- ✅ **Steady Mode:** Optional steady polling mode for predictable intervals.
- ✅ **Transparency:** Concise or verbose progress reporting.
- ✅ **Data Export:** Save raw API JSON responses to a file.
- ✅ **API Compliance:** Respects SSL Labs API constraints and recommendations.
- ✅ **Global Timeout:** Configurable safety net for long sessions.

---

## Installation

### From source

```bash
git clone https://github.com/paulrojasg/sslchecker.git
cd sslchecker
go build -o sslchecker
```

## Usage

```bash
sslcheck [options] <host> [host2 host3 ...]
```

> [NOTE]
> Depending on the operating system's settings prepending "./" to the executable may be needed to use the tool:

```bash
./sslcheck host
```

### Examples:

```bash
sslcheck ssllabs.com
sslcheck --verbose ssllabs.com
sslcheck --all on ssllabs.com
sslcheck --output result.json ssllabs.com
sslcheck --steady-polling ssllabs.com
sslcheck --timeout 600 ssllabs.com
```

## Command-line options

Print help information

```bash
sslcheck -h
```

### Input

| Flag           | Description                                                                                  |
| -------------- | -------------------------------------------------------------------------------------------- |
| `--hosts-file` | File path to a host list for scanning. May be combined with hosts supplied as tail arguments |

### Output & verbosity

| Flag              | Description                                             |
| ----------------- | ------------------------------------------------------- |
| `--verbose`       | Enable verbose output (more progress details, metadata) |
| `--output <file>` | Save the raw API JSON response to a file (NDJSON)       |

### Assessment behavior

| Flag                | Description                                                         |
| ------------------- | ------------------------------------------------------------------- |
| `--new`             | Ignore cached results and start a new assessment                    |
| `--cache`           | Retrieve cached results only                                        |
| `--max-age <hours>` | Maximum cache age (requires `--cache`)                              |
| `--all on`          | Return full endpoint information                                    |
| `--all done`        | Return full information only when assessment is complete            |
| `--publish`         | Publish results on SSL Labs public boards                           |
| `--ignore-mismatch` | Proceed even if certificate hostname mismatch                       |
| `--base-url`        | Scanning API's base url (default "https://api.ssllabs.com/api/v2/") |

### Polling & timing

| Flag                  | Description                                             |
| --------------------- | ------------------------------------------------------- |
| `--timeout <seconds>` | Global timeout for all assessments (0 disables timeout) |
| `--steady-polling`    | Disable polling randomization (fixed intervals)         |

By default, polling intervals are randomized (~20%) on top of SSL Labs recommended delays.

### Progress output

#### Non-verbose mode sample log

```bash
[12:41:03] ASSESSMENT PROGRESS: 1/3 COMPLETE
```

#### Verbose mode

Same as previous sample log, plus:

- Per-endpoint progress

- Status details

- Additional diagnostic information

## API usage notes

- The tool respects SSL Labs API rate limits and concurrency rules

- 429 (Too Many Requests) and 529 (Server overloaded) are handled with retries and backoff

- Polling intervals follow SSL Labs recommendations

- Randomized polling helps prevent synchronized request bursts

## Future Work

### Parallel / Asynchronous Assessments

Parallel assessment execution is implemented and under active refinement in the following branch: `feat-parallel-assessments`.

This work focuses on enabling concurrent scans while respecting SSL Labs API constraints and maintaining accurate progress reporting. It adds two new options: `--parallel` to enable parallel mode and `--max-parallel` to specify the maximum number of assessments running at the same time.

Once edge cases around concurrency limits, retry coordination, and shared state handling are fully validated, the feature will be promoted to the stable release.

## License

MIT License
