# pyenv-audit

![pyenv-audit](assets/pyenv-audit_cover.png)

**Security audit tool for all your pyenv Python environments.**

`pyenv-audit` scans every Python version managed by [pyenv](https://github.com/pyenv/pyenv) for packages with known vulnerabilities. It enriches results with severity scores and descriptions from the [OSV](https://osv.dev/) database, groups findings by package, and can generate upgrade commands to fix them.

Built after investigating the [LiteLLM supply chain attack](https://www.reversinglabs.com/blog/teampcp-supply-chain-attack-spreads) (CVE-2026-33634, March 2026), where malicious versions of a widely used PyPI package were silently stealing credentials, SSH keys, and cloud tokens.

![pyenv-audit demo](assets/demo.gif)

## Why this tool?

Managing multiple Python versions with pyenv means having multiple independent sets of installed packages. A vulnerability in one environment is easy to overlook. `pyenv-audit` closes that gap by scanning all environments in a single command, using globally installed tools so it never modifies your pyenv environments.

## Features

- Scans all pyenv versions (or a specific one) without installing anything into them
- Uses a globally installed `pip-audit` via `uv tool` or `pipx` -- zero footprint on target environments
- Enriches each vulnerability with data from the OSV database (description, CVSS score, CWE, references)
- Computes numeric CVSS v3 and v4 scores when the `cvss` Python library is available
- Groups results by package for actionable output ("upgrade X to version Y")
- Filters by severity threshold (default: HIGH+)
- Generates and optionally executes `pip install --upgrade` commands
- Colored terminal output with progress indicators
- Portable: works on macOS (BSD) and Linux (GNU)

## Requirements

**Required:**

| Tool | Purpose | Install |
|------|---------|---------|
| [pip-audit](https://github.com/trailofbits/pip-audit) | Vulnerability scanning | `uv tool install pip-audit` |
| [jq](https://jqlang.github.io/jq/) | JSON processing | `brew install jq` / `apt install jq` |
| [curl](https://curl.se/) | OSV API queries | Usually pre-installed |
| [pyenv](https://github.com/pyenv/pyenv) | Python version management | `brew install pyenv` / [installer](https://github.com/pyenv/pyenv-installer) |

**Optional (recommended):**

| Tool | Purpose | Install |
|------|---------|---------|
| [cvss](https://pypi.org/project/cvss/) | Numeric CVSS score computation | `uv tool install cvss` |

Without `cvss`, the tool still displays CVSS vector strings and the severity label from the OSV database, but cannot compute numeric scores (displayed as N/A).

## Installation

Clone the repository and make the script available in your PATH:

```bash
git clone https://github.com/jeanremacle/pyenv-audit.git
cd pyenv-audit

# Option 1: symlink into your PATH
ln -s "$(pwd)/pyenv-audit.sh" ~/.local/bin/pyenv-audit

# Option 2: copy directly
cp pyenv-audit.sh ~/.local/bin/pyenv-audit
chmod +x ~/.local/bin/pyenv-audit
```

Install the required global tools:

```bash
# Using uv (recommended)
uv tool install pip-audit
uv tool install cvss    # optional, for numeric CVSS scores

# Or using pipx
pipx install pip-audit
pipx install cvss
```

## Usage

```
pyenv-audit.sh [OPTIONS]
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--severity <level>` | Minimum severity to display: `all`, `low`, `moderate`, `high`, `critical` | `high` |
| `--version <ver>` | Audit only the specified pyenv version (e.g., `3.12.6`) | All versions |
| `--fix` | Generate and execute `pip install --upgrade` commands for fixable vulnerabilities | Off |
| `--dry-run` | Show what `--fix` would do without executing | Off |
| `-h`, `--help` | Show usage information | |

### Examples

Audit all pyenv versions, showing HIGH and CRITICAL vulnerabilities:

```bash
pyenv-audit.sh
```

Audit a specific version with all severity levels:

```bash
pyenv-audit.sh --version 3.12.6 --severity all
```

Preview what upgrades would be applied:

```bash
pyenv-audit.sh --version 3.12.6 --fix --dry-run
```

Apply fixes:

```bash
pyenv-audit.sh --version 3.12.6 --fix
```

## Output

The tool produces grouped, color-coded output:

```
======================================================================
  Python 3.12.6
======================================================================
  Scanning 59 packages...
  23 total vulnerability(ies) found. Enriching from OSV...

  Showing 8/23 vulnerabilities (severity >= HIGH)

  --- deepdiff==7.0.1 (1 issue(s)) ---
  Upgrade to: 8.6.1

    HIGH (9.8/10)  CVE-2025-58367
    Aliases: GHSA-...
    DeepDiff is vulnerable to DoS and Remote Code Execution via Delta class pollution
    CWE: CWE-94
    Fix: 8.6.1

  --- pdfminer.six==20231228 (2 issue(s)) ---
  Upgrade to: 20251230

    HIGH (8.8/10)  CVE-2025-64512
    pdfminer.six vulnerable to Arbitrary Code Execution via Crafted PDF Input
    ...
```

## How it works

1. **Discovery** -- Enumerates all Python versions under `$PYENV_ROOT/versions/` (or a specific one with `--version`).

2. **Scanning** -- Runs `pip-audit --path <site-packages> --format json` using the globally installed `pip-audit`. This reads package metadata directly from each environment's `site-packages` directory without installing anything.

3. **Enrichment** -- For each vulnerability found, queries the [OSV API](https://api.osv.dev/) to retrieve severity ratings, CVSS vectors, CWE identifiers, and human-readable descriptions. When the primary CVE ID lacks severity data, the tool automatically tries alias identifiers (GHSA, PYSEC).

4. **Scoring** -- If the `cvss` Python library is installed (via `uv tool`), computes numeric CVSS v3 and v4 base scores from the vector strings. Otherwise, derives severity from the OSV database's own classification.

5. **Filtering** -- Applies the severity threshold (default: HIGH+) and groups remaining vulnerabilities by package.

6. **Fixing** -- In `--fix` mode, collects the highest required fix version per package and executes `pip install --upgrade` via the target environment's own pip.

## Environment variables

| Variable | Description | Default |
| --- | --- | --- |
| `PYENV_ROOT` | Path to your pyenv installation | `$HOME/.pyenv` |

## Limitations

- **OSV rate limits**: The tool makes one HTTP request per vulnerability ID to the OSV API. Environments with many vulnerabilities may take a minute or two to enrich. A future version may batch requests.
- **Fix mode**: The `--fix` flag upgrades packages to the minimum version that resolves the reported CVEs. It does not check whether the upgrade introduces breaking changes in your application. Always test after upgrading.
- **CVSS scores**: Numeric scores require the `cvss` Python library. Without it, the tool falls back to the severity label from the OSV database (which is not always available for every CVE).

## Background: the LiteLLM incident

On March 24, 2026, threat actor **TeamPCP** published two malicious versions (1.82.7 and 1.82.8) of the widely used [LiteLLM](https://github.com/BerriAI/litellm) Python package on PyPI. The malware harvested SSH keys, cloud credentials, Kubernetes secrets, and crypto wallets, attempted lateral movement across Kubernetes clusters, and installed a persistent systemd backdoor.

The attack vector was a `.pth` file that executed on every Python interpreter startup -- even `pip`, `python -c`, or an IDE's language server. The malicious versions were live for approximately three hours on a package downloaded 3.4 million times per day.

This tool was built to answer a simple question: **is any version of this package installed in any of my pyenv environments?** It has since grown into a general-purpose audit tool for pyenv-managed Python installations.

## Contributing

Contributions are welcome. Please open an issue or pull request on GitHub.

## License

[MIT](LICENSE)
