# Crates.io Publishing Guide

This directory contains the automation script (`publish.sh`) for testing, packaging, and publishing `nuclei-run` to [crates.io](https://crates.io/).

---

## Quick Start

### 1. Test Package (Dry Run)
Validates compilation, runs tests, and packages without uploading to crates.io:
```bash
./scripts/publish.sh --dry-run
```
*Or via Makefile:*
```bash
make publish-dry
```

### 2. Full Interactive Publish
Walks through authentication, uncommitted changes check, version bump, test execution, and publishing:
```bash
./scripts/publish.sh
```
*Or via Makefile:*
```bash
make publish
```

---

## Authentication

The script looks for crates.io credentials in the following order:
1. `.env` file in the project root containing `CRATE_TOKEN=...` or `CARGO_REGISTRY_TOKEN=...`
2. `CARGO_REGISTRY_TOKEN` environment variable
3. Saved cargo credentials (`~/.cargo/credentials.toml` or `~/.cargo/credentials`)
4. CLI token argument: `--token <YOUR_TOKEN>`
5. Interactive prompt to paste the token during execution

Get your API token at: [https://crates.io/settings/tokens](https://crates.io/settings/tokens)

---

## Common CLI Options

| Option | Description |
| :--- | :--- |
| `--dry-run` | Run pre-checks & test packaging without uploading |
| `--allow-dirty` | Allow publishing even if working directory has uncommitted files |
| `--skip-tests` | Skip test suite execution |
| `--bump <type>` | Bump version: `patch`, `minor`, `major`, or explicit version (e.g. `0.1.1`) |
| `--token <token>` | Provide API token directly for `cargo login` |
| `-y`, `--yes` | Non-interactive mode (auto-confirm prompts) |
| `-h`, `--help` | Display help instructions |

---

## Examples

```bash
# Dry run with uncommitted changes
./scripts/publish.sh --dry-run --allow-dirty

# Bump patch version and publish directly
./scripts/publish.sh --bump patch

# Bump minor version (e.g. 0.1.0 -> 0.2.0)
./scripts/publish.sh --bump minor

# CI / Non-interactive publish with token
./scripts/publish.sh --token "$CRATE_TOKEN" --yes
```

---

## Publish Workflow Steps

When executed, the script automatically handles:
1. **Authentication**: Verifies / logs in with your Crates.io token.
2. **Git Status**: Confirms clean working tree or prompts `--allow-dirty`.
3. **Version Selection**: Prompts or bumps semantic version in `Cargo.toml`.
4. **Tests**: Runs `cargo test` suite to prevent broken releases.
5. **Dry Run Validation**: Packages the crate and validates the build locally.
6. **Publication**: Runs `cargo publish` to upload to crates.io.
7. **Git Tagging (Optional)**: Creates a release tag (e.g. `v0.1.0`) and pushes to Git remote.
