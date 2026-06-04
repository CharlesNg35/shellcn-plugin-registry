# Contributing a plugin

## Before you start

1. Build your plugin against the published ShellCN SDK — start from the
   [starter template](https://github.com/CharlesNg35/shellcn-plugin-starter).
2. Tag a release on **your** repo with one binary per platform plus a
   `checksums.txt` (the starter's release workflow does this). `linux/amd64` is
   mandatory — CI inspects it.
3. Make sure your manifest passes the gateway's validation locally
   (`plugin.Validate` runs in the starter's tests).

## The manifest

Add `plugins/<name>.yaml` (file name must equal the plugin `name`):

```yaml
name: surrealdb
displayName: SurrealDB
description: Explore, query, and manage a SurrealDB namespace/database.
repo: github.com/CharlesNg35/shellcn-plugin-surrealdb
homepage: https://surrealdb.com # optional
license: MIT
maintainers: [CharlesNg35] # GitHub handles
versions: # newest first
  - version: 0.2.0
    sdk: v0.1.3 # ShellCN SDK version it builds against
    assets:
      linux/amd64:
        url: https://github.com/CharlesNg35/shellcn-plugin-surrealdb/releases/download/v0.2.0/surrealdb-linux-amd64
        sha256: <64 hex chars>
      linux/arm64:
        url: https://github.com/CharlesNg35/shellcn-plugin-surrealdb/releases/download/v0.2.0/surrealdb-linux-arm64
        sha256: <64 hex chars>
      darwin/arm64:
        url: https://github.com/CharlesNg35/shellcn-plugin-surrealdb/releases/download/v0.2.0/surrealdb-darwin-arm64
        sha256: <64 hex chars>
```

Rules CI enforces:

- Asset URLs must be release downloads of the declared `repo` — nowhere else.
- `sha256` must match the actual bytes (CI downloads and checks).
- Only `linux/amd64` is **required**. Every other platform
  (`linux|darwin|windows` × `amd64|arm64`) is optional — ship what you can
  build; gateways without a matching build simply see the plugin as
  incompatible.
- Every asset you ship is downloaded, checksum-verified, and **executed on a
  native runner for its platform** (linux amd64/arm64, macOS, Windows): each
  binary must complete the real plugin handshake, pass the gateway's manifest
  validation, and present the same name/version/SDK the manifest claims.
  Platforms you don't ship are simply skipped.
- **Icons** must be self-contained: `lucide` name, emoji, inline SVG (≤16KB, no
  scripts/handlers/external references), or an inline `base64` data URI
  (png/webp/jpeg/svg, ≤48KB). Remote icon URLs are rejected. If unsure, use a
  lucide name. By submitting artwork you represent you have the right to use it.

Validate locally before opening the PR:

```sh
cd tools
go run ./cmd/regctl validate ../plugins/<name>.yaml
go run ./cmd/regctl verify   ../plugins/<name>.yaml
```

## Releasing a new version

Tag the release on your repo, then PR the new version entry **prepended** to
`versions:` (newest first). After merge, the mirror workflow republishes the
binaries here and the new version appears in the index.

## Fixing a bad release

Mirror releases are immutable — never re-tag with different bytes upstream
(installs would fail the checksum). Ship a new patch version. To pull a version
(e.g. a security issue), PR `yanked: true` onto it; it disappears from installs
immediately, no upstream cooperation required.

## Review

Maintainers review the manifest, the plugin's source repo, and the projection
CI prints (permissions, risk levels, transports). Keep your repo public and
buildable from source — unreviewable blobs don't get merged.
