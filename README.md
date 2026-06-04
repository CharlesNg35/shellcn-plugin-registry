# shellcn-plugins

The community plugin registry for [ShellCN](https://github.com/CharlesNg35/shellcn).
Fully hosted on GitHub: manifests live here as PRs, verified binaries are
mirrored to this repo's Releases, and the gateway consumes the generated
[`index.json`](index.json) to power its Marketplace.

```
contributor PR (plugins/<name>.yaml)
        │  CI: schema ✓  sha256 ✓  loads through the real plugin handshake ✓
        ▼
merge → mirror workflow
        │  re-verify → release <name>-v<version> on THIS repo (binaries + checksums)
        │  snapshot the manifest projection + icon → snapshots/
        ▼
index.json (regenerated)  ──fetched by──▶  ShellCN gateway → Marketplace → Install
```

## How trust works

- **Checksums are the contract.** Every asset's sha256 lives in the reviewed
  manifest; CI verifies it at PR time, again at mirror time, and the gateway
  verifies it at install time. A maintainer replacing or deleting an upstream
  release can break availability, never integrity.
- **The mirror removes the availability risk too.** Installs are served from
  this repo's releases (`<name>-v<version>`), which exist independently of the
  upstream repo. Mirror releases are immutable - a fix is always a new version.
- **What you see is what was reviewed.** The gateway shows each plugin's full
  permission/risk/transport surface from a projection snapshot taken from the
  _verified binary_ by CI - not from anything the manifest author typed.
- **`yanked: true`** on a version hides it from installs registry-side, with no
  cooperation needed from the upstream maintainer.

## Installing plugins

In ShellCN: **Settings → Protocols → Marketplace**. Or manually: download a
binary from this repo's releases, check its sha256 against `index.json`, drop it
into the gateway's `plugins.d/`, restart.

## Adding your plugin

See [CONTRIBUTING.md](CONTRIBUTING.md). Short version: build your plugin from the
[starter template](https://github.com/CharlesNg35/shellcn-plugin-starter), tag a
release with per-platform binaries, then PR one YAML file here.

## Repository layout

| Path         | What                                                         |
| ------------ | ------------------------------------------------------------ |
| `plugins/`   | One manifest per plugin - the only files contributors touch. |
| `snapshots/` | Generated projection snapshots (committed by the mirror CI). |
| `index.json` | Generated catalog the gateway fetches. Never edit by hand.   |
| `tools/`     | `regctl`, the registry tool CI runs (works locally too).     |
