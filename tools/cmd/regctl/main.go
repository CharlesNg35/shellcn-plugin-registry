// Command regctl is the shellcn-plugins registry tool: it validates manifests,
// verifies release assets against their checksums, inspects plugin binaries
// through the real go-plugin handshake, and generates index.json. CI is its
// only intended caller, but every subcommand runs locally too.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CharlesNg35/shellcn-plugins/tools/internal/registry"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "validate":
		err = cmdValidate(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "inspect":
		err = cmdInspect(os.Args[2:])
	case "check":
		err = cmdCheck(os.Args[2:])
	case "plan":
		err = cmdPlan(os.Args[2:])
	case "build-index":
		err = cmdBuildIndex(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "regctl:", err)
		os.Exit(1)
	}
}

// annotate emits a GitHub Actions error annotation so the failure shows inline
// on the PR's changed file; outside Actions it is a plain stderr line.
func annotate(file string, err error) {
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		msg := strings.ReplaceAll(err.Error(), "\n", "%0A")
		fmt.Printf("::error file=%s::%s\n", file, msg)
		return
	}
	fmt.Fprintf(os.Stderr, "%s: %v\n", file, err)
}

// splitPositional pulls a leading positional argument off args so flags may
// follow it (stdlib flag stops at the first non-flag otherwise).
func splitPositional(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  regctl validate [manifest.yaml ...]        validate manifests (default: plugins/*.yaml)
  regctl verify <manifest.yaml> [flags]      download assets and verify sha256
      -version <v>    only this version (default: all)
      -dir <path>     keep downloads here (default: verify and discard)
	  regctl inspect <binary> [flags]            handshake, validate, snapshot a plugin binary
	      -o <path>             write the snapshot JSON here (default: stdout)
	      -expect-name <n>      fail unless the binary presents this plugin name
	      -expect-version <v>   fail unless the binary presents this version
	  regctl check <manifest.yaml> -platform <os/arch> [-version v]
                                             download, hash-verify, and execute every version's
                                             binary for one platform; versions without that
                                             platform are skipped
  regctl plan -existing <file>               print "name version" pairs missing a mirror tag
  regctl build-index [flags]                 generate index.json from manifests + snapshots
      -plugins <dir>  (default plugins) -snapshots <dir> (default snapshots)
      -o <path>       (default index.json) -generated-by <id>`)
	os.Exit(2)
}

func cmdValidate(args []string) error {
	paths := args
	if len(paths) == 0 {
		var err error
		paths, err = filepath.Glob(filepath.Join("plugins", "*.yaml"))
		if err != nil {
			return err
		}
	}
	failed := false
	for _, p := range paths {
		m, err := registry.Load(p)
		if err == nil {
			err = m.Validate()
		}
		if err != nil {
			annotate(p, err)
			failed = true
			continue
		}
		fmt.Printf("ok: %s (%d versions)\n", m.Name, len(m.Versions))
	}
	if failed {
		return fmt.Errorf("validation failed")
	}
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	version := fs.String("version", "", "")
	dir := fs.String("dir", "", "")
	path, rest := splitPositional(args)
	_ = fs.Parse(rest)
	if path == "" {
		return fmt.Errorf("verify: exactly one manifest path required")
	}
	m, err := registry.Load(path)
	if err != nil {
		return err
	}
	if err := m.Validate(); err != nil {
		return err
	}
	for _, v := range m.Versions {
		if *version != "" && v.Version != *version {
			continue
		}
		if err := registry.VerifyVersion(v, *dir); err != nil {
			return fmt.Errorf("%s %s: %w", m.Name, v.Version, err)
		}
		fmt.Printf("verified: %s %s (%d assets)\n", m.Name, v.Version, len(v.Assets))
	}
	return nil
}

func cmdInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	out := fs.String("o", "", "")
	expectName := fs.String("expect-name", "", "")
	expectVersion := fs.String("expect-version", "", "")
	path, rest := splitPositional(args)
	_ = fs.Parse(rest)
	if path == "" {
		return fmt.Errorf("inspect: exactly one binary path required")
	}
	snap, err := registry.Inspect(path, registry.Expect{
		Name: *expectName, Version: *expectVersion,
	})
	if err != nil {
		return err
	}
	if *out == "" {
		fmt.Printf("ok: %s %s (apiVersion %d, protocol %d, icon %s)\n",
			snap.Name, snap.Version, snap.APIVersion, snap.ProtocolVersion, snap.Icon.Type)
		return nil
	}
	if err := registry.WriteSnapshot(strings.TrimSuffix(*out, "/"), snap); err != nil {
		return err
	}
	fmt.Printf("snapshot: %s\n", registry.SnapshotPath(*out, snap.Name, snap.Version))
	return nil
}

// cmdCheck runs the full per-platform gate for one manifest: fetch the asset,
// verify its sha256, execute it through the plugin handshake, and require the
// identity (name/version) the manifest claims. Used by the CI matrix where
// the runner's platform matches -platform.
func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	platform := fs.String("platform", "", "")
	version := fs.String("version", "", "")
	path, rest := splitPositional(args)
	_ = fs.Parse(rest)
	if path == "" || *platform == "" {
		return fmt.Errorf("check: a manifest path and -platform are required")
	}
	m, err := registry.Load(path)
	if err != nil {
		return err
	}
	if err := m.Validate(); err != nil {
		return err
	}

	dir, err := os.MkdirTemp("", "regctl-check-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	for _, v := range m.Versions {
		if *version != "" && v.Version != *version {
			continue
		}
		asset, ok := v.Assets[*platform]
		if !ok {
			fmt.Printf("skip: %s %s has no %s asset\n", m.Name, v.Version, *platform)
			continue
		}
		bin, err := registry.FetchVerified(asset, dir)
		if err != nil {
			return fmt.Errorf("%s %s %s: %w", m.Name, v.Version, *platform, err)
		}
		snap, err := registry.Inspect(bin, registry.Expect{Name: m.Name, Version: v.Version})
		if err != nil {
			annotate(path, fmt.Errorf("%s %s (%s): %w", m.Name, v.Version, *platform, err))
			return fmt.Errorf("check failed")
		}
		fmt.Printf("ok: %s %s %s (apiVersion %d)\n",
			m.Name, v.Version, *platform, snap.APIVersion)
		_ = os.Remove(bin)
	}
	return nil
}

// cmdPlan prints the name/version pairs whose mirror release does not exist
// yet. The existing-tags file is one tag per line (from `gh release list`).
func cmdPlan(args []string) error {
	fs := flag.NewFlagSet("plan", flag.ExitOnError)
	existing := fs.String("existing", "", "")
	_ = fs.Parse(args)
	if *existing == "" {
		return fmt.Errorf("plan: -existing <file> is required")
	}
	f, err := os.Open(*existing)
	if err != nil {
		return err
	}
	defer f.Close()
	have := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		have[strings.TrimSpace(sc.Text())] = true
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read %s: %w", *existing, err)
	}
	ms, err := registry.LoadAll("plugins")
	if err != nil {
		return err
	}
	for _, m := range ms {
		for _, v := range m.Versions {
			if !have[registry.MirrorTag(m.Name, v.Version)] {
				fmt.Printf("%s %s\n", m.Name, v.Version)
			}
		}
	}
	return nil
}

func cmdBuildIndex(args []string) error {
	fs := flag.NewFlagSet("build-index", flag.ExitOnError)
	pluginsDir := fs.String("plugins", "plugins", "")
	snapshots := fs.String("snapshots", "snapshots", "")
	out := fs.String("o", "index.json", "")
	generatedBy := fs.String("generated-by", "regctl", "")
	_ = fs.Parse(args)

	ms, err := registry.LoadAll(*pluginsDir)
	if err != nil {
		return err
	}
	for _, m := range ms {
		if err := m.Validate(); err != nil {
			return err
		}
	}
	idx, skipped, err := registry.BuildIndex(ms, *snapshots, *generatedBy)
	if err != nil {
		return err
	}
	for _, s := range skipped {
		fmt.Fprintln(os.Stderr, "skipped:", s)
	}
	if err := registry.WriteIndex(idx, *out); err != nil {
		return err
	}
	fmt.Printf("index: %s (%d plugins)\n", *out, len(idx.Plugins))
	return nil
}
