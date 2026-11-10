// Command homebrewcheck validates the inputs for a future offline Homebrew build.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
)

func main() {
	if err := mainRun(context.Background(), os.Args[1:]); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "homebrewcheck: %v\n", err)
		os.Exit(1)
	}
}

func mainRun(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("homebrewcheck", flag.ContinueOnError)
	root := flags.String("root", "", "repository root (detected when omitted)")
	manifest := flags.String("manifest", "", "dependency manifest (defaults below repository root)")
	proxyDir := flags.String("proxy-dir", "", "directory containing staged Go proxy zips")
	build := flags.Bool("build", false, "rehearse the offline CGO build")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if *proxyDir == "" {
		return fmt.Errorf("--proxy-dir is required")
	}
	return check(ctx, checkOptions{
		Root:         *root,
		ManifestPath: *manifest,
		ProxyDir:     *proxyDir,
		Build:        *build,
	}, execRunner{})
}
