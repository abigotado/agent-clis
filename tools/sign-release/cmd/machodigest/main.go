// Command machodigest writes the signature-independent stream of a thin Mach-O
// binary and prints its sha256.
//
//	machodigest -o <stream-file> <binary>
//
// The stream file must not exist. Exit status is 2 for a usage error and 1 when
// the input is refused, a file cannot be read or written or the program panics. -h and -help print
// the usage to stderr and exit 0, so asking for help is not a failure.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/abigotado/agent-clis/tools/sign-release/machodigest"
)

const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWith(args, stdout, stderr, digest)
}

// runWith is run with the digest step injected. A panic anywhere in it exits
// 1: a Go program that panics exits 2 on its own, which here means usage.
func runWith(args []string, stdout, stderr io.Writer, digestFn func(binary, output string) ([32]byte, error)) (code int) {
	defer func() {
		if rec := recover(); rec != nil {
			report(stderr, "machodigest: internal error: %v\n", rec)
			code = exitFailure
		}
	}()
	fs := flag.NewFlagSet("machodigest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		report(stderr, "usage: machodigest -o <stream-file> <binary>\n")
	}
	output := fs.String("o", "", "file to create with the normalized stream")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if *output == "" || fs.NArg() != 1 {
		fs.Usage()
		return exitUsage
	}
	binary := fs.Arg(0)

	sum, err := digestFn(binary, *output)
	if err != nil {
		report(stderr, "machodigest: %v\n", err)
		return exitFailure
	}
	if _, err := fmt.Fprintf(stdout, "sha256:%x  %s\n", sum, binary); err != nil {
		report(stderr, "machodigest: write result: %v\n", err)
		return exitFailure
	}
	return exitOK
}

// report prints a diagnostic. A failed write to stderr has nowhere better to
// go, and the exit status already carries the outcome.
func report(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

// digest validates the binary, creates the stream file exclusively and returns
// the sha256 of the stream. A refused binary leaves no stream file behind.
func digest(binary, output string) ([32]byte, error) {
	var zero [32]byte
	data, err := readRegular(binary)
	if err != nil {
		return zero, err
	}
	sum, err := machodigest.Sum(data)
	if err != nil {
		return zero, fmt.Errorf("digest %s: %w", binary, err)
	}
	if err := writeStream(output, data); err != nil {
		return zero, err
	}
	return sum, nil
}

func readRegular(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open binary: %w", err)
	}
	defer func() {
		_ = f.Close() // read-only descriptor; a close failure cannot affect data already read
	}()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat binary %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("binary %s is not a regular file", path)
	}
	data, err := machodigest.Read(f)
	if err != nil {
		return nil, fmt.Errorf("read binary %s: %w", path, err)
	}
	return data, nil
}

func writeStream(path string, data []byte) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create stream file: %w", err)
	}
	defer func() {
		if err == nil {
			if cerr := f.Close(); cerr != nil {
				err = fmt.Errorf("close stream file %s: %w", path, cerr)
			}
		} else {
			// The partial file is ours (created with O_EXCL); leave none behind.
			_ = f.Close()       // already failing; the first error is the one to report
			_ = os.Remove(path) // best effort: the stream is incomplete, a leftover would mislead
		}
	}()
	if err := machodigest.Write(f, data); err != nil {
		return fmt.Errorf("write stream file %s: %w", path, err)
	}
	return nil
}
