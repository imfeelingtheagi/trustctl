package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"trstctl.com/trstctl/internal/perf"
)

func main() {
	var (
		profile     = flag.String("profile", "smoke", "perf profile name")
		out         = flag.String("out", "", "optional JSON output path; stdout when empty")
		samples     = flag.Int("samples", 64, "samples per hot path")
		printPretty = flag.Bool("pretty", true, "pretty-print JSON")
	)
	flag.Parse()

	report, err := perf.RunSmoke(*profile, *samples)
	if err != nil {
		fail("run perf smoke: %v", err)
	}
	var data []byte
	if *printPretty {
		data, err = json.MarshalIndent(report, "", "  ")
	} else {
		data, err = json.Marshal(report)
	}
	if err != nil {
		fail("marshal report: %v", err)
	}
	data = append(data, '\n')
	if *out == "" {
		if _, err := os.Stdout.Write(data); err != nil {
			fail("write stdout: %v", err)
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
			fail("create output dir: %v", err)
		}
		if err := os.WriteFile(*out, data, 0o644); err != nil {
			fail("write %s: %v", *out, err)
		}
	}
	if !report.Summary.OK {
		fail("perf gate failed: %d of %d hot paths missed SLO", report.Summary.Failed, report.Summary.HotPaths)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
