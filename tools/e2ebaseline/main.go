// Command e2ebaseline compares the failures in a Ginkgo JSON report against a
// recorded baseline of specs that are known to fail, and exits non-zero only
// when that set changes.
//
// Why this exists: the e2e suite went unrun for a long time, and when it was
// finally wired into CI it came up with a block of failures that all trace to
// one open design gap rather than to anything a pull request did. The choice was
// between a permanently red required job — which teaches everyone to ignore CI —
// and no job at all. This is the third option, and the same shape as the lint
// baseline in docs/UPSTREAM_SYNC.md §9: record what fails, say why, and fail the
// build the moment the set moves in either direction.
//
// A spec that starts failing is a regression. A baseline spec that starts
// passing is progress that has to be recorded, or the baseline slowly turns into
// a list of specs nobody runs.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

type specReport struct {
	ContainerHierarchyTexts []string `json:"ContainerHierarchyTexts"`
	LeafNodeText            string   `json:"LeafNodeText"`
	LeafNodeType            string   `json:"LeafNodeType"`
	State                   string   `json:"State"`
}

type suiteReport struct {
	SuiteDescription           string       `json:"SuiteDescription"`
	SpecialSuiteFailureReasons []string     `json:"SpecialSuiteFailureReasons"`
	SpecReports                []specReport `json:"SpecReports"`
}

func (s specReport) name() string {
	return strings.Join(append(append([]string{}, s.ContainerHierarchyTexts...), s.LeafNodeText), " ")
}

func main() {
	reportPath := flag.String("report", "e2e-report.json", "path to the Ginkgo --json-report output")
	baselinePath := flag.String("baseline", "e2e/failing-baseline.txt", "path to the recorded baseline of known-failing specs")
	flag.Parse()

	if err := run(*reportPath, *baselinePath); err != nil {
		fmt.Fprintf(os.Stderr, "e2ebaseline: %v\n", err)
		os.Exit(1)
	}
}

func run(reportPath, baselinePath string) error {
	failing, reasons, err := readReport(reportPath)
	if err != nil {
		return err
	}

	baseline, err := readBaseline(baselinePath)
	if err != nil {
		return err
	}

	var unexpected, fixed []string

	for name := range failing {
		if !baseline[name] {
			unexpected = append(unexpected, name)
		}
	}

	for name := range baseline {
		if !failing[name] {
			fixed = append(fixed, name)
		}
	}

	sort.Strings(unexpected)
	sort.Strings(fixed)

	// A suite that aborted, panicked or never ran its specs is not "no new
	// failures" — it is no measurement at all, and has to be loud.
	if len(reasons) > 0 {
		return fmt.Errorf("the suite did not complete normally: %s", strings.Join(reasons, "; "))
	}

	if len(unexpected) == 0 && len(fixed) == 0 {
		fmt.Printf("e2e baseline: unchanged — %d recorded failure(s), no new ones\n", len(baseline))

		return nil
	}

	var b strings.Builder

	if len(unexpected) > 0 {
		fmt.Fprintf(&b, "\n%d spec(s) failed that are not in %s:\n", len(unexpected), baselinePath)

		for _, n := range unexpected {
			fmt.Fprintf(&b, "  FAIL  %s\n", n)
		}

		b.WriteString("\nThese are regressions. Fix them, or — if the failure is understood and\n" +
			"deliberately deferred — add the exact line above to the baseline with a comment\n" +
			"saying why.\n")
	}

	if len(fixed) > 0 {
		fmt.Fprintf(&b, "\n%d spec(s) in %s no longer fail:\n", len(fixed), baselinePath)

		for _, n := range fixed {
			fmt.Fprintf(&b, "  PASS  %s\n", n)
		}

		b.WriteString("\nGood news, but the baseline has to say so: delete those lines. A baseline that\n" +
			"lists specs which already pass stops being a record of what is broken.\n")
	}

	return fmt.Errorf("%s", b.String())
}

func readReport(path string) (failing map[string]bool, reasons []string, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read report: %w", err)
	}

	var suites []suiteReport
	if err := json.Unmarshal(raw, &suites); err != nil {
		return nil, nil, fmt.Errorf("parse report %s: %w", path, err)
	}

	failing = map[string]bool{}
	specs := 0

	for _, suite := range suites {
		reasons = append(reasons, suite.SpecialSuiteFailureReasons...)

		for _, spec := range suite.SpecReports {
			// Suite-level setup nodes carry no spec text; their failures show up
			// as SpecialSuiteFailureReasons instead.
			if spec.LeafNodeType != "It" {
				continue
			}

			specs++

			switch spec.State {
			case "failed", "panicked", "timedout", "interrupted", "aborted":
				failing[spec.name()] = true
			}
		}
	}

	if specs == 0 {
		return nil, nil, fmt.Errorf("report %s contains no specs", path)
	}

	return failing, reasons, nil
}

func readBaseline(path string) (map[string]bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}

	baseline := map[string]bool{}

	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		baseline[line] = true
	}

	return baseline, nil
}
