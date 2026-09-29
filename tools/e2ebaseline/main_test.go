package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const oneFailOnePass = `[{"SuiteDescription":"e2e Suite","SpecReports":[
 {"ContainerHierarchyTexts":["Domain blocking","with lists"],"LeafNodeText":"blocks a domain","LeafNodeType":"It","State":"failed"},
 {"ContainerHierarchyTexts":["Custom DNS"],"LeafNodeText":"resolves mapping","LeafNodeType":"It","State":"passed"},
 {"ContainerHierarchyTexts":null,"LeafNodeText":"","LeafNodeType":"BeforeSuite","State":"passed"}
]}]`

func write(t *testing.T, name, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}

	return path
}

func TestRun(t *testing.T) {
	const failing = "Domain blocking with lists blocks a domain"

	tests := []struct {
		name     string
		report   string
		baseline string
		wantErr  string // substring; empty means success
	}{
		{
			name:     "recorded failure is not a build failure",
			report:   oneFailOnePass,
			baseline: "# comment\n\n" + failing + "\n",
		},
		{
			name:     "unrecorded failure is a regression",
			report:   oneFailOnePass,
			baseline: "# nothing recorded\n",
			wantErr:  "FAIL  " + failing,
		},
		{
			name:     "recorded spec that now passes has to be pruned",
			report:   oneFailOnePass,
			baseline: failing + "\nCustom DNS resolves mapping\n",
			wantErr:  "PASS  Custom DNS resolves mapping",
		},
		{
			name:     "a suite that never ran its specs is not a pass",
			report:   `[{"SuiteDescription":"e2e Suite","SpecReports":[]}]`,
			baseline: "",
			wantErr:  "contains no specs",
		},
		{
			name: "an aborted suite is not a pass",
			report: `[{"SuiteDescription":"e2e Suite","SpecialSuiteFailureReasons":["Interrupted by User"],
			 "SpecReports":[{"ContainerHierarchyTexts":["A"],"LeafNodeText":"b","LeafNodeType":"It","State":"passed"}]}]`,
			baseline: "",
			wantErr:  "did not complete normally",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := run(write(t, "report.json", tc.report), write(t, "baseline.txt", tc.baseline))

			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("expected success, got: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("expected error containing %q, got success", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}
