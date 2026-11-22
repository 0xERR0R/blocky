package dnssec

// The universe test checks ValidateResponse against the truth instead of against expectations
// written case by case. Its universe is a set of signed zones under one trust anchor
// (uniZoneSpecs in universe_helpers_test.go), built with fixed keys and signature periods, so the
// answer to every question about them and the status of that answer are known.
//
//   - Completeness: the honest reply to every question, as a correct DNSSEC-aware resolver sends
//     it, and every reply that means the same must get the true status.
//   - Soundness: no other reply may get a better status than the oracle allows (see judge). The
//     other replies are the honest ones changed by generic operators (see mutations), the honest
//     ones validated with a DS or DNSKEY query of the validator failing or answered wrongly, and
//     curated cases of known findings (see curated).
//
// Case ids are the question ("www.nsec./A"), followed for a changed reply by the operator and the
// RRset it changed ("www.nsec./A+drop.an0"), with the validator's query whose reply was changed
// before the operator ("www.rsa./A@rsa./DNSKEY+servfail"). "www.nsec./A+upper.qname" is the reply
// to the question with its name in upper case. Curated cases are named after the finding
// ("583r/ends-at-hash"), and the questions of the second universe have a prefix.
//
// A third universe ("dname:", see uniDNAMEZones) has the zones of the first with more DNAME
// RRsets. It is asked about the names below those and for ANY: honest replies, one of them
// mutated, and curated cases (see curatedDNAME).
//
// testdata/universe-statuses.txt records the status of every case and the numbers of signature
// verifications and NSEC3 hash computations that its validation makes, and the spec fails when one
// changes. The honest replies share a validator, and so do the mutated ones (see run), so both
// numbers leave out what an earlier case put in the validator's cache of zones: the work for the
// replies to DS and DNSKEY queries that the case no longer makes. A case whose status breaks the
// oracle is a known defect: its line also says how the status breaks it and carries a tag naming
// what will fix it. The spec fails for a broken case without a tag, and for a tagged case that is
// no longer broken or is broken in another way, so the list of known defects only changes on
// purpose.
//
// Both numbers have a limit for one validation (see budget). No honest reply may run out, and
// each must stay within half of it for a validator that has no zone in its cache yet: among them
// are a CNAME chain across eight zones and a zone nine labels deep.
//
// After an intended change, regenerate the file with
//
//	go test ./resolver/dnssec/ -ginkgo.focus 'test universe' -update-golden -count=1
//
// which keeps its comment lines and the tags of the cases that are still broken in the same way,
// and marks the other broken cases "untagged" for a tag to be written by hand.

import (
	"flag"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	uniStatusFile   = "testdata/universe-statuses.txt"
	uniStatusHeader = "# Statuses of the cases of the universe test (universe_test.go): case, status, signature\n" +
		"# verifications, NSEC3 hash computations and, for a status that breaks the test's oracle, how it\n" +
		"# does and a tag naming what will fix it.\n"
	uniUntagged = "untagged"
)

var updateGolden = flag.Bool("update-golden", false, "regenerate "+uniStatusFile)

// uniRecord is what the status file holds for a case: its status, the signature verifications and
// NSEC3 hash computations of its validation and, if the status breaks the oracle, how it does (see
// judge) and a tag.
type uniRecord struct{ status, verifications, hashes, broken, tag string }

func (r uniRecord) String() string {
	return strings.TrimSpace(r.status + " " + r.verifications + " " + r.hashes + " " + r.broken)
}

// uniReadStatuses returns the comment lines of the status file and its records by case.
func uniReadStatuses() (header string, records map[string]uniRecord) {
	data, err := os.ReadFile(uniStatusFile)
	Expect(err).Should(Succeed(), "run with -update-golden to create the file")

	var comments []string

	records = map[string]uniRecord{}

	for line := range strings.Lines(string(data)) {
		if strings.HasPrefix(line, "#") {
			comments = append(comments, line)

			continue
		}

		// A case, its status, its verifications and its hashes, alone or with the way the status is
		// broken and a tag
		fields := append(strings.Fields(line), "", "", "", "", "", "")
		_, err := ParseValidationResult(fields[1])
		_, verificationsErr := strconv.ParseUint(fields[2], 10, 64)
		_, hashesErr := strconv.ParseUint(fields[3], 10, 64)
		_, twice := records[fields[0]]

		if err != nil || verificationsErr != nil || hashesErr != nil || twice ||
			(fields[4] == "") != (fields[5] == "") || fields[6] != "" {
			Fail(fmt.Sprintf("%s: malformed or repeated line %q", uniStatusFile, line))
		}

		records[fields[0]] = uniRecord{fields[1], fields[2], fields[3], fields[4], fields[5]}
	}

	return strings.Join(comments, ""), records
}

// uniWriteStatuses writes the status file for results. A case keeps its tag if it is broken in
// the way it was.
func uniWriteStatuses(results []uniResult) {
	header, old := uniStatusHeader, map[string]uniRecord{}
	if _, err := os.Stat(uniStatusFile); err == nil {
		header, old = uniReadStatuses()
	}

	lines := make([]string, len(results))
	for i, r := range results {
		lines[i] = fmt.Sprintf("%s %s %d %d", r.id, r.status, r.verifications, r.hashes)

		switch was := old[r.id]; {
		case r.broken == "":
		case was.broken == r.broken && was.tag != "":
			lines[i] += " " + r.broken + " " + was.tag
		default:
			lines[i] += " " + r.broken + " " + uniUntagged
		}
	}

	slices.Sort(lines)
	Expect(os.WriteFile(uniStatusFile, []byte(header+strings.Join(lines, "\n")+"\n"), 0o644)).Should(Succeed())
}

var _ = Describe("Signed test universe", Ordered, ContinueOnFailure, func() {
	var (
		results  []uniResult
		recorded map[string]uniRecord
	)

	BeforeAll(func(ctx SpecContext) {
		results = append(newUniverse("", uniZoneSpecs).run(ctx), newUniverse("nsec3-root:", uniNSEC3Root).run(ctx)...)
		results = append(results, newUniverse("dname:", uniDNAMEZones()).runDNAME(ctx)...)

		if *updateGolden {
			uniWriteStatuses(results)
		}

		_, recorded = uniReadStatuses()
	})

	It("gives every case its recorded status, verifications and hashes", func() {
		var changes []string

		cases := map[string]bool{}

		for _, r := range results {
			got := uniRecord{
				status:        r.status.String(),
				verifications: strconv.FormatInt(r.verifications, 10),
				hashes:        strconv.FormatInt(r.hashes, 10),
				broken:        r.broken,
			}

			switch record, found := recorded[r.id]; {
			case cases[r.id]:
				changes = append(changes, r.id+": two cases have this id")
			case !found:
				changes = append(changes, fmt.Sprintf("%s: %s, not recorded", r.id, got))
			case record.String() != got.String():
				changes = append(changes, fmt.Sprintf("%s: %s, recorded as %s", r.id, got, record))
			}

			cases[r.id] = true
		}

		for id := range recorded {
			if !cases[id] {
				changes = append(changes, id+": recorded, but not a case")
			}
		}

		slices.Sort(changes)
		Expect(changes).Should(BeEmpty(),
			"statuses, verifications or hashes differ from %s; if that is intended, run with -update-golden:\n%s",
			uniStatusFile, strings.Join(changes, "\n"))
	})

	It("validates every honest reply within half of the budget of a validation", func() {
		var over []string

		for _, r := range results {
			switch {
			case !r.honest:
			case r.ranOut:
				over = append(over, r.id+": ran out of budget")
			case r.coldVerifications > maxVerifications/2 || r.coldHashes > maxNSEC3Hashes/2:
				over = append(over, fmt.Sprintf("%s: %d verifications, %d hashes with an empty cache",
					r.id, r.coldVerifications, r.coldHashes))
			}
		}

		Expect(over).Should(BeEmpty(),
			"an honest reply may take half of the %d verifications and %d hashes of a validation:\n%s",
			maxVerifications, maxNSEC3Hashes, strings.Join(over, "\n"))
	})

	It("has a tag for every case that breaks the oracle, and for no other", func() {
		var problems []string

		for _, r := range results {
			switch tag := recorded[r.id].tag; {
			case r.broken != "" && (tag == "" || tag == uniUntagged):
				problems = append(problems, fmt.Sprintf("%s: %s %s, without a tag", r.id, r.status, r.broken))
			case r.broken == "" && tag != "":
				problems = append(problems, fmt.Sprintf("%s: %s is right, but tagged %s", r.id, r.status, tag))
			case strings.HasPrefix(tag, "deferred:") && r.broken != "false-bogus":
				// Only a refusal may wait: of a reply that is right, never one that is served.
				problems = append(problems, fmt.Sprintf("%s: %s %s cannot be %s", r.id, r.status, r.broken, tag))
			}
		}

		slices.Sort(problems)
		Expect(problems).Should(BeEmpty(),
			"a broken case needs a tag in %s naming what will fix it, a case that is right needs none:\n%s",
			uniStatusFile, strings.Join(problems, "\n"))
	})
})
