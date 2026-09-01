package plugin

import (
	"testing"

	model "github.com/bomly-dev/bomly-sdk"
)

// TestEvidenceFromASecondModuleIsNotDiscarded pins the loss phase 2.8 removes.
//
// This analyzer annotated a vulnerability once and skipped it on every later
// module pass -- "already annotated by an earlier module pass". In a workspace
// that is wrong in the unsafe direction: the first module can find no call
// path while the second calls the vulnerable symbol, and the first answer
// stood. Each module root now contributes evidence and the annotation is the
// derived summary.
func TestEvidenceFromASecondModuleIsNotDiscarded(t *testing.T) {
	const stamp = "2026-08-31T00:00:00Z"

	first := withEvidence(nil, model.ReachabilityEvidence{
		ModuleRoot: "apps/api",
		Analyzer:   Name,
		Status:     model.ReachabilityUnreachable,
		Tier:       model.TierSymbol,
		Reason:     "no-call-into-vulnerable-symbol",
	}, stamp)
	if first.Status != model.ReachabilityUnreachable {
		t.Fatalf("first pass = %q, want unreachable", first.Status)
	}

	second := withEvidence(first, model.ReachabilityEvidence{
		ModuleRoot:     "apps/web",
		Analyzer:       Name,
		Status:         model.ReachabilityReachable,
		Tier:           model.TierSymbol,
		DependencyRefs: []string{"pkg:golang/example.com/lib@v1.0.0"},
	}, stamp)

	if second.Status != model.ReachabilityReachable {
		t.Errorf("summary = %q, want a reachable second module to win", second.Status)
	}
	if len(second.Evidence) != 2 {
		t.Errorf("evidence = %d entries, want both module roots kept", len(second.Evidence))
	}
	roots := map[string]bool{}
	for _, e := range second.Evidence {
		roots[e.ModuleRoot] = true
	}
	if !roots["apps/api"] || !roots["apps/web"] {
		t.Errorf("evidence lost a module root: %+v", second.Evidence)
	}
}

// TestUnanalyzedModuleDoesNotReadAsUnreachable pins the safety half. A module
// govulncheck could not process contributes unknown evidence, and one module
// finding nothing must not let the pair summarize as unreachable -- that would
// turn "we did not look there" into "it is not reachable there".
func TestUnanalyzedModuleDoesNotReadAsUnreachable(t *testing.T) {
	const stamp = "2026-08-31T00:00:00Z"

	r := withEvidence(nil, model.ReachabilityEvidence{
		ModuleRoot: "apps/api", Analyzer: Name,
		Status: model.ReachabilityUnreachable, Tier: model.TierPackage, Reason: "package-not-imported",
	}, stamp)
	r = withEvidence(r, model.ReachabilityEvidence{
		ModuleRoot: "apps/web", Analyzer: Name,
		Status: model.ReachabilityUnknown, Tier: model.TierNone, Reason: "missing-toolchain",
	}, stamp)

	if r.Status != model.ReachabilityUnknown {
		t.Errorf("summary = %q, want unknown when a module could not be analyzed", r.Status)
	}
	if r.Reason == "" {
		t.Error("an unknown summary must still explain itself")
	}
}
