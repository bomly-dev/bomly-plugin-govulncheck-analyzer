package plugin

import (
	"path/filepath"
	"strings"

	model "github.com/bomly-dev/bomly-sdk"
)

// rootAttribution is how firmly a dependency node's declaration sites tie it
// to the module root currently being analyzed.
//
// ADR-0037 makes the module root the mandatory attribution floor for
// reachability evidence and node references the optional ceiling — refs exist
// for "analyzers that can attribute to a specific occurrence", and a consumer
// must read their absence as "not stated", never as "no occurrence". Naming
// whichever node the annotation loop happens to be visiting states a precision
// the analysis does not have: it pins an occurrence to a root nothing tied it
// to, which is a false claim rather than a vague one.
//
// This rule reads SDK types to produce SDK types and its proper home is the
// SDK, next to ReachabilityEvidence; it lives here in four copies only because
// the analyzers are four modules with no shared internal package. Tracked as
// https://github.com/bomly-dev/bomly-sdk/issues/68.
type rootAttribution int

const (
	// attributedElsewhere: every site this node records names some other
	// module root. The node is not part of the root under analysis and
	// contributes no evidence to it — a finding about a root a package is
	// absent from is noise at best and, when it reads "unreachable", a claim
	// about code that was never in that build.
	attributedElsewhere rootAttribution = iota
	// attributedToRootOnly: nothing ties the node to a particular root. The
	// analysis still covers it — the analyzer ran over this root's build — so
	// the evidence carries the module root, but no node reference, because
	// the occurrence was not established.
	attributedToRootOnly
	// attributedToSite: a site names this root, or lies under it. The
	// occurrence is established and the evidence may name the node.
	attributedToSite
)

// rootAttributor answers the question above for one analysis pass.
//
// It is built per Analyze call rather than per node because the honest answer
// depends on the whole run: a node whose sites declare module roots may only
// be judged "not in this root" when the producer's roots and the analyzer's
// roots are the same vocabulary. Detectors record the root they resolved
// from; this analyzer derives roots from the filesystem. When those two
// disagree — a relative workspace path against an absolute module directory,
// say — a non-match means the two are speaking past each other, not that the
// package is absent, and dropping the node's evidence on that basis would lose
// the finding entirely. So a non-match only means "not ours" once at least one
// declared root in the graph is a root this run analyzes.
type rootAttributor struct {
	// trustDeclaredRoots is set when producer-recorded roots and analyzed
	// roots overlap, which is what licenses reading a non-match as absence.
	trustDeclaredRoots bool
}

// newRootAttributor calibrates attribution against the roots this run will
// analyze and the sites the graph actually records.
func newRootAttributor(graph *model.Graph, roots []string) rootAttributor {
	if graph == nil || len(roots) == 0 {
		return rootAttributor{}
	}
	analyzed := make(map[string]struct{}, len(roots))
	for _, root := range roots {
		if cleaned := cleanRoot(root); cleaned != "" {
			analyzed[cleaned] = struct{}{}
		}
	}
	for _, node := range graph.DependencyNodes() {
		if node == nil {
			continue
		}
		for _, location := range node.Locations {
			declared := cleanRoot(location.ModuleRoot)
			if declared == "" {
				continue
			}
			if _, ok := analyzed[declared]; ok {
				return rootAttributor{trustDeclaredRoots: true}
			}
		}
	}
	return rootAttributor{}
}

// attribute reports how firmly node's sites tie it to root.
func (a rootAttributor) attribute(node *model.DependencyNode, root string) rootAttribution {
	if node == nil {
		return attributedElsewhere
	}
	target := cleanRoot(root)
	declaredAnyRoot := false
	for _, location := range node.Locations {
		if declared := cleanRoot(location.ModuleRoot); declared != "" {
			declaredAnyRoot = true
			if target != "" && declared == target {
				return attributedToSite
			}
		}
		if location.RealPath != "" && target != "" && pathContainsRoot(location.RealPath, target) {
			return attributedToSite
		}
	}
	// The producer attributed its sites in a vocabulary this run shares, and
	// none of them is this root. That is a real absence, so the node
	// contributes nothing here.
	if declaredAnyRoot && a.trustDeclaredRoots {
		return attributedElsewhere
	}
	return attributedToRootOnly
}

// cleanRoot normalizes a module root for comparison. Empty in, empty out —
// an unset root is not a root that matches everything.
func cleanRoot(root string) string {
	root = strings.TrimSpace(root)
	if root == "" {
		return ""
	}
	return filepath.Clean(root)
}
