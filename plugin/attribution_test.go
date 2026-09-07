package plugin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	model "github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/testkit"
)

// mapRunner answers per module directory, so a test can make one root succeed
// and another fail — which is the only way to exercise a workspace where the
// analyzer's knowledge is uneven.
type mapRunner struct {
	results map[string]RunnerResult
	errs    map[string]error
}

func (m *mapRunner) Name() string { return "fake" }

func (m *mapRunner) Run(_ context.Context, moduleDir string) (RunnerResult, error) {
	if err, ok := m.errs[moduleDir]; ok {
		return RunnerResult{}, err
	}
	return m.results[moduleDir], nil
}

// goModuleDirNamed creates a real go.mod directory, which discoverModuleRoots
// needs on disk to recognize a module root.
func goModuleDirNamed(t *testing.T, parent, name string) string {
	t.Helper()
	dir := filepath.Join(parent, name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.test/"+name+"\n\ngo 1.22\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// goNodeIn builds one Go dependency node sited in moduleRoot.
func goNodeIn(t *testing.T, name, version, moduleRoot string, declareRoot bool) *model.DependencyNode {
	t.Helper()
	dep := testkit.MustDependencyCoords(t, model.Coordinates{
		Name:           name,
		Version:        version,
		Ecosystem:      "go",
		PackageManager: "gomod",
	})
	location := model.PackageLocation{RealPath: filepath.Join(moduleRoot, "go.sum")}
	if declareRoot {
		location.ModuleRoot = moduleRoot
	}
	dep.Locations = []model.PackageLocation{location}
	dep.PackageRef = dep.NodeID()
	return dep
}

// graphWithVulns wires nodes into a graph and gives each node's package one
// vulnerability in the registry.
func graphWithVulns(t *testing.T, nodes []*model.DependencyNode, ids []string) (*model.Graph, *model.PackageRegistry) {
	t.Helper()
	g := model.New()
	registry := model.NewPackageRegistry()
	for i, node := range nodes {
		if err := g.AddNode(node); err != nil {
			t.Fatalf("AddNode(%s): %v", node.NodeID(), err)
		}
		pkg := registry.Ensure(node.PackageRef)
		pkg.Vulnerabilities = append(pkg.Vulnerabilities, model.Vulnerability{ID: ids[i], Source: "osv"})
	}
	return g, registry
}

func reachabilityFor(t *testing.T, registry *model.PackageRegistry, purl string) *model.Reachability {
	t.Helper()
	pkg, ok := registry.Get(purl)
	if !ok || pkg == nil || len(pkg.Vulnerabilities) == 0 {
		t.Fatalf("no vulnerability for %q", purl)
	}
	return pkg.Vulnerabilities[0].Reachability
}

func evidenceRoots(r *model.Reachability) []string {
	if r == nil {
		return nil
	}
	roots := make([]string, 0, len(r.Evidence))
	for _, e := range r.Evidence {
		roots = append(roots, e.ModuleRoot)
	}
	return roots
}

// TestEvidenceIsKeyedByTheModuleRootThatEstablishedIt is the core of row 2.8.
//
// A node sited in apps/api must not collect a finding from apps/web's build.
// Before attribution was real, every module root annotated every Go package,
// so a package absent from a root still got that root's "unreachable" — a
// claim about code that was never in that build, and one that survives into
// the summary because DeriveReachability counts unreachable evidence.
func TestEvidenceIsKeyedByTheModuleRootThatEstablishedIt(t *testing.T) {
	workspace := t.TempDir()
	apiRoot := goModuleDirNamed(t, workspace, "api")
	webRoot := goModuleDirNamed(t, workspace, "web")

	apiDep := goNodeIn(t, "example.com/apilib", "v1.0.0", apiRoot, true)
	webDep := goNodeIn(t, "example.com/weblib", "v2.0.0", webRoot, true)
	g, registry := graphWithVulns(t, []*model.DependencyNode{apiDep, webDep}, []string{"GO-2024-1", "GO-2024-2"})

	a := Analyzer{DisableCache: true, Runner: &mapRunner{results: map[string]RunnerResult{
		apiRoot: {Findings: map[string]Finding{}, ImportedModules: map[string]struct{}{}},
		webRoot: {Findings: map[string]Finding{}, ImportedModules: map[string]struct{}{}},
	}}}
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: registry, ProjectPath: workspace}); err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	for _, tc := range []struct {
		dep  *model.DependencyNode
		want string
	}{{apiDep, apiRoot}, {webDep, webRoot}} {
		roots := evidenceRoots(reachabilityFor(t, registry, tc.dep.PackageRef))
		if len(roots) != 1 || roots[0] != tc.want {
			t.Errorf("%s evidence roots = %v, want exactly [%s]", tc.dep.Name, roots, tc.want)
		}
	}
}

// TestVendoredSiteUnderAnotherRootIsNotOurs covers the path half of the
// exclusion, independently of declared roots. A vendored dependency lives
// inside the module that vendored it, so its path alone says which root it
// belongs to — and a site under another root this run analyzes is positive
// evidence of absence here.
func TestVendoredSiteUnderAnotherRootIsNotOurs(t *testing.T) {
	workspace := t.TempDir()
	apiRoot := goModuleDirNamed(t, workspace, "api")
	webRoot := goModuleDirNamed(t, workspace, "web")

	// Neither node declares a module root, so only its vendored path can say
	// which module it belongs to. Both roots are vendored into, so both are
	// discovered and both passes run.
	apiDep := goNodeIn(t, "example.com/apilib", "v1.0.0", apiRoot, false)
	apiDep.Locations = []model.PackageLocation{{
		RealPath: filepath.Join(apiRoot, "vendor", "example.com", "apilib", "lib.go"),
	}}
	webDep := goNodeIn(t, "example.com/weblib", "v2.0.0", webRoot, false)
	webDep.Locations = []model.PackageLocation{{
		RealPath: filepath.Join(webRoot, "vendor", "example.com", "weblib", "lib.go"),
	}}
	g, registry := graphWithVulns(t, []*model.DependencyNode{apiDep, webDep}, []string{"GO-2024-1", "GO-2024-2"})

	a := Analyzer{DisableCache: true, Runner: &mapRunner{results: map[string]RunnerResult{
		apiRoot: {Findings: map[string]Finding{}, ImportedModules: map[string]struct{}{}},
		webRoot: {Findings: map[string]Finding{}, ImportedModules: map[string]struct{}{}},
	}}}
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: registry, ProjectPath: workspace}); err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	for _, tc := range []struct {
		dep  *model.DependencyNode
		want string
	}{{apiDep, apiRoot}, {webDep, webRoot}} {
		roots := evidenceRoots(reachabilityFor(t, registry, tc.dep.PackageRef))
		if len(roots) != 1 || roots[0] != tc.want {
			t.Errorf("%s evidence roots = %v, want exactly [%s]: a vendored copy belongs to the module that vendored it", tc.dep.Name, roots, tc.want)
		}
	}
}

// TestBuildModuleVersionNamesTheExactOccurrence pins govulncheck's own
// attribution source. Two roots can build two versions of one module; the
// version govulncheck reported for this build is what says which occurrence
// node the finding is about.
func TestBuildModuleVersionNamesTheExactOccurrence(t *testing.T) {
	root := goModuleDirNamed(t, t.TempDir(), "api")

	// Go dependencies live in the module cache, not under the module root, so
	// neither node has a site that pins it here. Only the build module
	// version can distinguish them.
	cache := filepath.Join(t.TempDir(), "modcache")
	built := goNodeIn(t, "example.com/lib", "v1.0.0", cache, false)
	other := goNodeIn(t, "example.com/lib", "v2.0.0", cache, false)
	g, registry := graphWithVulns(t, []*model.DependencyNode{built, other}, []string{"GO-2024-1", "GO-2024-1"})

	a := Analyzer{DisableCache: true, Runner: &mapRunner{results: map[string]RunnerResult{
		root: {
			Findings:        map[string]Finding{},
			ImportedModules: map[string]struct{}{},
			// "v1.0" and "v1.0.0" are one module version; semver canonicalizes
			// both sides so the match does not depend on how it was spelled.
			BuildModules: map[string]string{"example.com/lib": canonicalModuleVersion("v1.0")},
		},
	}}}
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: registry, ProjectPath: root}); err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	builtEvidence := reachabilityFor(t, registry, built.PackageRef).Evidence
	if len(builtEvidence) != 1 {
		t.Fatalf("built node evidence = %d entries, want 1", len(builtEvidence))
	}
	if got := builtEvidence[0].DependencyRefs; len(got) != 1 || got[0] != built.NodeID() {
		t.Errorf("built node refs = %v, want [%s]", got, built.NodeID())
	}

	otherEvidence := reachabilityFor(t, registry, other.PackageRef).Evidence
	if len(otherEvidence) != 1 {
		t.Fatalf("other node evidence = %d entries, want 1", len(otherEvidence))
	}
	if got := otherEvidence[0].DependencyRefs; len(got) != 0 {
		t.Errorf("refs = %v for a version this build did not select; the module root is the whole claim", got)
	}
	if otherEvidence[0].ModuleRoot != root {
		t.Errorf("module root = %q, want %q: the floor is mandatory even without refs", otherEvidence[0].ModuleRoot, root)
	}
}

// TestFailedModuleRootStillContributesUnknownEvidence pins the safety half in
// the failure path. One root finding nothing must not speak for a workspace
// whose other root was never analyzed.
func TestFailedModuleRootStillContributesUnknownEvidence(t *testing.T) {
	workspace := t.TempDir()
	apiRoot := goModuleDirNamed(t, workspace, "api")
	webRoot := goModuleDirNamed(t, workspace, "web")

	// One node, sited in both roots, so both passes are about the same
	// package: exactly the workspace case where one root's answer must not
	// stand for the other's silence.
	dep := goNodeIn(t, "example.com/lib", "v1.0.0", apiRoot, true)
	dep.Locations = append(dep.Locations, model.PackageLocation{
		RealPath:   filepath.Join(webRoot, "go.sum"),
		ModuleRoot: webRoot,
	})
	g, registry := graphWithVulns(t, []*model.DependencyNode{dep}, []string{"GO-2024-1"})

	a := Analyzer{DisableCache: true, Runner: &mapRunner{
		results: map[string]RunnerResult{apiRoot: {Findings: map[string]Finding{}, ImportedModules: map[string]struct{}{}}},
		errs:    map[string]error{webRoot: errors.New("go: build failed")},
	}}
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: registry, ProjectPath: workspace}); err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	r := reachabilityFor(t, registry, dep.PackageRef)
	if r == nil {
		t.Fatal("no reachability recorded")
	}
	if len(r.Evidence) != 2 {
		t.Fatalf("evidence = %d entries (%v), want one per module root", len(r.Evidence), evidenceRoots(r))
	}
	if r.Status != model.ReachabilityUnknown {
		t.Errorf("summary = %q, want unknown: one root was never analyzed", r.Status)
	}
	var sawUnknownForWeb bool
	for _, e := range r.Evidence {
		if e.ModuleRoot == webRoot && e.Status == model.ReachabilityUnknown {
			sawUnknownForWeb = true
		}
	}
	if !sawUnknownForWeb {
		t.Errorf("no unknown evidence for the root that failed: %+v", r.Evidence)
	}
}

// TestDeclaredRootsAreOnlyTrustedWhenTheyShareOurVocabulary guards the
// degradation path. Detectors record the root they resolved from and this
// analyzer derives roots from the filesystem; when the two spellings do not
// overlap, a non-match means they are speaking past each other, not that the
// package is absent — and dropping the node would lose the finding outright.
func TestDeclaredRootsAreOnlyTrustedWhenTheyShareOurVocabulary(t *testing.T) {
	workspace := t.TempDir()
	root := goModuleDirNamed(t, workspace, "api")

	dep := goNodeIn(t, "example.com/lib", "v1.0.0", root, false)
	// A root spelled the way a detector might record it, which this run never
	// analyzes.
	dep.Locations = []model.PackageLocation{{RealPath: "vendor/modules.txt", ModuleRoot: "apps/api"}}
	g, registry := graphWithVulns(t, []*model.DependencyNode{dep}, []string{"GO-2024-1"})

	a := Analyzer{DisableCache: true, Runner: &mapRunner{results: map[string]RunnerResult{
		root: {Findings: map[string]Finding{}, ImportedModules: map[string]struct{}{}},
	}}}
	if _, err := a.Analyze(context.Background(), model.AnalyzeRequest{Graph: g, Registry: registry, ProjectPath: root}); err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	r := reachabilityFor(t, registry, dep.PackageRef)
	if r == nil || len(r.Evidence) == 0 {
		t.Fatal("evidence was dropped for a root vocabulary mismatch; the finding is lost")
	}
	if got := r.Evidence[0].DependencyRefs; len(got) != 0 {
		t.Errorf("refs = %v, want none: nothing established this occurrence", got)
	}
}

// TestAttributorCalibratesOnOverlap covers the calibration directly, so the
// two halves of the rule are pinned independently of a full Analyze run.
func TestAttributorCalibratesOnOverlap(t *testing.T) {
	node := testkit.MustDependencyCoords(t, model.Coordinates{
		Name:           "example.com/lib",
		Version:        "v1.0.0",
		Ecosystem:      "go",
		PackageManager: "gomod",
	})
	node.Locations = []model.PackageLocation{{ModuleRoot: "/ws/api"}}
	g := model.New()
	if err := g.AddNode(node); err != nil {
		t.Fatal(err)
	}

	shared := model.NewRootAttributor([]string{"/ws/api", "/ws/web"}, g)
	if got := shared.Attribute(node, "/ws/api"); got != model.AttributedToSite {
		t.Errorf("attribute(own root) = %v, want attributed-to-site", got)
	}
	if got := shared.Attribute(node, "/ws/web"); got != model.AttributedElsewhere {
		t.Errorf("attribute(other root) = %v, want attributed-elsewhere", got)
	}

	foreign := model.NewRootAttributor([]string{"/other/one", "/other/two"}, g)
	if got := foreign.Attribute(node, "/other/one"); got != model.AttributedToRootOnly {
		t.Errorf("attribute under a foreign vocabulary = %v, want attributed-to-root-only", got)
	}
}
