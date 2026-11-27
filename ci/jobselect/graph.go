package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// tagSets are the build configurations the CI jobs compile: the default, -tags devauth (the worker the e2e tests start), -tags teesim (the simulated
// enclave), and both. The graph is the union of the four, so an import that exists in any of them is an edge. `check` fails on a build tag that is
// not modelled here (a new tag must be added, or shown not to be used by CI).
var tagSets = []string{"", "devauth", "teesim", "devauth,teesim"}

// knownTags are the build constraint words that `check` accepts: the modelled tags, tags CI never sets (cloudhsm_hw: real hardware only), and the
// platform words go itself sets.
var knownTags = map[string]bool{"devauth": true, "teesim": true, "cloudhsm_hw": true, "ignore": true, "cgo": true, "unix": true,
	"linux": true, "darwin": true, "windows": true, "freebsd": true, "openbsd": true, "netbsd": true, "amd64": true, "arm64": true, "386": true, "arm": true}

// pkg is one package of the repository, the union over tagSets.
type pkg struct {
	path, dir, module, name string
	imports                 set               // of the package itself
	testImports             set               // of its _test.go files (internal and external test packages)
	files                   map[string]string // base name -> "go", "test" or "ignored" (go and test win over ignored)
}

type graph struct {
	pkgs  map[string]*pkg // by import path
	byDir map[string]*pkg // by directory relative to the repository root
}

type listed struct {
	ImportPath, Dir, Name                                        string
	Imports, TestImports, XTestImports                           []string
	GoFiles, CgoFiles, TestGoFiles, XTestGoFiles, IgnoredGoFiles []string
	Error                                                        *struct{ Err string }
}

// loadGraph runs `go list` in every module under every tag set, offline (no module is downloaded: only the repository's own packages and their import
// lists are needed). GOOS and GOARCH are those of the CI runners, so a run on a laptop decides the same as CI.
func loadGraph(root string, modules []string) (*graph, error) {
	type result struct {
		module string
		pkgs   []listed
		err    error
	}
	var wg sync.WaitGroup
	res := make(chan result, len(modules)*len(tagSets))
	for _, m := range modules {
		for _, tags := range tagSets {
			wg.Add(1)
			go func(m, tags string) {
				defer wg.Done()
				ps, err := goList(root, m, tags)
				res <- result{m, ps, err}
			}(m, tags)
		}
	}
	wg.Wait()
	close(res)
	g := &graph{pkgs: map[string]*pkg{}, byDir: map[string]*pkg{}}
	realRoot := root
	if r, err := filepath.EvalSymlinks(root); err == nil {
		realRoot = r
	}
	for r := range res {
		if r.err != nil {
			return nil, r.err
		}
		for _, l := range r.pkgs {
			dir := l.Dir
			if d, err := filepath.EvalSymlinks(dir); err == nil {
				dir = d
			}
			rel, err := filepath.Rel(realRoot, dir)
			if err != nil || strings.HasPrefix(rel, "..") {
				continue // not in the repository (go list ./... lists only the module's own packages; this is a safety net)
			}
			rel = filepath.ToSlash(rel)
			if l.Error != nil && !strings.Contains(l.Error.Err, "build constraints exclude all Go files") {
				return nil, fmt.Errorf("go list in %s: package %s: %s", r.module, l.ImportPath, l.Error.Err)
			}
			p := g.pkgs[l.ImportPath]
			if p == nil {
				p = &pkg{path: l.ImportPath, dir: rel, module: r.module, imports: set{}, testImports: set{}, files: map[string]string{}}
				g.pkgs[l.ImportPath] = p
			}
			if p.dir != rel || p.module != r.module {
				return nil, fmt.Errorf("package %s listed in %s and %s", l.ImportPath, p.dir, rel)
			}
			if l.Name != "" {
				p.name = l.Name
			}
			for _, i := range l.Imports {
				p.imports[i] = true
			}
			for _, i := range append(append([]string{}, l.TestImports...), l.XTestImports...) {
				p.testImports[i] = true
			}
			for _, f := range append(append([]string{}, l.GoFiles...), l.CgoFiles...) {
				p.files[f] = "go"
			}
			for _, f := range append(append([]string{}, l.TestGoFiles...), l.XTestGoFiles...) {
				p.files[f] = "test"
			}
			for _, f := range l.IgnoredGoFiles {
				if p.files[f] == "" {
					p.files[f] = "ignored"
				}
			}
		}
	}
	for _, p := range g.pkgs {
		if q := g.byDir[p.dir]; q != nil && q != p {
			return nil, fmt.Errorf("two packages in %s", p.dir)
		}
		g.byDir[p.dir] = p
	}
	if len(g.pkgs) == 0 {
		return nil, errors.New("go list found no package")
	}
	return g, nil
}

func goList(root, module, tags string) ([]listed, error) {
	args := []string{"list", "-e", "-json=ImportPath,Dir,Name,Imports,TestImports,XTestImports,GoFiles,CgoFiles,TestGoFiles,XTestGoFiles,IgnoredGoFiles,Error"}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	args = append(args, "./...")
	cmd := exec.Command("go", args...)
	cmd.Dir = filepath.Join(root, filepath.FromSlash(module))
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=1", "GOFLAGS=-mod=readonly", "GOPROXY=off", "GOWORK=off")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list in %s (tags %q): %v: %s", module, tags, err, oneLine(stderr.String()))
	}
	var ps []listed
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var l listed
		if err := dec.Decode(&l); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("go list in %s: %v", module, err)
		}
		ps = append(ps, l)
	}
	return ps, nil
}

// closure: the packages a job compiles. The packages it tests, with their test imports, and the binaries it builds (@mains, without their tests), then
// everything they import.
func (g *graph) closure(tested, built []*pkg) set {
	seen := set{}
	var walk func(path string)
	walk = func(path string) {
		p := g.pkgs[path]
		if p == nil || seen[path] {
			return // outside the repository (the standard library, a module dependency)
		}
		seen[path] = true
		for i := range p.imports {
			walk(i)
		}
	}
	for _, r := range tested {
		walk(r.path)
		for i := range r.testImports {
			walk(i)
		}
	}
	for _, r := range built {
		walk(r.path)
	}
	return seen
}

// resolve finds the packages of one root of ci/jobs.
func (g *graph) resolve(r rootSpec) []*pkg {
	base := strings.TrimPrefix(r.pattern, "./")
	recursive := strings.HasSuffix(base, "...")
	base = strings.TrimSuffix(strings.TrimSuffix(base, "..."), "/")
	dir := filepath.ToSlash(filepath.Join(r.module, base))
	var out []*pkg
	for _, p := range g.pkgs {
		if p.module != r.module {
			continue
		}
		if p.dir == dir || recursive && (dir == "." || strings.HasPrefix(p.dir, dir+"/")) {
			out = append(out, p)
		}
	}
	return out
}

// mains: every main package of the modules but those under an excluded tree.
func (g *graph) mains(c *config) []*pkg {
	var out []*pkg
	for _, p := range g.pkgs {
		if p.name != "main" || !contains(c.modules, p.module) {
			continue
		}
		skip := false
		for _, x := range c.mainsExclude {
			if strings.HasPrefix(p.dir+"/", x) {
				skip = true
			}
		}
		if !skip {
			out = append(out, p)
		}
	}
	return out
}

// why: one import chain from a job's roots to a package (for people: `jobselect why <job> <dir>`).
func (w *world) why(job, dir string) string {
	target := w.g.byDir[dir]
	if target == nil {
		return dir + " is not a package"
	}
	var spec *jobSpec
	for i := range w.cfg.jobs {
		if w.cfg.jobs[i].id == job {
			spec = &w.cfg.jobs[i]
		}
	}
	if spec == nil {
		return job + " is not a job"
	}
	var roots, built []*pkg
	for _, r := range spec.roots {
		roots = append(roots, w.g.resolve(r)...)
	}
	if spec.mains {
		built = w.g.mains(w.cfg)
	}
	prev := map[string]string{}
	var queue []string
	for _, r := range built {
		if _, ok := prev[r.path]; !ok {
			prev[r.path] = ""
			queue = append(queue, r.path)
		}
	}
	for _, r := range roots {
		if _, ok := prev[r.path]; !ok {
			prev[r.path] = ""
			queue = append(queue, r.path)
		}
		for i := range r.testImports {
			if _, ok := prev[i]; !ok && w.g.pkgs[i] != nil {
				prev[i] = r.path + " (test)"
				queue = append(queue, i)
			}
		}
	}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		if p == target.path {
			chain := []string{p}
			for q := prev[p]; q != ""; q = prev[strings.TrimSuffix(q, " (test)")] {
				chain = append([]string{q}, chain...)
			}
			return strings.Join(chain, " -> ")
		}
		for i := range w.g.pkgs[p].imports {
			if _, ok := prev[i]; !ok && w.g.pkgs[i] != nil {
				prev[i] = p
				queue = append(queue, i)
			}
		}
	}
	return job + " does not compile " + dir
}
