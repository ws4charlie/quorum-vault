package mpcstack

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// The binaries the end-to-end tests start are compiled once per CI run by the `build` job (ci/e2e-prebuild.sh) instead of in every job. GoBuild is the
// one place the harnesses build a binary: with QV_E2E_PREBUILT set to that directory it copies the prebuilt file, otherwise (a laptop, or a binary the
// build job did not make) it runs `go build` as before. In CI QV_E2E_PREBUILT_STRICT=1 makes a missing binary an error instead, so a harness that
// starts building something new is noticed (add it to ci/e2e-prebuild.sh) rather than silently compiled in every job.
const modulePath = "github.com/ws4charlie/quorum-vault/"

// PrebuiltKey names a build: the package directory relative to the repository root, slashes as underscores, and "@tags" when there are tags.
// ci/e2e-prebuild.sh writes the same names.
func PrebuiltKey(workdir, pkg, tags string) (string, error) {
	var rel string
	switch {
	case strings.HasPrefix(pkg, modulePath):
		rel = strings.TrimPrefix(pkg, modulePath)
	case strings.HasPrefix(pkg, "./") || strings.HasPrefix(pkg, "../") || pkg == ".":
		abs, err := filepath.Abs(filepath.Join(workdir, pkg))
		if err != nil {
			return "", err
		}
		r, err := filepath.Rel(RepoRoot(), abs)
		if err != nil || strings.HasPrefix(r, "..") {
			return "", fmt.Errorf("package %s (in %s) is outside the repository", pkg, workdir)
		}
		rel = filepath.ToSlash(r)
	default:
		return "", fmt.Errorf("package %s: want an import path of this repository or a ./ path", pkg)
	}
	key := strings.ReplaceAll(rel, "/", "_")
	if tags != "" {
		key += "@" + strings.ReplaceAll(tags, ",", "+")
	}
	return key, nil
}

// GoBuild makes `out` from the package pkg (a ./ path relative to workdir, or an import path of this repository), with -tags tags when not empty.
func GoBuild(workdir, out, pkg, tags string) error {
	if dir := os.Getenv("QV_E2E_PREBUILT"); dir != "" {
		key, err := PrebuiltKey(workdir, pkg, tags)
		if err != nil {
			return err
		}
		src := filepath.Join(dir, key)
		if _, err := os.Stat(src); err == nil {
			return copyExecutable(src, out)
		}
		if os.Getenv("QV_E2E_PREBUILT_STRICT") == "1" {
			return fmt.Errorf("prebuilt binary %s is missing from %s: add the build to ci/e2e-prebuild.sh", key, dir)
		}
	}
	args := []string{"build", "-o", out}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	cmd := exec.Command("go", append(args, pkg)...)
	cmd.Dir = workdir
	if o, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("build %s: %v\n%s", filepath.Base(out), err, o)
	}
	return nil
}

func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
