package helmcheck

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type ImageContract struct {
	Zone          string     `json:"zone"`
	Flags         []string   `json:"flags"`
	Env           []string   `json:"env"`
	RequiredFlags []string   `json:"requiredFlags"`
	RequiredAny   [][]string `json:"requiredAny"`
	PathFlags     []string   `json:"pathFlags"`
	PathEnv       []string   `json:"pathEnv"`
	ForbiddenEnv  []string   `json:"forbiddenEnv"`
	DSNRole       string     `json:"dsnRole"`
	Listen        struct {
		Flag  string `json:"flag"`
		Env   string `json:"env"`
		Ports int    `json:"ports"`
	} `json:"listen"`
	LoopbackOnly []string            `json:"loopbackOnly"`
	NoTLSEnv     bool                `json:"noTLSEnv"`
	FlagValues   map[string][]string `json:"flagValues"`
	FlagOnlyIn   map[string]string   `json:"flagOnlyIn"` // flag -> the only container name that may use it
}

type Contract struct {
	User           int                      `json:"user"`
	MountRoots     []string                 `json:"mountRoots"`
	ForbiddenEnv   []string                 `json:"forbiddenEnv"`
	TLSEnv         []string                 `json:"tlsEnv"`
	Images         map[string]ImageContract `json:"images"`
	ExternalImages map[string]any           `json:"externalImages"`
	DevImages      map[string]DevImage      `json:"devImages"`
	SimImages      map[string]DevImage      `json:"simImages"` // tee-sim variants (task Broker-chart): checked like a -dev image, not part of images.sh
}

// DevImage is a SoftHSM variant of a production image: the same binary, and an environment it must run with.
type DevImage struct {
	Of          string            `json:"of"`
	RequiredEnv map[string]string `json:"requiredEnv"`
	PKCS11Lib   string            `json:"pkcs11Lib"`
}

// LoadContract reads deploy/images/contract.json.
func LoadContract() (Contract, error) {
	var c Contract
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "images", "contract.json"))
	if err != nil {
		return c, err
	}
	return c, json.Unmarshal(b, &c)
}

var imageName = regexp.MustCompile(`([^/@:]+)(?:[@:][^/]*)?$`)

// CheckContract compares every container of the workloads with the contract. One line per drift.
func CheckContract(objs []Obj, c Contract) []string {
	var v []string
	add := func(f string, a ...any) { v = append(v, fmt.Sprintf(f, a...)) }
	cms := map[string]map[string]any{}
	for _, o := range objs {
		if o.Kind == "ConfigMap" {
			cms[o.Metadata.Name] = o.Data
		}
	}
	for _, o := range Workloads(objs) {
		pod, _ := o.Pod()
		vols := map[string]Volume{}
		for _, vl := range pod.Volumes {
			vols[vl.Name] = vl
		}
		for _, ct := range containers(pod) {
			cid := o.Kind + "/" + o.Metadata.Name + "/" + ct.Name
			m := imageName.FindStringSubmatch(ct.Image)
			name := ""
			if m != nil {
				name = m[1]
			}
			if _, ext := c.ExternalImages[name]; ext {
				continue
			}
			ic, ok := c.Images[name]
			if !ok {
				add("%s: image %q is not in deploy/images/contract.json", cid, ct.Image)
				continue
			}
			if ic.Zone != "business" {
				add("%s: a %s-zone image in the business chart", cid, ic.Zone)
			}
			uid := 0
			if ct.SecurityContext != nil && ct.SecurityContext.RunAsUser != nil {
				uid = *ct.SecurityContext.RunAsUser
			} else if pod.SecurityContext != nil && pod.SecurityContext.RunAsUser != nil {
				uid = *pod.SecurityContext.RunAsUser
			}
			if uid != c.User {
				add("%s: runs as uid %d, the image's user is %d", cid, uid, c.User)
			}
			if len(ct.Command) > 0 {
				add("%s: sets command; the image's ENTRYPOINT is the contract", cid)
			}
			// flags
			flags := map[string]string{}
			args := ct.Args
			for i := 0; i < len(args); i++ {
				a := args[i]
				if !strings.HasPrefix(a, "-") {
					continue
				}
				f := strings.TrimLeft(a, "-")
				val := ""
				if k := strings.Index(f, "="); k >= 0 {
					f, val = f[:k], f[k+1:]
				} else if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					val = args[i+1]
					i++
				}
				flags[f] = val
				if !contains(ic.Flags, f) {
					add("%s: flag -%s is not in the contract", cid, f)
				}
				if only, ok := ic.FlagOnlyIn[f]; ok && ct.Name != only {
					add("%s: flag -%s belongs only in the container %q", cid, f, only)
				}
			}
			for f, allowed := range ic.FlagValues {
				if val, ok := flags[f]; ok && !contains(allowed, val) {
					add("%s: -%s %s (allowed: %v)", cid, f, val, allowed)
				}
			}
			// environment: explicit plus the ConfigMaps of envFrom
			env := map[string]string{}
			for _, e := range ct.Env {
				env[e.Name] = e.Value
			}
			for _, ef := range ct.EnvFrom {
				if ef.ConfigMapRef != nil {
					d, ok := cms[ef.ConfigMapRef.Name]
					if !ok {
						add("%s: envFrom names the ConfigMap %q, which the chart does not render", cid, ef.ConfigMapRef.Name)
					}
					for k, val := range d {
						env[k] = fmt.Sprint(val)
					}
				}
				if ef.SecretRef != nil {
					add("%s: envFrom a Secret (secrets are files)", cid)
				}
			}
			for k := range env {
				ok := contains(ic.Env, k) || (!ic.NoTLSEnv && (contains(c.TLSEnv, k) || strings.HasPrefix(k, "QV_ARCHIVE_TLS_") && contains(ic.Env, k)))
				if !ok {
					add("%s: environment variable %s is not in the contract", cid, k)
				}
			}
			for _, k := range append(append([]string{}, c.ForbiddenEnv...), ic.ForbiddenEnv...) {
				if _, ok := env[k]; ok {
					add("%s: environment variable %s must never be set", cid, k)
				}
			}
			for _, f := range ic.RequiredFlags {
				if _, ok := flags[f]; !ok {
					add("%s: required flag -%s is missing", cid, f)
				}
			}
			for _, grp := range ic.RequiredAny {
				found := false
				for _, k := range grp {
					if _, ok := flags[k]; ok {
						found = true
					}
					if _, ok := env[k]; ok {
						found = true
					}
				}
				if !found {
					add("%s: none of %v is set", cid, grp)
				}
			}
			// files must sit on volume mounts, and mounts under the contract's roots
			mounted := func(p string) (bool, bool) { // found, writable
				for _, vm := range ct.VolumeMounts {
					if p == vm.MountPath || strings.HasPrefix(p, strings.TrimSuffix(vm.MountPath, "/")+"/") {
						return true, !vm.ReadOnly
					}
				}
				return false, false
			}
			var paths []string
			for _, f := range ic.PathFlags {
				if val, ok := flags[f]; ok {
					paths = append(paths, val)
				}
			}
			for _, k := range ic.PathEnv {
				if val, ok := env[k]; ok {
					paths = append(paths, val)
				}
			}
			if dsn := firstNonEmpty(flags["dsn"], env["DATABASE_URL"]); dsn != "" {
				u, err := url.Parse(dsn)
				if err != nil {
					add("%s: DSN does not parse", cid)
				} else {
					if u.User == nil || u.User.Username() != ic.DSNRole {
						add("%s: DSN user is %q, the role of this service is %q", cid, u.User.Username(), ic.DSNRole)
					}
					if _, has := u.User.Password(); has {
						add("%s: DSN carries a password (the certificate is the credential)", cid)
					}
					q := u.Query()
					if q.Get("sslmode") != "verify-full" {
						add("%s: DSN sslmode is %q, not verify-full", cid, q.Get("sslmode"))
					}
					for _, k := range []string{"sslcert", "sslkey", "sslrootcert"} {
						if q.Get(k) == "" {
							add("%s: DSN has no %s", cid, k)
						}
						paths = append(paths, q.Get(k))
					}
				}
			}
			for _, p := range paths {
				if p == "" {
					continue
				}
				if found, _ := mounted(p); !found {
					add("%s: the path %s is read by the binary but no volume is mounted over it", cid, p)
				}
			}
			for _, vm := range ct.VolumeMounts {
				under := false
				for _, r := range c.MountRoots {
					if vm.MountPath == r || strings.HasPrefix(vm.MountPath, r+"/") {
						under = true
					}
				}
				if !under {
					add("%s: mount %s is outside the contract's directories %v", cid, vm.MountPath, c.MountRoots)
				}
				if vl, ok := vols[vm.Name]; ok && (vl.Secret != nil || vl.ConfigMap != nil) && !vm.ReadOnly {
					add("%s: mount %s of a Secret or ConfigMap is not read-only", cid, vm.MountPath)
				}
				if _, ok := vols[vm.Name]; !ok {
					add("%s: mount %s names an undeclared volume %s", cid, vm.MountPath, vm.Name)
				}
			}
			// ports
			var ports []int
			for _, p := range ct.Ports {
				ports = append(ports, p.ContainerPort)
			}
			if len(ports) != ic.Listen.Ports {
				add("%s: declares %d container ports, the contract says %d", cid, len(ports), ic.Listen.Ports)
			}
			if ic.Listen.Ports == 1 && len(ports) == 1 {
				addr := firstNonEmpty(flags[ic.Listen.Flag], env[ic.Listen.Env])
				if _, ps, err := splitHostPort(addr); err != nil || ps != ports[0] {
					add("%s: listen address %q does not match containerPort %d", cid, addr, ports[0])
				}
			}
			for _, k := range ic.LoopbackOnly {
				val := firstNonEmpty(flags[k], env[k])
				if env["QV_METRICS_ALLOW_NON_LOOPBACK"] == "1" && ic.Zone == "business" {
					continue // task D10: a business-zone service may bind the pod address; the NetworkPolicy lets only the monitoring namespace in
				}
				if val != "" && !strings.HasPrefix(val, "127.0.0.1:") && !strings.HasPrefix(val, "[::1]:") && !strings.HasPrefix(val, "localhost:") {
					add("%s: %s=%s is not a loopback address (metrics are loopback only)", cid, k, val)
				}
			}
		}
	}
	return v
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if s != "" {
			return s
		}
	}
	return ""
}

func splitHostPort(addr string) (string, int, error) {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return "", 0, fmt.Errorf("no port in %q", addr)
	}
	p, err := strconv.Atoi(addr[i+1:])
	return addr[:i], p, err
}
