// Package helmcheck renders the qv-business chart and checks the manifests: policy (policy_test.go) and the image contract (contract_test.go).
// The checks are functions over parsed manifests, so the tests can also show that each one fails on a bad manifest.
package helmcheck

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type SecCtx struct {
	RunAsNonRoot             *bool `yaml:"runAsNonRoot"`
	RunAsUser                *int  `yaml:"runAsUser"`
	ReadOnlyRootFilesystem   *bool `yaml:"readOnlyRootFilesystem"`
	AllowPrivilegeEscalation *bool `yaml:"allowPrivilegeEscalation"`
	Privileged               *bool `yaml:"privileged"`
	Capabilities             *struct {
		Add  []string `yaml:"add"`
		Drop []string `yaml:"drop"`
	} `yaml:"capabilities"`
	SeccompProfile *struct {
		Type string `yaml:"type"`
	} `yaml:"seccompProfile"`
}

type EnvVar struct {
	Name      string    `yaml:"name"`
	Value     string    `yaml:"value"`
	ValueFrom yaml.Node `yaml:"valueFrom"`
}

type Container struct {
	Name    string   `yaml:"name"`
	Image   string   `yaml:"image"`
	Command []string `yaml:"command"`
	Args    []string `yaml:"args"`
	Env     []EnvVar `yaml:"env"`
	EnvFrom []struct {
		ConfigMapRef *struct{ Name string } `yaml:"configMapRef"`
		SecretRef    *struct{ Name string } `yaml:"secretRef"`
	} `yaml:"envFrom"`
	Ports []struct {
		ContainerPort int `yaml:"containerPort"`
	} `yaml:"ports"`
	Resources struct {
		Requests map[string]string `yaml:"requests"`
		Limits   map[string]string `yaml:"limits"`
	} `yaml:"resources"`
	SecurityContext *SecCtx `yaml:"securityContext"`
	VolumeMounts    []struct {
		Name      string `yaml:"name"`
		MountPath string `yaml:"mountPath"`
		ReadOnly  bool   `yaml:"readOnly"`
	} `yaml:"volumeMounts"`
}

type Volume struct {
	Name   string `yaml:"name"`
	Secret *struct {
		SecretName string `yaml:"secretName"`
	} `yaml:"secret"`
	ConfigMap *struct{ Name string } `yaml:"configMap"`
	EmptyDir  *yaml.Node             `yaml:"emptyDir"`
}

type PodSpec struct {
	HostNetwork                  bool        `yaml:"hostNetwork"`
	HostPID                      bool        `yaml:"hostPID"`
	HostIPC                      bool        `yaml:"hostIPC"`
	AutomountServiceAccountToken *bool       `yaml:"automountServiceAccountToken"`
	SecurityContext              *SecCtx     `yaml:"securityContext"`
	InitContainers               []Container `yaml:"initContainers"`
	Containers                   []Container `yaml:"containers"`
	Volumes                      []Volume    `yaml:"volumes"`
}

type Meta struct {
	Name        string            `yaml:"name"`
	Labels      map[string]string `yaml:"labels"`
	Annotations map[string]string `yaml:"annotations"`
}

// Obj is one rendered Kubernetes object. Raw keeps the whole document for text checks.
type Obj struct {
	Kind     string         `yaml:"kind"`
	Metadata Meta           `yaml:"metadata"`
	Spec     yaml.Node      `yaml:"spec"`
	Data     map[string]any `yaml:"data"`
	Raw      string         `yaml:"-"`
}

func (o Obj) Component() string { return o.Metadata.Labels["app.kubernetes.io/component"] }

// Pod returns the pod spec of a Deployment, StatefulSet or Job.
func (o Obj) Pod() (PodSpec, bool) {
	switch o.Kind {
	case "Deployment", "StatefulSet", "Job", "DaemonSet":
	default:
		return PodSpec{}, false
	}
	var s struct {
		Template struct {
			Spec PodSpec `yaml:"spec"`
		} `yaml:"template"`
	}
	if err := o.Spec.Decode(&s); err != nil {
		return PodSpec{}, false
	}
	return s.Template.Spec, true
}

// Parse splits a multi-document YAML stream into objects.
func Parse(text string) ([]Obj, error) {
	var out []Obj
	dec := yaml.NewDecoder(strings.NewReader(text))
	for {
		var n yaml.Node
		if err := dec.Decode(&n); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if n.Kind == 0 {
			continue
		}
		var o Obj
		if err := n.Decode(&o); err != nil {
			return nil, err
		}
		if o.Kind == "" {
			continue
		}
		var b bytes.Buffer
		if err := yaml.NewEncoder(&b).Encode(&n); err != nil {
			return nil, err
		}
		o.Raw = b.String()
		out = append(out, o)
	}
	return out, nil
}

// ChartDir is the chart under test, relative to this package.
func ChartDir() string { return filepath.Join("..", "..", "deploy", "helm", "qv-business") }

// Render runs `helm template` for one values file ("values.yaml" or "values-kind.yaml") and returns the text. extra are more helm arguments.
func Render(valuesFile string, extra ...string) (string, error) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		return "", fmt.Errorf("helm not found on PATH: %w", err)
	}
	args := []string{"template", "qv", ChartDir(), "--namespace", "qv", "-f", filepath.Join(ChartDir(), valuesFile)}
	if valuesFile == "values.yaml" {
		args = append(args, "-f", "ci-digests.yaml")
	}
	args = append(args, extra...)
	args = append(args, strings.Fields(os.Getenv("QV_HELM_ARGS"))...) // e.g. QV_HELM_ARGS="--set core.replicas=0": to see a check fail on a real render
	cmd := exec.Command(helm, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("helm template: %w\n%s", err, errb.String())
	}
	return out.String(), nil
}

// Workloads are the objects that carry a pod spec.
func Workloads(objs []Obj) []Obj {
	var w []Obj
	for _, o := range objs {
		if _, ok := o.Pod(); ok {
			w = append(w, o)
		}
	}
	return w
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
