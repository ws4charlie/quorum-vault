package helmcheck

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// CheckWorkerStop: the worker's stop bound (-stop-timeout) fits the pod's termination grace period with 20 s to spare, so Kubernetes does not
// kill a worker that is still letting activities finish. Same rule as the party chart (shutdown grace + 20 s).
func CheckWorkerStop(objs []Obj) []string {
	var v []string
	found := false
	for _, o := range objs {
		if o.Kind != "Deployment" || o.Component() != "worker" {
			continue
		}
		found = true
		pod, ok := o.Pod()
		if !ok || len(pod.Containers) == 0 {
			v = append(v, o.Metadata.Name+": no pod")
			continue
		}
		var spec struct {
			Template struct {
				Spec struct {
					Grace int `yaml:"terminationGracePeriodSeconds"`
				} `yaml:"spec"`
			} `yaml:"template"`
		}
		if err := o.Spec.Decode(&spec); err != nil {
			v = append(v, err.Error())
			continue
		}
		bound := -1
		args := pod.Containers[0].Args
		for i, a := range args {
			if a == "-stop-timeout" && i+1 < len(args) {
				if d, err := time.ParseDuration(args[i+1]); err == nil {
					bound = int(d / time.Second)
				}
			}
		}
		if bound <= 0 {
			v = append(v, fmt.Sprintf("%s: no -stop-timeout argument: the worker's stop bound is not stated by the chart", o.Metadata.Name))
			continue
		}
		if spec.Template.Spec.Grace < bound+20 {
			v = append(v, fmt.Sprintf("%s: terminationGracePeriodSeconds %d is below -stop-timeout %d s + 20", o.Metadata.Name, spec.Template.Spec.Grace, bound))
		}
	}
	if !found {
		v = append(v, "no worker Deployment rendered")
	}
	return v
}

func TestWorkerStopFitsGracePeriod(t *testing.T) {
	for _, vf := range valuesFiles {
		t.Run(vf.file, func(t *testing.T) {
			for _, m := range CheckWorkerStop(render(t, vf.file)) {
				t.Error(m)
			}
		})
	}
}

func TestWorkerStopCheckCatches(t *testing.T) {
	text, err := Render("values.yaml")
	if err != nil {
		t.Skip(err)
	}
	for name, c := range map[string]struct{ from, to, want string }{
		"short grace":  {"terminationGracePeriodSeconds: 60", "terminationGracePeriodSeconds: 50", "is below -stop-timeout"},
		"bound raised": {`"40s"`, `"55s"`, "is below -stop-timeout"},
		"no bound":     {"- -stop-timeout", "- -stop-timeoutx", "no -stop-timeout"},
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(text, c.from) {
				t.Fatalf("stale: %q not rendered", c.from)
			}
			objs, err := Parse(strings.Replace(text, c.from, c.to, 1))
			if err != nil {
				t.Fatal(err)
			}
			if !anyContains(CheckWorkerStop(objs), c.want) {
				t.Errorf("no violation containing %q", c.want)
			}
		})
	}
}
