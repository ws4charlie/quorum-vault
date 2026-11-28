// Command kindimages prints every image a Helm values file names, one per line, for ci/kind/check-pins.sh: any map (at any depth, in block or flow
// style, keys in any order) with a `repository` key is an image, printed as repository@digest when it has a digest, else repository:tag (a missing or
// empty tag prints the bare repository, which the check refuses). A file that does not parse is an error, never an empty list.
//
//	go -C ci/helm run ./kindimages FILE...
package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: kindimages FILE...")
		os.Exit(2)
	}
	for _, f := range os.Args[1:] {
		b, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintln(os.Stderr, "kindimages:", err)
			os.Exit(1)
		}
		var doc any
		if err := yaml.Unmarshal(b, &doc); err != nil {
			fmt.Fprintf(os.Stderr, "kindimages: %s: %v\n", f, err)
			os.Exit(1)
		}
		walk(doc, func(ref string) { fmt.Println(ref) })
	}
}

func walk(v any, out func(string)) {
	switch x := v.(type) {
	case map[string]any:
		if repo, ok := x["repository"].(string); ok && repo != "" {
			dig, _ := x["digest"].(string)
			tag := fmt.Sprint(x["tag"])
			switch {
			case dig != "":
				out(repo + "@" + dig)
			case x["tag"] == nil || tag == "":
				out(repo)
			default:
				out(repo + ":" + tag)
			}
		}
		for _, c := range x {
			walk(c, out)
		}
	case []any:
		for _, c := range x {
			walk(c, out)
		}
	}
}
