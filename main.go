package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Obj = map[string]interface{}
type Evidence struct {
	Resource string `json:"resource"`
	Field    string `json:"field"`
}
type Finding struct {
	ID             string     `json:"id"`
	Severity       string     `json:"severity"`
	Classification string     `json:"classification"`
	Summary        string     `json:"summary"`
	Evidence       []Evidence `json:"evidence"`
}
type Report struct {
	SchemaVersion string    `json:"schemaVersion"`
	Tool          string    `json:"tool"`
	Findings      []Finding `json:"findings"`
	Limitations   []string  `json:"limitations"`
}

func get(o Obj, path ...string) interface{} {
	var v interface{} = o
	for _, p := range path {
		m, ok := v.(map[string]interface{})
		if !ok {
			return nil
		}
		v = m[p]
	}
	return v
}
func s(o Obj, p ...string) string {
	v := get(o, p...)
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}
func arr(o Obj, p ...string) []Obj {
	var out []Obj
	v, _ := get(o, p...).([]interface{})
	for _, x := range v {
		if m, ok := x.(map[string]interface{}); ok {
			out = append(out, m)
		}
	}
	return out
}
func num(o Obj, p ...string) int {
	v := get(o, p...)
	switch x := v.(type) {
	case int:
		return x
	case float64:
		return int(x)
	case int64:
		return int(x)
	}
	return 0
}
func ns(o Obj) string {
	n := s(o, "metadata", "namespace")
	if n == "" {
		return "default"
	}
	return n
}
func ref(o Obj) string { return s(o, "kind") + "/" + ns(o) + "/" + s(o, "metadata", "name") }
func find(objs []Obj, kind, namespace, name string) Obj {
	for _, o := range objs {
		if s(o, "kind") == kind && ns(o) == namespace && s(o, "metadata", "name") == name {
			return o
		}
	}
	return nil
}
func (r *Report) add(id, sev, cls, msg string, o Obj, field string) {
	r.Findings = append(r.Findings, Finding{id, sev, cls, msg, []Evidence{{ref(o), field}}})
}
func read(path string) ([]Obj, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if info.Size() > 32<<20 {
		return nil, fmt.Errorf("snapshot exceeds 32 MiB")
	}
	d := yaml.NewDecoder(io.LimitReader(f, 32<<20))
	out := []Obj{}
	for {
		var o Obj
		e = d.Decode(&o)
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return nil, e
		}
		if len(o) == 0 {
			continue
		}
		if s(o, "kind") == "List" || strings.HasSuffix(s(o, "kind"), "List") {
			out = append(out, arr(o, "items")...)
		} else {
			out = append(out, o)
		}
	}
	return out, nil
}
func live(kinds []string, namespace string) ([]Obj, []string) {
	out := []Obj{}
	limits := []string{}
	for _, kind := range kinds {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		args := []string{"get", kind, "-o", "json", "--request-timeout=15s"}
		if kind != "namespaces" {
			args = append(args, "-n", namespace)
		}
		b, e := exec.CommandContext(ctx, "kubectl", args...).Output()
		cancel()
		if e != nil {
			limits = append(limits, "Cannot read "+kind+": check RBAC, API availability, connection, or timeout")
			continue
		}
		var list Obj
		if json.Unmarshal(b, &list) != nil {
			limits = append(limits, "Invalid API response: "+kind)
			continue
		}
		out = append(out, arr(list, "items")...)
	}
	return out, limits
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "error:", e)
		os.Exit(1)
	}
}
func run() error {
	file := flag.String("file", "", "YAML/JSON snapshot (multi-document or List)")
	before := flag.String("before", "", "before manifests (kube-ripple)")
	after := flag.String("after", "", "after manifests (kube-ripple)")
	liveFlag := flag.Bool("live", false, "read resources with kubectl current context")
	namespace := flag.String("namespace", "default", "resource namespace")
	name := flag.String("name", "", "Deployment, Application, or Workload name")
	source := flag.String("source", "", "source Pod name (kube-netdiag)")
	destination := flag.String("destination", "", "destination Service name (same namespace)")
	port := flag.Int("port", 80, "destination Service port")
	output := flag.String("output", "text", "text, json, or markdown")
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	if *output != "text" && *output != "json" && *output != "markdown" {
		return fmt.Errorf("unsupported output: %s", *output)
	}
	r := Report{SchemaVersion: "v0alpha1", Tool: tool, Findings: []Finding{}, Limitations: []string{"Snapshots describe observed state; absence is not proof of absence. No changes or network probes are performed."}}
	var objects, previous []Obj
	var e error
	if tool == "kube-ripple" {
		if *before == "" || *after == "" || *file != "" || *liveFlag {
			return fmt.Errorf("use --before and --after only")
		}
		previous, e = read(*before)
		if e != nil {
			return e
		}
		objects, e = read(*after)
	} else {
		if (*file == "") == !*liveFlag {
			return fmt.Errorf("choose exactly one of --file or --live")
		}
		if tool == "kube-netdiag" {
			if *source == "" || *destination == "" || *port < 1 || *port > 65535 {
				return fmt.Errorf("--source, --destination, and valid --port required")
			}
		} else if *name == "" {
			return fmt.Errorf("--name required")
		}
		if *liveFlag {
			var limits []string
			objects, limits = live(resourceKinds(), *namespace)
			r.Limitations = append(r.Limitations, limits...)
			for _, l := range limits {
				r.add("collection-incomplete", "warning", "unknown", l, Obj{"kind": "Collection"}, "API")
			}
		} else {
			objects, e = read(*file)
		}
	}
	if e != nil {
		return e
	}
	diagnose(&r, objects, previous, *namespace, *name, *source, *destination, *port)
	if *output == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	fmt.Printf("%s (%s)\n", r.Tool, r.SchemaVersion)
	for _, f := range r.Findings {
		fmt.Printf("[%s/%s] %s: %s\n", f.Severity, f.Classification, f.ID, f.Summary)
		for _, e := range f.Evidence {
			fmt.Printf("  evidence: %s %s\n", e.Resource, e.Field)
		}
	}
	for _, l := range r.Limitations {
		fmt.Println("limitation:", l)
	}
	return nil
}
func missing(r *Report, kind, namespace, name string) {
	r.add("subject-unavailable", "warning", "unknown", "Subject not found in available data", Obj{"kind": kind, "metadata": Obj{"namespace": namespace, "name": name}}, "metadata")
}

const tool = "kube-netdiag"
