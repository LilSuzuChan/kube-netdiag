package main

import (
	"os"
	"strings"
	"testing"
)

func TestFixture(t *testing.T) {
	r := Report{Findings: []Finding{}}
	var before, objects []Obj
	var e error
	objects, e = read("examples/denied.json")
	if e != nil {
		t.Fatal(e)
	}
	diagnose(&r, objects, before, "default", "demo", "client", "backend", 80)
	found := false
	for _, f := range r.Findings {
		if f.ID == "policy-egress" {
			found = true
		}
		if len(f.Evidence) == 0 {
			t.Fatalf("missing evidence: %+v", f)
		}
	}
	if !found {
		t.Fatalf("expected diagnostic absent: %+v", r.Findings)
	}
}
func TestMalformedInput(t *testing.T) {
	p := t.TempDir() + "/bad.yaml"
	if e := os.WriteFile(p, []byte("x: ["), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := read(p); e == nil {
		t.Fatal("malformed YAML accepted")
	}
}
func TestMissingSubject(t *testing.T) {
	r := Report{}
	missing(&r, "Pod", "default", "absent")
	if r.Findings[0].Classification != "unknown" {
		t.Fatal("missing subject is not unknown")
	}
}
func TestNamespaceIsolation(t *testing.T) {
	objects := []Obj{{"kind": "Pod", "metadata": Obj{"name": "same", "namespace": "other"}}}
	if find(objects, "Pod", "default", "same") != nil {
		t.Fatal("cross namespace match")
	}
}
func TestSecretNotEchoed(t *testing.T) {
	r := Report{}
	secret := Obj{"kind": "Secret", "metadata": Obj{"name": "secret"}, "data": Obj{"password": "sensitive-marker"}}
	diagnose(&r, []Obj{secret}, nil, "default", "demo", "client", "backend", 80)
	for _, f := range r.Findings {
		if strings.Contains(f.Summary, "sensitive-marker") {
			t.Fatal("secret exposed")
		}
	}
}
func TestPolicyDirections(t *testing.T) {
	o, e := read("examples/denied.json")
	if e != nil {
		t.Fatal(e)
	}
	src := find(o, "Pod", "default", "client")
	dst := find(o, "Pod", "default", "server")
	v, _ := direction(o, src, dst, dst, "egress", 8080, "TCP")
	if v != "denied" {
		t.Fatalf("egress=%s", v)
	}
	v, _ = direction(o, dst, src, dst, "ingress", 8080, "TCP")
	if v != "allowed" {
		t.Fatalf("ingress=%s", v)
	}
}
func TestPolicyUnionAndNamedPort(t *testing.T) {
	o, _ := read("examples/denied.json")
	policy := Obj{"kind": "NetworkPolicy", "metadata": Obj{"name": "allow", "namespace": "default"}, "spec": Obj{"podSelector": Obj{"matchLabels": Obj{"app": "client"}}, "policyTypes": []interface{}{"Egress"}, "egress": []interface{}{Obj{"ports": []interface{}{Obj{"port": "http"}}, "to": []interface{}{Obj{"podSelector": Obj{"matchLabels": Obj{"app": "backend"}}}}}}}}
	o = append(o, policy)
	src := find(o, "Pod", "default", "client")
	dst := find(o, "Pod", "default", "server")
	v, _ := direction(o, src, dst, dst, "egress", 8080, "TCP")
	if v != "allowed" {
		t.Fatalf("union/named port=%s", v)
	}
	v, _ = direction(o, src, dst, dst, "egress", 9999, "TCP")
	if v != "denied" {
		t.Fatalf("wrong port=%s", v)
	}
}
func TestIPBlockUnknown(t *testing.T) {
	o, _ := read("examples/denied.json")
	policy := find(o, "NetworkPolicy", "default", "deny-client-egress")
	policy["spec"].(map[string]interface{})["egress"] = []interface{}{Obj{"to": []interface{}{Obj{"ipBlock": Obj{"cidr": "10.0.0.0/8"}}}}}
	v, _ := direction(o, find(o, "Pod", "default", "client"), find(o, "Pod", "default", "server"), find(o, "Pod", "default", "server"), "egress", 8080, "TCP")
	if v != "unknown" {
		t.Fatalf("IPBlock=%s", v)
	}
}
