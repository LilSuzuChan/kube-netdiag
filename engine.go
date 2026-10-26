package main

import (
	"encoding/json"
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"strings"
)

func resourceKinds() []string {
	return []string{"pods", "services", "endpointslices.discovery.k8s.io", "networkpolicies.networking.k8s.io", "namespaces"}
}
func selector(raw interface{}, o Obj, path ...string) (bool, bool) {
	b, e := json.Marshal(raw)
	if e != nil || raw == nil {
		return false, false
	}
	var ls metav1.LabelSelector
	if json.Unmarshal(b, &ls) != nil {
		return false, false
	}
	sel, e := metav1.LabelSelectorAsSelector(&ls)
	if e != nil {
		return false, false
	}
	m := map[string]string{}
	if v, ok := get(o, path...).(map[string]interface{}); ok {
		for k, v := range v {
			m[k] = fmt.Sprint(v)
		}
	}
	return sel.Matches(labels.Set(m)), true
}
func peerMatch(peer, remote, policy Obj, objects []Obj) (bool, bool) {
	if get(peer, "ipBlock") != nil {
		return false, false
	}
	if len(peer) == 0 {
		return true, true
	}
	if get(peer, "namespaceSelector") == nil {
		if ns(remote) != ns(policy) {
			return false, true
		}
	} else {
		var namespace Obj
		for _, o := range objects {
			if s(o, "kind") == "Namespace" && s(o, "metadata", "name") == ns(remote) {
				namespace = o
			}
		}
		if namespace == nil {
			return false, false
		}
		match, known := selector(get(peer, "namespaceSelector"), namespace, "metadata", "labels")
		if !known || !match {
			return match, known
		}
	}
	if get(peer, "podSelector") != nil {
		return selector(get(peer, "podSelector"), remote, "metadata", "labels")
	}
	return true, true
}
func portMatch(rule, destination Obj, port int, protocol string) (bool, bool) {
	if get(rule, "ports") == nil || len(arr(rule, "ports")) == 0 {
		return true, true
	}
	unknown := false
	for _, p := range arr(rule, "ports") {
		proto := s(p, "protocol")
		if proto == "" {
			proto = "TCP"
		}
		if proto != protocol {
			continue
		}
		if get(p, "port") == nil {
			return true, true
		}
		v := get(p, "port")
		if name, ok := v.(string); ok {
			found := false
			for _, c := range arr(destination, "spec", "containers") {
				for _, cp := range arr(c, "ports") {
					cpProto := s(cp, "protocol")
					if cpProto == "" {
						cpProto = "TCP"
					}
					if s(cp, "name") == name && cpProto == proto {
						found = true
						if num(cp, "containerPort") == port {
							return true, true
						}
					}
				}
			}
			if !found {
				unknown = true
			}
		} else {
			start := num(p, "port")
			end := start
			if get(p, "endPort") != nil {
				end = num(p, "endPort")
			}
			if port >= start && port <= end {
				return true, true
			}
		}
	}
	return false, !unknown
}
func direction(objects []Obj, local, remote, dest Obj, dir string, port int, proto string) (string, []Obj) {
	isolated, allowed, unknown := false, false, false
	applied := []Obj{}
	for _, p := range objects {
		if s(p, "kind") != "NetworkPolicy" || ns(p) != ns(local) {
			continue
		}
		matches, known := selector(get(p, "spec", "podSelector"), local, "metadata", "labels")
		if !known {
			unknown = true
			continue
		}
		if !matches {
			continue
		}
		types, _ := get(p, "spec", "policyTypes").([]interface{})
		applies := false
		if len(types) == 0 {
			applies = dir == "ingress" || (dir == "egress" && len(arr(p, "spec", "egress")) > 0)
		} else {
			for _, t := range types {
				if strings.EqualFold(fmt.Sprint(t), dir) {
					applies = true
				}
			}
		}
		if !applies {
			continue
		}
		isolated = true
		applied = append(applied, p)
		for _, rule := range arr(p, "spec", dir) {
			pm, pk := portMatch(rule, dest, port, proto)
			if pk && !pm {
				continue
			}
			key := "from"
			if dir == "egress" {
				key = "to"
			}
			peers := arr(rule, key)
			match, known := len(peers) == 0, true
			for _, peer := range peers {
				m, k := peerMatch(peer, remote, p, objects)
				if m && k {
					match = true
				}
				if !k {
					known = false
				}
			}
			if pm && pk && match {
				allowed = true
			}
			if (!pk && (match || !known)) || (!known && pm) {
				unknown = true
			}
		}
	}
	if allowed {
		return "allowed", applied
	}
	if unknown {
		return "unknown", applied
	}
	if !isolated {
		return "allowed", applied
	}
	return "denied", applied
}
func diagnose(r *Report, o, b []Obj, n, name, src, dst string, port int) {
	source := find(o, "Pod", n, src)
	service := find(o, "Service", n, dst)
	if source == nil {
		missing(r, "Pod", n, src)
		return
	}
	if service == nil {
		missing(r, "Service", n, dst)
		return
	}
	proto := ""
	for _, p := range arr(service, "spec", "ports") {
		if num(p, "port") == port {
			proto = s(p, "protocol")
			if proto == "" {
				proto = "TCP"
			}
		}
	}
	if proto == "" {
		r.add("service-port-missing", "error", "confirmed", "Requested port is not declared by Service", service, "spec.ports")
		return
	}
	count := 0
	for _, slice := range o {
		if s(slice, "kind") != "EndpointSlice" || ns(slice) != n || s(slice, "metadata", "labels", "kubernetes.io/service-name") != dst {
			continue
		}
		for _, ep := range arr(slice, "endpoints") {
			if get(ep, "conditions", "ready") == false {
				continue
			}
			pod := find(o, "Pod", n, s(ep, "targetRef", "name"))
			if s(ep, "targetRef", "kind") != "Pod" || pod == nil {
				r.add("endpoint-unresolved", "warning", "unknown", "Endpoint cannot be mapped to a Pod", slice, "endpoints.targetRef")
				continue
			}
			count++
			targetPort := 0
			for _, sp := range arr(service, "spec", "ports") {
				if num(sp, "port") != port {
					continue
				}
				for _, epPort := range arr(slice, "ports") {
					pProto := s(epPort, "protocol")
					if pProto == "" {
						pProto = "TCP"
					}
					if s(epPort, "name") == s(sp, "name") && pProto == proto {
						targetPort = num(epPort, "port")
					}
				}
			}
			if targetPort == 0 {
				r.add("endpoint-port-unknown", "warning", "unknown", "EndpointSlice does not resolve requested Service port", slice, "ports")
				continue
			}
			for _, dir := range []string{"egress", "ingress"} {
				local, remote := source, pod
				if dir == "ingress" {
					local, remote = pod, source
				}
				verdict, policies := direction(o, local, remote, pod, dir, targetPort, proto)
				sev, cls := "info", "predicted"
				if verdict == "denied" {
					sev = "warning"
				}
				if verdict == "unknown" {
					sev = "warning"
					cls = "unknown"
				}
				r.add("policy-"+dir, sev, cls, fmt.Sprintf("%s to %s:%d/%s: %s under standard NetworkPolicy semantics", dir, s(pod, "metadata", "name"), targetPort, proto, verdict), pod, "metadata.labels")
				for _, p := range policies {
					r.add("policy-applied", "info", "confirmed", dir+" policy selected endpoint", p, "spec")
				}
			}
		}
	}
	if count == 0 {
		r.add("no-usable-endpoint", "warning", "unknown", "No usable Pod endpoint in available EndpointSlices", service, "EndpointSlice.endpoints")
	}
	r.Limitations = append(r.Limitations, "Actual connectivity, DNS, CNI behavior, external firewalls, Service Mesh and NAT ordering are unverified. IPBlock is unknown. Snapshot must include all relevant policies and Namespace labels; missing data can affect static results.")
}
