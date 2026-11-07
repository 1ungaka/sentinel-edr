// Package forward ships what the agent concludes to a SIEM without ever making
// detection wait on the network.
//
// A scan has a report to render and an exit code to return, so it can forward
// synchronously at the end of the run and let a transport error be a warning on
// the way out. The defend daemon has neither: it is meant to be started once and
// left running, so every property that only matters over months is this
// package's problem rather than the caller's.
//
//   - Detection never blocks on delivery. Offer hands an event to a bounded
//     queue and returns; the network happens on the sink's own goroutine.
//   - A SIEM outage costs bounded memory, not the host. The queue has a fixed
//     size and drops its oldest event to admit a newer one, because the local
//     report is still the record of everything and the freshest incidents are
//     the ones an analyst is about to need.
//   - A failing manager is retried with a backoff, so an outage does not become
//     a hot loop against a service that is already struggling.
//
// OCSFIncident renders a correlated incident in the same OCSF 1.3.0 Detection
// Finding envelope as `cau scan --format ocsf`, so one SIEM rule matches events
// from either surface.
package forward

import (
	"net"
	"sort"
	"strings"
	"time"

	"github.com/s-b-repo/cau/internal/attack"
	"github.com/s-b-repo/cau/internal/correlate"
	"github.com/s-b-repo/cau/internal/report"
)

// Product identifies the agent that observed the incident. Host is the agent's
// hostname, which is what tells a fleet's events apart once they are in one
// index; it is carried in unmapped because OCSF puts the reporting device under
// a profile this envelope does not claim.
type Product struct {
	Name    string
	Version string
	URL     string
	Host    string
}

// DefaultProduct describes this build.
func DefaultProduct(host string) Product {
	return Product{
		Name:    report.DefaultToolName,
		Version: report.DefaultToolVersion,
		URL:     report.DefaultInformationURI,
		Host:    host,
	}
}

// OCSFIncident renders one correlated incident as an OCSF Detection Finding.
//
// The mapping keeps the daemon's own distinction, because it is the one an
// analyst acts on: a CONFIRMED incident is an alert at High severity, and an
// unconfirmed one is a Medium finding with is_alert false. The daemon raises the
// second on one layer's opinion alone, and a SIEM that paged on those would be
// paging on `grep "/dev/tcp" notes.txt`.
//
// finding_info.uid is the incident fingerprint rather than its id: that is what
// the daemon itself dedupes on, so if the same incident is raised again the SIEM
// sees the same uid and can collapse the two instead of showing a second alert.
func OCSFIncident(inc correlate.Incident, p Product, now time.Time) map[string]any {
	ms := now.UTC().UnixMilli()

	severityID, severity, isAlert := 3, "Medium", false
	if inc.Confirmed {
		severityID, severity, isAlert = 4, "High", true
	}

	layers := make([]string, 0, len(inc.Layers))
	for _, l := range inc.Layers {
		layers = append(layers, string(l))
	}

	ev := map[string]any{
		"activity_id":   report.OCSFActivityID,
		"activity_name": report.OCSFActivityName,
		"category_uid":  report.OCSFCategoryUID,
		"category_name": report.OCSFCategoryName,
		"class_uid":     report.OCSFClassUID,
		"class_name":    report.OCSFClassName,
		"type_uid":      report.OCSFTypeUID,
		"type_name":     report.OCSFTypeName,
		"time":          ms,
		"severity_id":   severityID,
		"severity":      severity,
		"status_id":     report.OCSFStatusNew,
		"status":        "New",
		"is_alert":      isAlert,
		"message":       incidentMessage(inc),
		"metadata": map[string]any{
			"version": report.OCSFVersion,
			"product": map[string]any{
				"name":        p.Name,
				"version":     p.Version,
				"vendor_name": "CAU",
				"url_string":  p.URL,
			},
			"logged_time": ms,
		},
		"finding_info": map[string]any{
			"title": incidentMessage(inc),
			"uid":   inc.Fingerprint(),
			"desc":  inc.Why,
			// analytic.uid names what detected this, not which incident it was.
			// It used to carry inc.ID, which is unique per artefact, so every
			// incident looked like a different kind of event: formats that use
			// this as their event or signature id — CEF and LEEF do — gave an
			// ArcSight or QRadar class map a value it could never group on. The
			// lead signal's class is stable across incidents of the same kind,
			// which is exactly what such a map is keyed on. The incident's own
			// identity is finding_info.uid, and its id stays in unmapped.
			"analytic": map[string]any{
				"name":    "cau defend correlation",
				"type_id": 4, // Behavioral
				"type":    "Behavioral",
				"uid":     analyticUID(inc),
				"desc":    inc.Why,
			},
			"attacks":      ocsfAttacks(inc.Techniques),
			"data_sources": layers,
		},
		// The incident verbatim: the layers that agreed, every signal with its
		// class, score, technique and detail, and what confirmed it. A mapping
		// that dropped this would make the SIEM a worse record than the host's
		// own log, which is the opposite of forwarding.
		"unmapped": map[string]any{
			"incident":   inc,
			"agent_host": p.Host,
			"confirmed":  inc.Confirmed,
			"score":      inc.Score,
			"layers":     layers,
			// verdict is the daemon's own tier, in the same field `cau scan`
			// uses for a file's verdict. Without it the wire formats derived
			// from this envelope carry the tier in severity alone, which loses
			// the distinction the daemon actually acts on: CONFIRMED is what it
			// would respond to, ALERT is what it leaves for a human.
			"verdict": incidentVerdict(inc),
		},
	}

	if evs := ocsfEvidences(inc); len(evs) > 0 {
		ev["evidences"] = evs
	}
	// One peer is an incident about a conversation, and OCSF's own field for it
	// is dst_endpoint. Several peers stay in evidences only: naming one of them
	// at the top level would make a SIEM rule act on an arbitrary choice.
	if len(inc.Peers) == 1 {
		ev["dst_endpoint"] = map[string]any{"ip": inc.Peers[0]}
	}
	if mw := ocsfMalware(inc); len(mw) > 0 {
		ev["malware"] = mw
	}
	return ev
}

// incidentVerdict is the daemon's tier for an incident, in its own vocabulary:
// CONFIRMED is what it would act on, ALERT is what it leaves for a human.
func incidentVerdict(inc correlate.Incident) string {
	if inc.Confirmed {
		return "CONFIRMED"
	}
	return "ALERT"
}

// leadSignal picks the signal an analyst reads first. Definitive evidence leads
// regardless of score, because a YARA or hash hit answers the question that a
// pile of behavioural observations only narrows.
func leadSignal(inc correlate.Incident) (correlate.Signal, bool) {
	var lead correlate.Signal
	best, found := -1, false
	for _, s := range inc.Signals {
		weight := s.Score
		if s.Definitive {
			weight += 1000
		}
		if weight > best {
			best, lead, found = weight, s, true
		}
	}
	return lead, found
}

// analyticUID identifies the kind of detection rather than the instance of it,
// so a SIEM keyed on it groups like with like.
func analyticUID(inc correlate.Incident) string {
	if lead, ok := leadSignal(inc); ok && lead.Class != "" {
		return "cau.defend." + lead.Class
	}
	return "cau.defend.correlate"
}

// incidentMessage is the one line a SIEM shows in a list. It names the state,
// the layers that agreed and the strongest signal, because "incident
// e3b0c442" on its own tells an analyst nothing.
func incidentMessage(inc correlate.Incident) string {
	state := incidentVerdict(inc)
	lead := ""
	if s, ok := leadSignal(inc); ok {
		lead = s.Class
		if s.Detail != "" {
			lead = s.Class + ": " + s.Detail
		}
	}
	layers := make([]string, 0, len(inc.Layers))
	for _, l := range inc.Layers {
		layers = append(layers, string(l))
	}
	msg := state + " incident (" + strings.Join(layers, "+") + ")"
	if lead != "" {
		msg += " " + lead
	}
	return truncate(msg, 400)
}

// ocsfAttacks maps each technique to an OCSF attack object, with its name and
// tactics resolved from the bundled catalogue so the SIEM does not have to.
func ocsfAttacks(techniques []string) []map[string]any {
	seen := map[string]bool{}
	var out []map[string]any
	for _, raw := range techniques {
		for _, id := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
			id = strings.TrimSpace(id)
			if id == "" || seen[id] || !attack.ValidID(id) {
				continue
			}
			seen[id] = true
			a := map[string]any{
				"technique": map[string]any{"uid": id, "name": attack.Name(id)},
				"version":   attack.Version,
			}
			if ts := attack.Tactics(id); len(ts) > 0 {
				tactics := make([]map[string]any, 0, len(ts))
				for _, t := range ts {
					tactics = append(tactics, map[string]any{"name": t})
				}
				a["tactics"] = tactics
			}
			out = append(out, a)
		}
	}
	return out
}

// ocsfEvidences names the artefacts: the files the incident is about and the
// processes it was seen in.
func ocsfEvidences(inc correlate.Incident) []map[string]any {
	var out []map[string]any
	for _, f := range inc.Files {
		out = append(out, map[string]any{
			"file": map[string]any{
				"name":    baseName(f),
				"path":    f,
				"type_id": 1,
				"type":    "Regular File",
			},
		})
	}
	for _, pid := range inc.PIDs {
		out = append(out, map[string]any{
			"process": map[string]any{"pid": pid},
		})
	}
	// Network evidence as an endpoint object, so a SIEM rule can pivot on an
	// address without reading details. A network incident forwarded without the
	// peer is the one thing an analyst is certain to need.
	for _, peer := range inc.Peers {
		ep := map[string]any{"ip": peer}
		if ip := net.ParseIP(peer); ip != nil && ip.To4() == nil {
			ep["type_id"], ep["type"] = 2, "IPv6"
		} else if ip != nil {
			ep["type_id"], ep["type"] = 1, "IPv4"
		}
		out = append(out, map[string]any{"dst_endpoint": ep})
	}
	return out
}

// ocsfMalware carries the exact identifications, so a SIEM can pivot on a threat
// name without parsing details. Only definitive signals qualify: a score is a
// suspicion, not a name.
func ocsfMalware(inc correlate.Incident) []map[string]any {
	names := map[string]bool{}
	for _, s := range inc.Signals {
		if !s.Definitive || s.Detail == "" {
			continue
		}
		names[s.Detail] = true
	}
	keys := make([]string, 0, len(names))
	for k := range names {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, map[string]any{"name": truncate(k, 200)})
	}
	return out
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
