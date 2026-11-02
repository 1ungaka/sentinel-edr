// Package attack carries the small slice of MITRE ATT&CK (Enterprise) the
// engine references: technique names and tactics for every id the detection
// content maps to, so reports and the coverage matrix can print a name next
// to an id without a network or a STIX bundle. Ids the catalog does not
// know are still valid; they are rendered without a name.
//
// Names follow ATT&CK v15. The catalog is data, not a claim of coverage:
// the coverage matrix says what is detected, this package only says what an
// id is called.
package attack

import (
	"regexp"
	"sort"
	"strings"
)

// Version is the ATT&CK release the catalog's names follow.
const Version = "15"

// Technique is one ATT&CK technique or sub-technique.
type Technique struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Tactics []string `json:"tactics,omitempty"`
}

// Tactic names used in the catalog.
const (
	InitialAccess   = "Initial Access"
	Execution       = "Execution"
	Persistence     = "Persistence"
	PrivEsc         = "Privilege Escalation"
	DefenseEvasion  = "Defense Evasion"
	CredAccess      = "Credential Access"
	Discovery       = "Discovery"
	LateralMovement = "Lateral Movement"
	Collection      = "Collection"
	C2              = "Command and Control"
	Impact          = "Impact"
)

var catalog = map[string]Technique{
	"T1003":     {"T1003", "OS Credential Dumping", []string{CredAccess}},
	"T1003.008": {"T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow", []string{CredAccess}},
	"T1014":     {"T1014", "Rootkit", []string{DefenseEvasion}},
	"T1027":     {"T1027", "Obfuscated Files or Information", []string{DefenseEvasion}},
	"T1027.002": {"T1027.002", "Obfuscated Files or Information: Software Packing", []string{DefenseEvasion}},
	"T1027.007": {"T1027.007", "Obfuscated Files or Information: Dynamic API Resolution", []string{DefenseEvasion}},
	"T1027.009": {"T1027.009", "Obfuscated Files or Information: Embedded Payloads", []string{DefenseEvasion}},
	"T1027.010": {"T1027.010", "Obfuscated Files or Information: Command Obfuscation", []string{DefenseEvasion}},
	"T1027.013": {"T1027.013", "Obfuscated Files or Information: Encrypted/Encoded File", []string{DefenseEvasion}},
	"T1036":     {"T1036", "Masquerading", []string{DefenseEvasion}},
	"T1036.001": {"T1036.001", "Masquerading: Invalid Code Signature", []string{DefenseEvasion}},
	"T1036.005": {"T1036.005", "Masquerading: Match Legitimate Name or Location", []string{DefenseEvasion}},
	"T1055":     {"T1055", "Process Injection", []string{DefenseEvasion, PrivEsc}},
	"T1055.012": {"T1055.012", "Process Injection: Process Hollowing", []string{DefenseEvasion, PrivEsc}},
	"T1056.001": {"T1056.001", "Input Capture: Keylogging", []string{Collection, CredAccess}},
	"T1057":     {"T1057", "Process Discovery", []string{Discovery}},
	"T1059":     {"T1059", "Command and Scripting Interpreter", []string{Execution}},
	"T1059.001": {"T1059.001", "Command and Scripting Interpreter: PowerShell", []string{Execution}},
	"T1059.003": {"T1059.003", "Command and Scripting Interpreter: Windows Command Shell", []string{Execution}},
	"T1059.004": {"T1059.004", "Command and Scripting Interpreter: Unix Shell", []string{Execution}},
	"T1059.005": {"T1059.005", "Command and Scripting Interpreter: Visual Basic", []string{Execution}},
	"T1059.007": {"T1059.007", "Command and Scripting Interpreter: JavaScript", []string{Execution}},
	"T1070.004": {"T1070.004", "Indicator Removal: File Deletion", []string{DefenseEvasion}},
	"T1070.006": {"T1070.006", "Indicator Removal: Timestomp", []string{DefenseEvasion}},
	"T1071":     {"T1071", "Application Layer Protocol", []string{C2}},
	"T1082":     {"T1082", "System Information Discovery", []string{Discovery}},
	"T1087":     {"T1087", "Account Discovery", []string{Discovery}},
	"T1091":     {"T1091", "Replication Through Removable Media", []string{InitialAccess, LateralMovement}},
	"T1105":     {"T1105", "Ingress Tool Transfer", []string{C2}},
	"T1137":     {"T1137", "Office Application Startup", []string{Persistence}},
	"T1203":     {"T1203", "Exploitation for Client Execution", []string{Execution}},
	"T1204":     {"T1204", "User Execution", []string{Execution}},
	"T1204.001": {"T1204.001", "User Execution: Malicious Link", []string{Execution}},
	"T1204.002": {"T1204.002", "User Execution: Malicious File", []string{Execution}},
	"T1106":     {"T1106", "Native API", []string{Execution}},
	"T1134":     {"T1134", "Access Token Manipulation", []string{DefenseEvasion, PrivEsc}},
	"T1140":     {"T1140", "Deobfuscate/Decode Files or Information", []string{DefenseEvasion}},
	"T1218":     {"T1218", "System Binary Proxy Execution", []string{DefenseEvasion}},
	"T1486":     {"T1486", "Data Encrypted for Impact", []string{Impact}},
	"T1490":     {"T1490", "Inhibit System Recovery", []string{Impact}},
	"T1497.001": {"T1497.001", "Virtualization/Sandbox Evasion: System Checks", []string{DefenseEvasion, Discovery}},
	"T1497.003": {"T1497.003", "Virtualization/Sandbox Evasion: Time Based Evasion", []string{DefenseEvasion, Discovery}},
	"T1543.003": {"T1543.003", "Create or Modify System Process: Windows Service", []string{Persistence, PrivEsc}},
	"T1547.001": {"T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", []string{Persistence, PrivEsc}},
	"T1553.002": {"T1553.002", "Subvert Trust Controls: Code Signing", []string{DefenseEvasion}},
	"T1555":     {"T1555", "Credentials from Password Stores", []string{CredAccess}},
	"T1555.003": {"T1555.003", "Credentials from Password Stores: Credentials from Web Browsers", []string{CredAccess}},
	"T1564.001": {"T1564.001", "Hide Artifacts: Hidden Files and Directories", []string{DefenseEvasion}},
	"T1574":     {"T1574", "Hijack Execution Flow", []string{Persistence, PrivEsc, DefenseEvasion}},
	"T1574.006": {"T1574.006", "Hijack Execution Flow: Dynamic Linker Hijacking", []string{Persistence, PrivEsc, DefenseEvasion}},
	"T1056":     {"T1056", "Input Capture", []string{Collection, CredAccess}},
	"T1070":     {"T1070", "Indicator Removal", []string{DefenseEvasion}},
	"T1497":     {"T1497", "Virtualization/Sandbox Evasion", []string{DefenseEvasion, Discovery}},
	"T1543":     {"T1543", "Create or Modify System Process", []string{Persistence, PrivEsc}},
	"T1547":     {"T1547", "Boot or Logon Autostart Execution", []string{Persistence, PrivEsc}},
	"T1553":     {"T1553", "Subvert Trust Controls", []string{DefenseEvasion}},
	"T1564":     {"T1564", "Hide Artifacts", []string{DefenseEvasion}},
	"T1620":     {"T1620", "Reflective Code Loading", []string{DefenseEvasion}},
	"T1622":     {"T1622", "Debugger Evasion", []string{DefenseEvasion, Discovery}},
}

var idRe = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)

// ValidID reports whether s is shaped like an ATT&CK technique id
// (T1234 or T1234.001). It does not check that the id exists.
func ValidID(s string) bool { return idRe.MatchString(strings.TrimSpace(s)) }

// Lookup returns the catalog entry for id, and whether it is known.
func Lookup(id string) (Technique, bool) {
	t, ok := catalog[strings.TrimSpace(id)]
	return t, ok
}

// Name returns the technique name for id, or "" when the catalog does not
// know it.
func Name(id string) string { return catalog[strings.TrimSpace(id)].Name }

// Tactics returns the tactics a technique belongs to, or nil when unknown.
func Tactics(id string) []string { return catalog[strings.TrimSpace(id)].Tactics }

// Parent returns the parent technique id of a sub-technique ("T1027" for
// "T1027.002"), or the id itself.
func Parent(id string) string {
	id = strings.TrimSpace(id)
	if i := strings.IndexByte(id, '.'); i > 0 {
		return id[:i]
	}
	return id
}

// IDs returns every id in the catalog, sorted.
func IDs() []string {
	out := make([]string, 0, len(catalog))
	for id := range catalog {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
