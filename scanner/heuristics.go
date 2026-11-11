package scanner

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"github.com/1ungaka/sentinel-edr/internal/safefs"
	"github.com/1ungaka/sentinel-edr/scanner/static"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode/utf16"
	"unsafe"

	"github.com/1ungaka/sentinel-edr/internal/prefilter"
)

// Heuristic scoring model
//
// The heuristic detector looks for two kinds of evidence: Windows API names in
// a PE import table, and suspicious substrings in the printable ASCII / UTF-16
// strings of any file. Evidence is scored like this:
//
//  1. Every *pattern* scores at most once per file, however many strings
//     contain it. The previous implementation scored each distinct string, so
//     a binary carrying its Authenticode certificate chain scored +16 from the
//     sixteen "http://" CRL and OCSP URLs alone (measured on plink.exe).
//  2. Every *category* has a cap. A ransomware sample that imports five crypto
//     APIs is not five times more suspicious than one that imports one.
//  3. The "weak" categories (networking, timers, file deletion, system
//     discovery, temp paths, ...) are things nearly every real program does.
//     Together they can contribute at most weakBudget points, so no amount of
//     ordinary behaviour adds up to a detection on its own.
//  4. An API seen in the import table is not scored a second time when its
//     name also shows up as a string (it always does: import names are stored
//     as strings).
//
// The threshold was then chosen against the Windows tool set shipped on Kali
// (/usr/share/windows-resources: debuggers, remote-access tools, credential
// dumpers) so that single-capability binaries stay below it and multi-stage
// behaviour (injection + persistence, credential access + network, encoded
// PowerShell + download) crosses it. See heuristics_test.go for the fixtures
// that pin this. A debugger such as OllyDbg still scores: it legitimately has
// the exact import profile of a process injector, and the report says so.

// DefaultHeuristicThreshold is the shipped score at which a file is reported
// as suspicious.
const DefaultHeuristicThreshold = 7

// HeuristicThreshold is the threshold used when a caller does not pass one.
// It is a variable so operators can retune it (CLI flag) without a rebuild.
var HeuristicThreshold = DefaultHeuristicThreshold

// DefaultMaxHeuristicSize is the largest file ScanHeuristics reads into memory.
const DefaultMaxHeuristicSize int64 = DefaultMaxInMemory

// weakBudget is the maximum total contribution of all weak categories.
const weakBudget = 2

// maxExamplesPerPattern bounds how many example strings are kept per pattern.
const maxExamplesPerPattern = 3

// HeuristicMatch is one piece of evidence.
type HeuristicMatch struct {
	// Indicator is the API name or the (first) string that matched.
	Indicator string
	Category  string
	// Source is "PE Import" or "String".
	Source string
	// Pattern is the configured pattern that matched (equal to Indicator for
	// imports).
	Pattern string
	// Score is the weight of the pattern. It is applied once per pattern and
	// may be reduced further by the category cap and the weak budget.
	Score int
	// Hits is how many distinct strings matched the pattern.
	Hits int
	// Examples holds up to maxExamplesPerPattern matching strings.
	Examples []string
	// Technique is the ATT&CK technique the category is evidence for ("" when
	// none applies). It is derived from the category, never from the file.
	Technique string
}

// CategoryScore explains how one category contributed to the total.
type CategoryScore struct {
	Category string
	// Raw is the sum of pattern weights in the category.
	Raw int
	// Applied is the contribution after the category cap and weak budget.
	Applied int
	Cap     int
	Weak    bool
	// Technique is the ATT&CK technique the category maps to, if any.
	Technique string
}

// HeuristicResult is the heuristic verdict for one file.
type HeuristicResult struct {
	FilePath   string
	Matches    []HeuristicMatch
	Categories []CategoryScore
	Score      int
	// Threshold is the threshold the result was scored against (0 means the
	// package variable HeuristicThreshold applies).
	Threshold int
	// IsPE reports whether the file parsed as a PE image (import scanning ran).
	IsPE bool
	// IsELF reports whether the file parsed as an ELF image (its undefined
	// dynamic symbols, or a kernel module's undefined .symtab entries, were
	// scanned as imports).
	IsELF bool
	// Skipped is a non-empty reason when the file was deliberately not scanned
	// (too large). A skipped file is neither detected nor an error.
	Skipped string
	Error   error
}

// EffectiveThreshold returns the threshold that applies to this result.
func (h HeuristicResult) EffectiveThreshold() int {
	if h.Threshold > 0 {
		return h.Threshold
	}
	return HeuristicThreshold
}

// Detected reports whether the score reached the threshold.
func (h HeuristicResult) Detected() bool {
	if h.Error != nil || h.Skipped != "" {
		return false
	}
	return h.Score >= h.EffectiveThreshold()
}

// HeuristicOptions tunes a heuristic scan.
type HeuristicOptions struct {
	// Threshold overrides HeuristicThreshold (0 = package default).
	Threshold int
	// MaxSize overrides DefaultMaxHeuristicSize for ScanHeuristicsFile
	// (0 = default).
	MaxSize int64
}

// ── Indicator tables ─────────────────────────────────────────────────────────

type indicator struct {
	Category string
	Score    int
}

// Category names.
const (
	catInjection     = "Process Injection"
	catHollowing     = "Process Hollowing"
	catAntiDebug     = "Anti-Debug"
	catTiming        = "Timing / Sandbox Evasion"
	catPrivEsc       = "Privilege Escalation"
	catRegPersist    = "Registry Persistence"
	catSvcPersist    = "Service Persistence"
	catStartup       = "Startup Folder Persistence"
	catNetwork       = "Network Activity"
	catURLDownload   = "URL Download API"
	catKeylog        = "Keylogging"
	catSysDiscovery  = "System Discovery"
	catProcDiscovery = "Process Discovery"
	catFileOps       = "File Manipulation"
	catCrypto        = "Encryption / Ransomware"
	catCredAccess    = "Credential Access"
	catMemProtect    = "Memory Protection"
	catShellExec     = "Shell Execution"
	catEncodedPS     = "Encoded PowerShell"
	catPSExec        = "PowerShell Execution"
	catScriptExec    = "Script Execution"
	catLOLBin        = "LOLBin Execution"
	catLOLDownload   = "LOLBin Download"
	catShadowCopy    = "Shadow Copy Deletion"
	catPaths         = "Suspicious Paths"
	catAcctDiscovery = "Account Discovery"
	catRansomNote    = "Ransom Note"
	catRansomFamily  = "Ransomware Family"
	catVMDetect      = "VM Detection"
	catSandboxDetect = "Sandbox Detection"
	catUnixShell     = "Unix Shell Reference"
	catDownloadTool  = "Download Tool Reference"
	catKernelRootkit = "Kernel Rootkit"
)

// categoryCaps bounds each category's contribution. Categories not listed are
// capped at defaultCategoryCap.
var categoryCaps = map[string]int{
	catInjection:     8,
	catHollowing:     3,
	catAntiDebug:     3,
	catPrivEsc:       3,
	catRegPersist:    3,
	catSvcPersist:    3,
	catStartup:       2,
	catKeylog:        5,
	catCrypto:        6,
	catCredAccess:    8,
	catShellExec:     2,
	catEncodedPS:     3,
	catPSExec:        3,
	catScriptExec:    2,
	catLOLBin:        3,
	catLOLDownload:   3,
	catShadowCopy:    4,
	catURLDownload:   3,
	catAcctDiscovery: 2,
	catRansomNote:    5,
	catRansomFamily:  3,
	catVMDetect:      2,
	catSandboxDetect: 3,
	catKernelRootkit: 6,
}

const defaultCategoryCap = 4

// weakCategories share weakBudget between them.
var weakCategories = map[string]bool{
	catNetwork:       true,
	catTiming:        true,
	catSysDiscovery:  true,
	catProcDiscovery: true,
	catFileOps:       true,
	catPaths:         true,
	catMemProtect:    true,
	catUnixShell:     true,
	catDownloadTool:  true,
}

// categoryTechniques maps each category to the ATT&CK technique it is
// evidence for. The mapping is part of the detection content: fused verdicts
// and the coverage matrix read it, and a category without a mapping is
// reported as such rather than padded with a loose fit ("Suspicious Paths"
// is a location hint, not a technique).
var categoryTechniques = map[string]string{
	catInjection:     "T1055",     // Process Injection
	catHollowing:     "T1055.012", // Process Hollowing
	catAntiDebug:     "T1622",     // Debugger Evasion
	catTiming:        "T1497.003", // Virtualization/Sandbox Evasion: Time Based Evasion
	catPrivEsc:       "T1134",     // Access Token Manipulation
	catRegPersist:    "T1547.001", // Registry Run Keys / Startup Folder
	catSvcPersist:    "T1543.003", // Create or Modify System Process: Windows Service
	catStartup:       "T1547.001", // Registry Run Keys / Startup Folder
	catNetwork:       "T1071",     // Application Layer Protocol
	catURLDownload:   "T1105",     // Ingress Tool Transfer
	catKeylog:        "T1056.001", // Input Capture: Keylogging
	catSysDiscovery:  "T1082",     // System Information Discovery
	catProcDiscovery: "T1057",     // Process Discovery
	catFileOps:       "T1070.004", // Indicator Removal: File Deletion
	catCrypto:        "T1486",     // Data Encrypted for Impact
	catCredAccess:    "T1003",     // OS Credential Dumping
	catMemProtect:    "T1055",     // Process Injection (RWX staging)
	catShellExec:     "T1059.003", // Windows Command Shell
	catEncodedPS:     "T1027.010", // Obfuscated Files or Information: Command Obfuscation
	catPSExec:        "T1059.001", // PowerShell
	catScriptExec:    "T1059.005", // Visual Basic
	catLOLBin:        "T1218",     // System Binary Proxy Execution
	catLOLDownload:   "T1105",     // Ingress Tool Transfer
	catShadowCopy:    "T1490",     // Inhibit System Recovery
	catAcctDiscovery: "T1087",     // Account Discovery
	catRansomNote:    "T1486",     // Data Encrypted for Impact
	catRansomFamily:  "T1486",     // Data Encrypted for Impact
	catVMDetect:      "T1497.001", // Virtualization/Sandbox Evasion: System Checks
	catSandboxDetect: "T1497.001", // Virtualization/Sandbox Evasion: System Checks
	catUnixShell:     "T1059.004", // Unix Shell
	catDownloadTool:  "T1105",     // Ingress Tool Transfer
	catKernelRootkit: "T1014",     // Rootkit
}

// CategoryTechnique returns the ATT&CK technique id a heuristic category is
// evidence for, or "" when the category has no defensible mapping.
func CategoryTechnique(category string) string {
	return categoryTechniques[category]
}

// Categories lists every heuristic category with its ATT&CK technique, in a
// stable order, for coverage reporting.
func Categories() []CategoryScore {
	out := make([]CategoryScore, 0, len(categoryCaps)+len(weakCategories))
	seen := map[string]bool{}
	add := func(cat string) {
		if seen[cat] {
			return
		}
		seen[cat] = true
		cap, ok := categoryCaps[cat]
		if !ok {
			cap = defaultCategoryCap
		}
		out = append(out, CategoryScore{Category: cat, Cap: cap, Weak: weakCategories[cat], Technique: categoryTechniques[cat]})
	}
	for _, api := range suspiciousAPIs {
		add(api.Category)
	}
	for _, sp := range suspiciousStrings {
		add(sp.Category)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Category < out[j].Category })
	return out
}

// suspiciousAPIs maps PE and ELF import names to a category and weight. Names
// must be the exact exported symbol, which for the Windows A/W API pairs means
// both spellings. The Linux entries are deliberately few: an ELF import table
// names libc, and libc is not evidence. What is listed is what a debugger,
// an injector or a kernel rootkit cannot do without.
var suspiciousAPIs = map[string]indicator{
	// Linux user space: cross-process memory and control (debuggers score
	// here too, the same documented class as OllyDbg on Windows)
	"ptrace":            {catInjection, 2},
	"process_vm_writev": {catInjection, 2},
	"process_vm_readv":  {catInjection, 1},
	"pidfd_getfd":       {catInjection, 1},
	// Linux kernel modules: what a rootkit needs to find and patch the
	// syscall table or hook functions. Ordinary drivers import none of them.
	"kallsyms_lookup_name":     {catKernelRootkit, 3},
	"register_kprobe":          {catKernelRootkit, 2},
	"register_kretprobe":       {catKernelRootkit, 1},
	"register_ftrace_function": {catKernelRootkit, 2},
	"ftrace_set_filter_ip":     {catKernelRootkit, 2},
	"set_memory_rw":            {catKernelRootkit, 2},
	"set_memory_x":             {catKernelRootkit, 1},
	"lookup_address":           {catKernelRootkit, 1},
	"text_poke":                {catKernelRootkit, 3},
	"text_poke_bp":             {catKernelRootkit, 3},
	"stop_machine":             {catKernelRootkit, 1},
	"sys_call_table":           {catKernelRootkit, 3},
	"find_task_by_vpid":        {catKernelRootkit, 1},

	// Process injection
	"VirtualAllocEx":       {catInjection, 2},
	"WriteProcessMemory":   {catInjection, 3},
	"NtWriteVirtualMemory": {catInjection, 3},
	"CreateRemoteThread":   {catInjection, 3},
	"CreateRemoteThreadEx": {catInjection, 3},
	"NtCreateThreadEx":     {catInjection, 3},
	"RtlCreateUserThread":  {catInjection, 3},
	"QueueUserAPC":         {catInjection, 2},
	"SetThreadContext":     {catInjection, 2},
	"NtMapViewOfSection":   {catInjection, 2},
	"OpenProcess":          {catInjection, 1},
	"NtUnmapViewOfSection": {catHollowing, 3},
	"ZwUnmapViewOfSection": {catHollowing, 3},

	// Defense evasion. IsDebuggerPresent is imported by the MSVC CRT itself,
	// so it is nearly worthless on its own.
	"IsDebuggerPresent":          {catAntiDebug, 1},
	"CheckRemoteDebuggerPresent": {catAntiDebug, 2},
	"NtQueryInformationProcess":  {catAntiDebug, 1},
	"NtSetInformationThread":     {catAntiDebug, 2},
	"GetTickCount":               {catTiming, 1},
	"GetTickCount64":             {catTiming, 1},
	"Sleep":                      {catTiming, 1},
	"NtDelayExecution":           {catTiming, 2},

	// Privilege escalation
	"AdjustTokenPrivileges":   {catPrivEsc, 2},
	"OpenProcessToken":        {catPrivEsc, 1},
	"LookupPrivilegeValueA":   {catPrivEsc, 1},
	"LookupPrivilegeValueW":   {catPrivEsc, 1},
	"ImpersonateLoggedOnUser": {catPrivEsc, 1},

	// Persistence
	"RegSetValueExA": {catRegPersist, 1},
	"RegSetValueExW": {catRegPersist, 1},
	"SHSetValueA":    {catRegPersist, 1},
	"SHSetValueW":    {catRegPersist, 1},
	"OpenSCManagerA": {catSvcPersist, 1},
	"OpenSCManagerW": {catSvcPersist, 1},
	"CreateServiceA": {catSvcPersist, 2},
	"CreateServiceW": {catSvcPersist, 2},
	"StartServiceA":  {catSvcPersist, 1},
	"StartServiceW":  {catSvcPersist, 1},

	// Network / C2
	"WSAStartup":         {catNetwork, 1},
	"connect":            {catNetwork, 1},
	"InternetOpenA":      {catNetwork, 1},
	"InternetOpenW":      {catNetwork, 1},
	"InternetOpenUrlA":   {catNetwork, 1},
	"InternetOpenUrlW":   {catNetwork, 1},
	"HttpSendRequestA":   {catNetwork, 1},
	"HttpSendRequestW":   {catNetwork, 1},
	"WinHttpOpen":        {catNetwork, 1},
	"URLDownloadToFileA": {catURLDownload, 3},
	"URLDownloadToFileW": {catURLDownload, 3},

	// Keylogging / credential access
	"SetWindowsHookExA":         {catKeylog, 3},
	"SetWindowsHookExW":         {catKeylog, 3},
	"GetAsyncKeyState":          {catKeylog, 2},
	"GetKeyboardState":          {catKeylog, 1},
	"LsaEnumerateLogonSessions": {catCredAccess, 2},
	"LsaRetrievePrivateData":    {catCredAccess, 3},
	"SamConnect":                {catCredAccess, 3},
	"SamOpenDomain":             {catCredAccess, 2},
	"SamQueryInformationUser":   {catCredAccess, 3},
	"CredEnumerateA":            {catCredAccess, 3},
	"CredEnumerateW":            {catCredAccess, 3},
	"CryptUnprotectData":        {catCredAccess, 2},
	"MiniDumpWriteDump":         {catCredAccess, 2},

	// Discovery
	"GetSystemInfo":            {catSysDiscovery, 1},
	"GetComputerNameA":         {catSysDiscovery, 1},
	"GetComputerNameW":         {catSysDiscovery, 1},
	"GetUserNameA":             {catSysDiscovery, 1},
	"GetUserNameW":             {catSysDiscovery, 1},
	"EnumProcesses":            {catProcDiscovery, 1},
	"CreateToolhelp32Snapshot": {catProcDiscovery, 1},
	"Process32FirstW":          {catProcDiscovery, 1},
	"Process32NextW":           {catProcDiscovery, 1},

	// File operations (common in ransomware, and in everything else)
	"MoveFileExA":        {catFileOps, 1},
	"MoveFileExW":        {catFileOps, 1},
	"DeleteFileA":        {catFileOps, 1},
	"DeleteFileW":        {catFileOps, 1},
	"SetFileAttributesA": {catFileOps, 1},
	"SetFileAttributesW": {catFileOps, 1},

	// Crypto
	"CryptEncrypt":               {catCrypto, 3},
	"CryptGenKey":                {catCrypto, 2},
	"CryptDeriveKey":             {catCrypto, 2},
	"CryptAcquireContextA":       {catCrypto, 1},
	"CryptAcquireContextW":       {catCrypto, 1},
	"BCryptEncrypt":              {catCrypto, 3},
	"BCryptGenerateSymmetricKey": {catCrypto, 2},

	// Memory protection changes (RWX staging)
	"VirtualProtect":         {catMemProtect, 1},
	"VirtualProtectEx":       {catMemProtect, 2},
	"NtProtectVirtualMemory": {catMemProtect, 2},
}

type stringPattern struct {
	Pattern  string
	Category string
	Score    int
}

// suspiciousStrings are matched case-insensitively as substrings of extracted
// strings. Each pattern scores once per file.
var suspiciousStrings = []stringPattern{
	// Execution via shell
	{"cmd.exe /c", catShellExec, 2},
	{"cmd /c", catShellExec, 2},
	{"powershell -enc", catEncodedPS, 3},
	{"-encodedcommand", catEncodedPS, 3},
	{" -enc ", catEncodedPS, 3},
	{"frombase64string(", catEncodedPS, 2},
	{"powershell -nop", catPSExec, 2},
	{"powershell -w hidden", catPSExec, 2},
	{" -w hidden", catPSExec, 2},
	{"-windowstyle hidden", catPSExec, 2},
	{"-executionpolicy bypass", catPSExec, 2},
	{"invoke-expression", catPSExec, 1},
	{"downloadstring(", catPSExec, 3},
	{"wscript.exe", catScriptExec, 1},
	{"cscript.exe", catScriptExec, 1},
	{"mshta.exe", catLOLBin, 3},
	{"rundll32.exe", catLOLBin, 1},
	{"regsvr32.exe", catLOLBin, 1},
	{"certutil -decode", catLOLDownload, 3},
	{"certutil -urlcache", catLOLDownload, 3},
	{"bitsadmin /transfer", catLOLDownload, 3},
	{"schtasks /create", catRegPersist, 2},
	{"vssadmin delete shadows", catShadowCopy, 4},
	{"wbadmin delete catalog", catShadowCopy, 4},
	{"bcdedit /set", catShadowCopy, 2},

	// Persistence keys
	{"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", catRegPersist, 2},
	{"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", catRegPersist, 3},
	{"Image File Execution Options", catRegPersist, 3},
	{"SYSTEM\\CurrentControlSet\\Services", catSvcPersist, 1},
	{"\\Start Menu\\Programs\\Startup", catStartup, 2},

	// Suspicious paths
	{"%TEMP%", catPaths, 1},
	{"\\AppData\\Roaming", catPaths, 1},
	{"\\AppData\\Local\\Temp", catPaths, 1},

	// Credential / privilege strings
	{"SeDebugPrivilege", catPrivEsc, 2},
	{"sekurlsa", catCredAccess, 4},
	{"lsadump", catCredAccess, 4},
	{"mimikatz", catCredAccess, 3},
	{"lsass.exe", catCredAccess, 2},
	{"SAM\\Domains\\Account", catCredAccess, 3},
	{"net user", catAcctDiscovery, 1},
	{"net localgroup administrators", catAcctDiscovery, 2},

	// Network indicators
	{"http://", catNetwork, 1},
	{"https://", catNetwork, 1},
	{"ftp://", catNetwork, 1},
	{"/bin/sh", catUnixShell, 1},
	{"wget ", catDownloadTool, 1},
	{"curl ", catDownloadTool, 1},

	// Ransomware
	{"files have been encrypted", catRansomNote, 4},
	{"all your files", catRansomNote, 2},
	{"decryption key", catRansomNote, 2},
	{"bitcoin", catRansomNote, 1},
	// Weak on purpose: Go's resolver carries ".onion" (RFC 7686), so every Go
	// binary with a network stack has it (measured: buildah's copy helper).
	{".onion", catRansomNote, 1},
	{"CryptoLocker", catRansomFamily, 3},
	{"WannaCry", catRansomFamily, 3},
	{"WanaCrypt0r", catRansomFamily, 3},

	// Evasion / anti-analysis
	{"IsDebuggerPresent", catAntiDebug, 1},
	{"VirtualBox", catVMDetect, 2},
	{"VMware", catVMDetect, 2},
	{"VBOX", catVMDetect, 2},
	{"vboxservice", catVMDetect, 2},
	{"vmtoolsd", catVMDetect, 2},
	{"SbieDll.dll", catSandboxDetect, 3},
	{"SandboxEnvironment", catSandboxDetect, 3},

	// Injection strings (for non-PE carriers and dynamically resolved APIs;
	// de-duplicated against the import table)
	{"VirtualAllocEx", catInjection, 1},
	{"WriteProcessMemory", catInjection, 2},
	{"CreateRemoteThread", catInjection, 2},
	{"NtCreateThreadEx", catInjection, 2},
}

// ── Scanning ─────────────────────────────────────────────────────────────────

// ScanHeuristics scans one file with the default options.
func ScanHeuristics(filePath string) HeuristicResult {
	return ScanHeuristicsFile(filePath, HeuristicOptions{})
}

// ScanHeuristicsFile reads a file (subject to the size cap) and scans it.
func ScanHeuristicsFile(filePath string, opts HeuristicOptions) HeuristicResult {
	result := HeuristicResult{FilePath: filePath, Threshold: opts.Threshold}

	maxSize := opts.MaxSize
	if maxSize <= 0 {
		maxSize = DefaultMaxHeuristicSize
	}
	fi, err := os.Stat(filePath)
	if err != nil {
		result.Error = fmt.Errorf("could not stat file: %w", err)
		return result
	}
	if fi.IsDir() {
		result.Error = fmt.Errorf("%s is a directory", filePath)
		return result
	}
	if fi.Size() > maxSize {
		result.Skipped = fmt.Sprintf("file is %d bytes, over the %d byte heuristic size limit", fi.Size(), maxSize)
		return result
	}

	data, err := safefs.ReadFile(filePath, maxSize)
	if err != nil {
		result.Error = fmt.Errorf("could not read file: %w", err)
		return result
	}
	return ScanHeuristicsData(filePath, data, opts)
}

// ScanHeuristicsData scores an in-memory buffer. filePath is used for
// reporting only; nothing is read from disk.
func ScanHeuristicsData(filePath string, data []byte, opts HeuristicOptions) HeuristicResult {
	result := HeuristicResult{FilePath: filePath, Threshold: opts.Threshold}

	imports, isPE := peImports(data)
	result.IsPE = isPE
	source := "PE Import"
	if !isPE {
		if elf, ok := elfImports(data); ok {
			imports, source = elf, "ELF Import"
			result.IsELF = true
		}
	}

	// Imports: one match per distinct API.
	seenAPI := make(map[string]bool)
	for _, name := range imports {
		info, ok := suspiciousAPIs[name]
		if !ok || seenAPI[name] {
			continue
		}
		seenAPI[name] = true
		result.Matches = append(result.Matches, HeuristicMatch{
			Indicator: name,
			Pattern:   name,
			Category:  info.Category,
			Source:    source,
			Score:     info.Score,
			Hits:      1,
			Technique: categoryTechniques[info.Category],
		})
	}

	// Strings: one match per pattern, with hit counts and examples.
	lowerAPIs := make(map[string]bool, len(seenAPI))
	for name := range seenAPI {
		lowerAPIs[strings.ToLower(name)] = true
	}
	for _, m := range scanStrings(data) {
		if lowerAPIs[strings.ToLower(m.Pattern)] {
			continue // already credited through the import table
		}
		result.Matches = append(result.Matches, m)
	}

	result.Categories, result.Score = scoreCategories(result.Matches)
	return result
}

// scoreCategories applies the per-category caps and the weak budget.
func scoreCategories(matches []HeuristicMatch) ([]CategoryScore, int) {
	raw := make(map[string]int)
	order := []string{}
	for _, m := range matches {
		if _, seen := raw[m.Category]; !seen {
			order = append(order, m.Category)
		}
		raw[m.Category] += m.Score
	}

	var out []CategoryScore
	total := 0
	weakLeft := weakBudget
	for _, cat := range order {
		cap, ok := categoryCaps[cat]
		if !ok {
			cap = defaultCategoryCap
		}
		cs := CategoryScore{Category: cat, Raw: raw[cat], Cap: cap, Weak: weakCategories[cat], Technique: categoryTechniques[cat]}
		applied := raw[cat]
		if applied > cap {
			applied = cap
		}
		if cs.Weak {
			if applied > weakLeft {
				applied = weakLeft
			}
			weakLeft -= applied
		}
		cs.Applied = applied
		total += applied
		out = append(out, cs)
	}
	// Strongest categories first so the report leads with the reason.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Applied != out[j].Applied {
			return out[i].Applied > out[j].Applied
		}
		return out[i].Category < out[j].Category
	})
	return out, total
}

// peImports parses an in-memory PE image and returns its imported symbol names.
// It returns (nil, false) for anything that is not a PE file.
func peImports(data []byte) ([]string, bool) {
	if len(data) < 64 || data[0] != 'M' || data[1] != 'Z' {
		return nil, false
	}
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, false
	}
	defer f.Close()

	syms, err := f.ImportedSymbols()
	if err != nil {
		return nil, true
	}
	names := make([]string, 0, len(syms))
	for _, sym := range syms {
		// ImportedSymbols returns "funcname:dllname"
		name := sym
		if idx := strings.Index(sym, ":"); idx != -1 {
			name = sym[:idx]
		}
		names = append(names, name)
	}
	return names, true
}

// elfImports returns the undefined symbol names of an ELF image through the
// static package's bounds-checked parser. ok is false for non-ELF input or an
// unparseable header.
func elfImports(data []byte) ([]string, bool) {
	if !static.IsELF(data) {
		return nil, false
	}
	e, err := static.ParseELF(data)
	if err != nil {
		return nil, false
	}
	return e.Imports, true
}

// ── Raw string extractor ─────────────────────────────────────────────────────

const minStringLen = 6

// scanStrings extracts printable ASCII and UTF-16LE strings from raw bytes and
// returns one HeuristicMatch per pattern that occurred, in table order.
func scanStrings(data []byte) []HeuristicMatch {
	lowerPatterns, filter := stringPatterns()

	hits := make(map[int]*HeuristicMatch)
	seenExample := make(map[int]map[string]bool)

	// consider is given a view into data for an ASCII string, so whatever is kept
	// has to be copied or one short string would pin the whole file in the result.
	consider := func(s string, patterns []int) {
		sl := strings.ToLower(s)
		copied := false
		for _, i := range patterns {
			p := lowerPatterns[i]
			if !strings.Contains(sl, p) {
				continue
			}
			if !copied {
				s, copied = strings.Clone(s), true
			}
			m, ok := hits[i]
			if !ok {
				sp := suspiciousStrings[i]
				m = &HeuristicMatch{
					Indicator: s,
					Pattern:   sp.Pattern,
					Category:  sp.Category,
					Source:    "String",
					Score:     sp.Score,
					Technique: categoryTechniques[sp.Category],
				}
				hits[i] = m
				seenExample[i] = make(map[string]bool)
			}
			if seenExample[i][s] {
				continue
			}
			seenExample[i][s] = true
			m.Hits++
			if len(m.Examples) < maxExamplesPerPattern {
				m.Examples = append(m.Examples, s)
			}
		}
	}

	// An ASCII string is a contiguous run of the file, so a pattern absent from the
	// whole file can't be in any of them. That is one pass of an automaton against
	// every string times every pattern, and on most files nothing survives it.
	view := unsafe.String(unsafe.SliceData(data), len(data)) // audit:ok safe only while scan buffers are never pooled or written; consider clones whatever it keeps
	present := filter.Scan(view)
	var asciiPatterns []int
	for i := range lowerPatterns {
		if present.May(i) {
			asciiPatterns = append(asciiPatterns, i)
		}
	}
	present.Release()
	if len(asciiPatterns) > 0 {
		forEachASCII(view, func(s string) { consider(s, asciiPatterns) })
	}
	// UTF-16 interleaves its bytes, so the pass above says nothing about these.
	for _, s := range extractUTF16(data) {
		consider(s, allStringPatterns())
	}

	out := make([]HeuristicMatch, 0, len(hits))
	for i := range suspiciousStrings {
		if m, ok := hits[i]; ok {
			out = append(out, *m)
		}
	}
	return out
}

// stringPatterns is suspiciousStrings lowercased, with a filter over them, built
// once: it used to be rebuilt for every file.
var stringPatterns = sync.OnceValues(func() ([]string, *prefilter.Set) {
	lower := make([]string, len(suspiciousStrings))
	exprs := make([]string, len(suspiciousStrings))
	for i, p := range suspiciousStrings {
		lower[i] = strings.ToLower(p.Pattern)
		exprs[i] = regexp.QuoteMeta(lower[i])
	}
	return lower, prefilter.New(exprs)
})

var allStringPatterns = sync.OnceValue(func() []int {
	all := make([]int, len(suspiciousStrings))
	for i := range all {
		all[i] = i
	}
	return all
})

// forEachASCII calls fn with each printable ASCII sequence of minStringLen+ chars,
// as a view of text rather than a copy. A file of text is millions of them.
func forEachASCII(text string, fn func(string)) {
	start := -1
	for i := 0; i < len(text); i++ {
		if isPrintableASCII(text[i]) {
			if start == -1 {
				start = i
			}
		} else {
			if start != -1 && i-start >= minStringLen {
				fn(text[start:i])
			}
			start = -1
		}
	}
	if start != -1 && len(text)-start >= minStringLen {
		fn(text[start:])
	}
}

// extractUTF16 pulls UTF-16LE sequences of minStringLen+ chars. Both byte
// alignments are tried so a wide string at an odd offset is not missed.
func extractUTF16(data []byte) []string {
	var results []string
	for _, off := range []int{0, 1} {
		var buf []uint16
		flush := func() {
			if len(buf) >= minStringLen {
				results = append(results, string(utf16.Decode(buf)))
			}
			buf = buf[:0]
		}
		for i := off; i+1 < len(data); i += 2 {
			v := binary.LittleEndian.Uint16(data[i : i+2])
			if v >= 0x20 && v <= 0x7e {
				buf = append(buf, v)
			} else {
				flush()
			}
		}
		flush()
	}
	return results
}

func isPrintableASCII(b byte) bool {
	return b >= 0x20 && b <= 0x7e
}
