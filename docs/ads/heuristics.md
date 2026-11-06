# ADS: Heuristics

## Goal
Surface files that name suspicious capabilities, through the Windows API
names in a PE import table (or an ELF's undefined dynamic symbols) and
substrings of their printable strings, with the categories responsible.

## Categorization
Thirty-three categories, thirty-two with an ATT&CK technique (T1055, T1003, T1486,
T1547.001, T1059.001, T1014 and the others in [Detectors](../detectors.md));
Suspicious Paths is deliberately unmapped. Pyramid of Pain: tools. Tier:
SUSPICIOUS.

## Strategy Abstract
A pattern scores once per file, every category is capped, the weak
categories share a budget of two points, and an API credited from the import
table is not scored again as a string. The threshold (7) requires multi-stage
behaviour: injection plus persistence, credential access plus network,
encoded PowerShell plus download.

## Technical Context
Indicator tables are in `scanner/heuristics.go`; `scanner.Categories()`
exposes the category → technique map that the coverage matrix and fused
verdicts read. Files over the in-memory cap are streamed and skip this pass,
and the report says so. The `.onion` indicator weighs 1 (down from the
original higher weight), because every Go binary with a network stack
carries the string in its `crypto/tls` initialisation list and the original
weight produced a steady trickle of benign hits.

## Blind Spots and Assumptions
Capability hidden behind dynamic API resolution or encryption; a binary that
does not name what it does. The ELF table is small on purpose because libc
imports are not evidence.

## False Positives
Debuggers and injection-capable developer tools: OllyDbg scores 11 because a
debugger has an injector's import profile; `sudo` scores 6 on Linux for its
`ptrace` / `process_vm_*` intercept feature. 28 of 349 files in the Kali
Windows tool set score at or above 7, almost all offensive tools shipped on
purpose.

## Validation
The smoke corpus fixtures (`make eval`); `go test ./scanner/ -run
TestHeuristic`; the measured numbers above are re-derived with `go test
./scanner/static/ -run TestMeasureReal -v` and belong in the docs when they
move.

## Priority
Medium: a score is evidence with an explanation. `--fail-on heuristic`
opts a pipeline into acting on it.

## Response
Read the categories and the indicators in the report; a single loud
category on a known developer tool is the documented false-positive class,
two independent categories on an unknown binary is not.
