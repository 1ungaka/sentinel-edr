# CAU EDR — build, test and evaluation targets.
#
# Requirements: Go 1.24+, libyara 4.3+ with headers (apt install libyara-dev),
# pkg-config. For a user-local toolchain, `source scripts/dev-env.sh` first.

BINARY   ?= cau
MCPBINARY ?= cau-mcp
PKG      := ./...
GOFLAGS  ?=
# VERSION is derived from the newest reachable tag, so `make build` on a
# checkout always reports the version the tag would ship. -trimpath strips the
# build directory from recorded file paths, which makes the binary reproducible:
# the same tree built in different directories (or by two packagers) produces
# the same bytes.
VERSION  ?= $(shell command git describe --tags --always --dirty 2>/dev/null || git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -X main.version=$(VERSION)
# -trimpath strips the build directory from recorded file paths, which makes the
# binary reproducible; -buildmode=pie makes it position-independent, which is
# what Debian's hardening flags ask for and what lintian checks (without it both
# binaries are flagged hardening-no-pie). Go passes CGO_ENABLED builds through
# the C compiler's PIE mode, so the libyara cgo binding keeps working.
BUILDFLAGS ?= -trimpath -buildmode=pie

CORPUS   ?= corpus/smoke/manifest.json
CORPUS_DB ?= corpus/smoke/hashes.txt
RULES    ?= rules
BASELINE ?= baselines/smoke.json
POLICY   ?= baselines/policy.json
COVERAGE ?= baselines/attack-coverage.txt
EVAL_OUT ?= eval-out

export CGO_ENABLED=1

.PHONY: regex-audit eval-lab all build test test-race vet fmt fmt-check lint bench clean install \
         install-systemd install-logrotate install-config \
         eval eval-validate eval-run eval-gate baseline lint-rules coverage \
         coverage-gate coverage-record fuzz ci build-mcp

all: build build-mcp

build:
	go build $(GOFLAGS) $(BUILDFLAGS) -ldflags '$(LDFLAGS)' -o $(BINARY) .

# cau-mcp: the Model Context Protocol server (Phase 3). Same engine, driven by
# an LLM agent or IDE over JSON-RPC on stdio.
build-mcp:
	go build $(GOFLAGS) $(BUILDFLAGS) -ldflags '$(LDFLAGS)' -o $(MCPBINARY) ./cmd/cau-mcp

# TESTFLAGS carries a generous timeout: the static package's real-binary
# measurement tests (TestMeasureRealELF walks ~5k system files) are slow under
# -race, and the 10-minute go-test default can trip on a loaded CI runner.
TESTFLAGS ?= -timeout 25m

test:
	go test $(GOFLAGS) $(TESTFLAGS) $(PKG)

test-race:
	go test $(GOFLAGS) $(TESTFLAGS) -race -count=1 $(PKG)

vet:
	go vet $(PKG)

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

fmt-check:
	@out=$$(gofmt -l $$(find . -name '*.go' -not -path './vendor/*')); \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

lint: fmt-check vet

# Regex sweep for bug shapes: swallowed errors, memory handling, broken logic and
# more, over all the code in the tree. Hits are candidates and need reading.
regex-audit:
	python3 scripts/regex-audit.py --self-test
	python3 scripts/regex-audit.py

bench:
	go test -run '^$$' -bench . -benchmem ./scanner/ ./scanner/static/ ./scanner/stego/

# Robustness fuzzing: drive the untrusted-input parsers with coverage-guided
# mutation. The invariant is "never panic". FUZZTIME tunes each target's run
# (default 30s); a crasher lands under <pkg>/testdata/fuzz/ and becomes a
# committed regression seed. The seed corpora also run as fast unit tests
# under `make test`, so this target is for hunting, not for the gate.
FUZZTIME ?= 30s
fuzz: build
	go test ./scanner/static/ -run '^$$' -fuzz '^FuzzParseELF$$' -fuzztime $(FUZZTIME)
	go test ./scanner/static/ -run '^$$' -fuzz '^FuzzParsePE$$'  -fuzztime $(FUZZTIME)
	go test ./scanner/static/ -run '^$$' -fuzz '^FuzzAnalyze$$'  -fuzztime $(FUZZTIME)
	go test ./scanner/static/ -run '^$$' -fuzz '^FuzzParseMachO$$' -fuzztime $(FUZZTIME)
	go test ./scanner/static/ -run '^$$' -fuzz '^FuzzParseELFDynamic$$' -fuzztime $(FUZZTIME)
	go test ./scanner/stego/  -run '^$$' -fuzz '^FuzzScan$$'     -fuzztime $(FUZZTIME)
	go test ./scanner/encchain/ -run '^$$' -fuzz '^FuzzAnalyze$$' -fuzztime $(FUZZTIME)
	go test ./scanner/lnk/    -run '^$$' -fuzz '^FuzzAnalyze$$' -fuzztime $(FUZZTIME)
	go test ./scanner/ole/    -run '^$$' -fuzz '^FuzzAnalyze$$' -fuzztime $(FUZZTIME)
	go test ./scanner/pdf/    -run '^$$' -fuzz '^FuzzAnalyze$$' -fuzztime $(FUZZTIME)
	go test ./scanner/iso/    -run '^$$' -fuzz '^FuzzAnalyze$$' -fuzztime $(FUZZTIME)
	go test ./scanner/linuxpkg/ -run '^$$' -fuzz '^FuzzAnalyze$$' -fuzztime $(FUZZTIME)
	go test ./scanner/chm/    -run '^$$' -fuzz '^FuzzAnalyze$$' -fuzztime $(FUZZTIME)
	go test ./scanner/uefi/   -run '^$$' -fuzz '^FuzzAnalyze$$' -fuzztime $(FUZZTIME)
	go test ./scanner/uefi/   -run '^$$' -fuzz '^FuzzLZMADecode$$' -fuzztime $(FUZZTIME)
	go test ./scanner/archive/ -run '^$$' -fuzz '^FuzzAnalyze$$' -fuzztime $(FUZZTIME)
	go test ./scanner/tradecraft/ -run '^$$' -fuzz '^FuzzAnalyze$$' -fuzztime $(FUZZTIME)
	go test ./scanner/        -run '^$$' -fuzz '^FuzzScanHeuristicsData$$' -fuzztime $(FUZZTIME)
	go test ./internal/peeler/ -run '^$$' -fuzz '^FuzzPeel$$' -fuzztime $(FUZZTIME)
	go test ./internal/intake/ -run '^$$' -fuzz '^FuzzParse$$' -fuzztime $(FUZZTIME)
	go test ./internal/release/ -run '^$$' -fuzz '^FuzzParse$$' -fuzztime $(FUZZTIME)
	go test ./internal/release/ -run '^$$' -fuzz '^FuzzVerifySignature$$' -fuzztime $(FUZZTIME)
	go test ./internal/updater/ -run '^$$' -fuzz '^FuzzVerify$$' -fuzztime $(FUZZTIME)
	go test ./internal/bootscan/ -run '^$$' -fuzz '^FuzzAnalyzeDisk$$' -fuzztime $(FUZZTIME)
	go test ./internal/bootscan/ -run '^$$' -fuzz '^FuzzFirmwareStructures$$' -fuzztime $(FUZZTIME)

# ── Evaluation harness ──────────────────────────────────────────────────────

eval-validate: build
	./$(BINARY) eval validate --corpus $(CORPUS) --verify-hashes

eval-run: build
	@mkdir -p $(EVAL_OUT)
	./$(BINARY) eval run --corpus $(CORPUS) --db $(CORPUS_DB) --rules $(RULES) \
		--out $(EVAL_OUT)/report.json

# Fail if the current tree regresses against the committed baseline.
eval-gate: eval-run
	./$(BINARY) eval gate --baseline $(BASELINE) --candidate $(EVAL_OUT)/report.json --policy $(POLICY)

eval: eval-validate eval-gate

# Re-record the baseline (review the diff before committing it).
baseline: build
	./$(BINARY) eval run --corpus $(CORPUS) --db $(CORPUS_DB) --rules $(RULES) \
		--out $(BASELINE) --quiet

# ── Recall and specificity (measured on separate corpora) ───────────────────

HELDOUT_MANIFEST ?= corpus/heldout/manifest.json

# Recall (miss rate) against the held-out corpus of real malware the rules were
# NOT authored from. Opt-in: skipped cleanly when the corpus has not been
# fetched, so CI (which never downloads malware) is unaffected. Build it with
# 'cau heldout pull' + scripts/fetch-heldout.sh.
eval-recall: build
	@if [ -f "$(HELDOUT_MANIFEST)" ]; then \
		mkdir -p $(EVAL_OUT); \
		./$(BINARY) eval validate --corpus $(HELDOUT_MANIFEST) --verify-hashes --require-provenance; \
		./$(BINARY) eval run --corpus $(HELDOUT_MANIFEST) --rules $(RULES) --out $(EVAL_OUT)/recall.json; \
		./$(BINARY) eval report $(EVAL_OUT)/recall.json; \
	else \
		echo "eval-recall: no $(HELDOUT_MANIFEST); run 'cau heldout pull' + scripts/fetch-heldout.sh (skipping)"; \
	fi

# Specificity (false positives + near misses) over a real clean population.
# Point CLEAN_ROOT at a tree known to be benign (e.g. a Kali install's /usr).
CLEAN_ROOT ?=
eval-specificity: build
	@if [ -z "$(CLEAN_ROOT)" ]; then \
		echo "eval-specificity: set CLEAN_ROOT=<benign dir> (e.g. CLEAN_ROOT=/usr) (skipping)"; \
	else \
		mkdir -p $(EVAL_OUT); \
		scripts/clean-manifest.sh "$(CLEAN_ROOT)" > $(EVAL_OUT)/specificity-manifest.json; \
		./$(BINARY) eval run --corpus $(EVAL_OUT)/specificity-manifest.json --rules $(RULES) --out $(EVAL_OUT)/specificity.json; \
		./$(BINARY) eval report $(EVAL_OUT)/specificity.json; \
	fi

# Detection rate against real tooling on this host, with no key and no download
# of live malware: Kali's offensive tools plus msfvenom payloads, against benign
# files from the same machine. Positives are split by tool, so `heldout` asks
# about tools the rules were not written from. Author against `dev`; read only
# the aggregate from `heldout`. Build it once with scripts/build-lab-corpus.py.
LAB ?= corpus/lab
eval-lab: build
	@if [ -f "$(LAB)/manifest-dev.json" ]; then \
		mkdir -p $(EVAL_OUT)/lab; \
		reports=""; \
		for split in dev heldout revshell-dev revshell-heldout catalog; do \
			if [ -f "$(LAB)/manifest-$$split.json" ]; then \
				./$(BINARY) eval run --corpus $(LAB)/manifest-$$split.json --rules $(RULES) \
					--out $(EVAL_OUT)/lab/$$split.json --quiet >/dev/null; \
				reports="$$reports $(EVAL_OUT)/lab/$$split.json"; \
			fi; \
		done; \
		scripts/lab-summary.py $$reports; \
	else \
		echo "eval-lab: run scripts/build-lab-corpus.py generate, then manifest (skipping)"; \
	fi

# ── Detection content gates ─────────────────────────────────────────────────

# Rule hygiene: compile, required meta, technique ids, dead strings.
lint-rules: build
	./$(BINARY) rules lint --rules $(RULES)

# Fail if the content lost a technique, or gained one nobody recorded.
coverage-gate: build
	./$(BINARY) coverage --rules $(RULES) --expect $(COVERAGE) --quiet --format text >/dev/null

# Render the matrix: text to stdout, an ATT&CK Navigator layer to EVAL_OUT.
coverage: build
	@mkdir -p $(EVAL_OUT)
	./$(BINARY) coverage --rules $(RULES) --expect $(COVERAGE) --quiet --format navigator --pretty --output $(EVAL_OUT)/attack-navigator.json
	./$(BINARY) coverage --rules $(RULES) --expect $(COVERAGE) --quiet --format sarif --pretty --output $(EVAL_OUT)/attack-coverage.sarif
	./$(BINARY) coverage --rules $(RULES) --expect $(COVERAGE) --quiet

# Re-record the expectation (review the diff before committing it).
coverage-record: build
	./$(BINARY) coverage --rules $(RULES) --expect $(COVERAGE) --record --quiet --format text >/dev/null

ci: lint build build-mcp test-race lint-rules coverage-gate eval

# ── Install ─────────────────────────────────────────────────────────────────
# Installs the binary plus its content to PREFIX. The binary finds
# $(PREFIX)/share/cau automatically (see resources.go).
PREFIX ?= /usr/local
# The share-relative install prefix. Debian, Arch and Fedora all agree on
# /usr/share for these five trees, so every packaging path installs the same
# files through the same target instead of reimplementing the list.
SHARE       = $(DESTDIR)$(PREFIX)/share
LICENSEDIR  = $(SHARE)/licenses/cau
DOCDIR      = $(SHARE)/doc/cau
MANDIR      = $(SHARE)/man/man1
BASHCOMPDIR = $(SHARE)/bash-completion/completions
ZSHCOMPDIR  = $(SHARE)/zsh/site-functions
FISHCOMPDIR = $(SHARE)/fish/vendor_completions.d

install: build build-mcp
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/share/cau/rules $(DESTDIR)$(PREFIX)/share/cau/signatures
	install -m 0755 $(BINARY) $(DESTDIR)$(PREFIX)/bin/$(BINARY)
	install -m 0755 $(MCPBINARY) $(DESTDIR)$(PREFIX)/bin/$(MCPBINARY)
	install -m 0644 rules/*.yar $(DESTDIR)$(PREFIX)/share/cau/rules/
	install -m 0644 signatures/hashes.txt signatures/fuzzy.txt $(DESTDIR)$(PREFIX)/share/cau/signatures/
	install -d $(LICENSEDIR) $(DOCDIR) $(MANDIR) $(BASHCOMPDIR) $(ZSHCOMPDIR) $(FISHCOMPDIR)
	install -m 0644 LICENSE $(LICENSEDIR)/LICENSE
	install -m 0644 README.md CHANGELOG.md $(DOCDIR)/
	install -m 0644 docs/cau.1 $(MANDIR)/cau.1
	install -m 0644 docs/cau-mcp.1 $(MANDIR)/cau-mcp.1
	install -m 0644 completions/cau.bash $(BASHCOMPDIR)/cau
	install -m 0644 completions/cau.zsh $(ZSHCOMPDIR)/_cau
	install -m 0644 completions/cau.fish $(FISHCOMPDIR)/cau.fish

# The optional scheduled-scan units are installed but not enabled: a security
# scanner that starts walking the filesystem at install time is a surprise, not
# a feature. The Debian package and the PKGBUILD install these too.
install-systemd:
	install -d $(DESTDIR)$(PREFIX)/lib/systemd/system
	install -m 0644 packaging/systemd/cau-daemon.service $(DESTDIR)$(PREFIX)/lib/systemd/system/
	install -m 0644 packaging/systemd/cau-defend.service $(DESTDIR)$(PREFIX)/lib/systemd/system/
	install -m 0644 packaging/systemd/cau-scan.service $(DESTDIR)$(PREFIX)/lib/systemd/system/
	install -m 0644 packaging/systemd/cau-scan.timer $(DESTDIR)$(PREFIX)/lib/systemd/system/

# Rotation for what the resident daemon writes. This is not optional polish for
# a service designed to be left running: cau-defend.service appends to
# /var/log/cau/defend.jsonl forever, so without this the agent eventually fills
# the disk of the host it is protecting. Installed under /etc, which is why it
# is its own target rather than part of install-systemd.
install-logrotate:
	install -d $(DESTDIR)/etc/logrotate.d
	install -m 0644 packaging/logrotate/cau $(DESTDIR)/etc/logrotate.d/cau

# The agent configuration. 0644 root-owned on purpose: the agent refuses to read
# a configuration file that is group- or world-writable, because a file somebody
# else can rewrite is an input from them rather than configuration. The secret
# does not live here (see packaging/cau.conf); it goes in /etc/cau/forward.env
# at 0600, which is created by the operator, not shipped.
install-config:
	install -d $(DESTDIR)/etc/cau
	install -m 0644 packaging/cau.conf $(DESTDIR)/etc/cau/cau.conf

clean:
	rm -rf $(BINARY) $(BINARY).exe $(EVAL_OUT) coverage.out
