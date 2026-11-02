# CAU EDR — build, test and evaluation targets.
#
# Requirements: Go 1.24+, libyara 4.3+ with headers (apt install libyara-dev),
# pkg-config. For a user-local toolchain, `source scripts/dev-env.sh` first.

BINARY   ?= cau
MCPBINARY ?= cau-mcp
PKG      := ./...
GOFLAGS  ?=
VERSION  ?= $(shell command git describe --tags --always --dirty 2>/dev/null || git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -X main.version=$(VERSION)

CORPUS   ?= corpus/smoke/manifest.json
CORPUS_DB ?= corpus/smoke/hashes.txt
RULES    ?= rules
BASELINE ?= baselines/smoke.json
POLICY   ?= baselines/policy.json
COVERAGE ?= baselines/attack-coverage.txt
EVAL_OUT ?= eval-out

export CGO_ENABLED=1

.PHONY: all build test test-race vet fmt fmt-check lint bench clean install \
        eval eval-validate eval-run eval-gate baseline lint-rules coverage \
        coverage-gate coverage-record fuzz ci build-mcp

all: build build-mcp

build:
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BINARY) .

# cau-mcp: the Model Context Protocol server (Phase 3). Same engine, driven by
# an LLM agent or IDE over JSON-RPC on stdio.
build-mcp:
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(MCPBINARY) ./cmd/cau-mcp

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
	go test ./scanner/stego/  -run '^$$' -fuzz '^FuzzScan$$'     -fuzztime $(FUZZTIME)
	go test ./scanner/encchain/ -run '^$$' -fuzz '^FuzzAnalyze$$' -fuzztime $(FUZZTIME)
	go test ./scanner/lnk/    -run '^$$' -fuzz '^FuzzAnalyze$$' -fuzztime $(FUZZTIME)
	go test ./scanner/ole/    -run '^$$' -fuzz '^FuzzAnalyze$$' -fuzztime $(FUZZTIME)
	go test ./scanner/pdf/    -run '^$$' -fuzz '^FuzzAnalyze$$' -fuzztime $(FUZZTIME)
	go test ./scanner/iso/    -run '^$$' -fuzz '^FuzzAnalyze$$' -fuzztime $(FUZZTIME)
	go test ./scanner/        -run '^$$' -fuzz '^FuzzScanHeuristicsData$$' -fuzztime $(FUZZTIME)

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
install: build build-mcp
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/share/cau/rules $(DESTDIR)$(PREFIX)/share/cau/signatures
	install -m 0755 $(BINARY) $(DESTDIR)$(PREFIX)/bin/$(BINARY)
	install -m 0755 $(MCPBINARY) $(DESTDIR)$(PREFIX)/bin/$(MCPBINARY)
	install -m 0644 rules/*.yar $(DESTDIR)$(PREFIX)/share/cau/rules/
	install -m 0644 signatures/hashes.txt signatures/fuzzy.txt $(DESTDIR)$(PREFIX)/share/cau/signatures/

clean:
	rm -rf $(BINARY) $(BINARY).exe $(EVAL_OUT) coverage.out
