# bash completion for the CAU EDR command line (cau).
#
# Install (Debian/Kali/Arch): /usr/share/bash-completion/completions/cau
# Install (make install):     $(PREFIX)/share/bash-completion/completions/cau
# Or print it from this binary: cau completion bash
#
# The command and flag tables mirror the dispatch in main.go and the cmd_*.go
# flag definitions; cmd_completion_test.go asserts every command in "cau help"
# also appears here, so the two cannot drift apart silently.
#
# This script is deliberately standalone: it does not source
# /usr/share/bash-completion/bash_completion, so it works in a minimal container
# and with a hand-typed `source completions/cau.bash` alike.

_cau() {
    local cur prev sub flags top
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    top="scan hash cluster add-hash add-fuzzy eval heldout rules coverage
quarantine canary peel firmware ps installed feed intake update selftest
verify-self bundle completion version help"

    # ── flags ────────────────────────────────────────────────────────────────
    # Flags complete once the command word is present and the word being typed
    # looks like a flag. Anything else falls through to the next rule, so file
    # and directory arguments keep bash's default filename completion.
    if [ "$COMP_CWORD" -ge 2 ]; then
        case "$cur" in
            -*)
                case "${COMP_WORDS[1]}" in
                    scan)
                        flags="-dir -file -db -rules -fuzzy-db -signers -feed
-format -output -pretty -fail-on -jobs -interval -max-in-memory
-yara-timeout -quarantine -quarantine-store -quarantine-level -quiet
-follow-symlinks -no-fail-on-scan-error -heuristic-threshold
-static-threshold -stego-threshold -encchain-threshold -lnk-threshold
-ole-threshold -pdf-threshold -iso-threshold -pkg-threshold -peel-threshold
-archive-threshold -chm-threshold -no-yara -no-heuristics -no-static
-no-fuzzy -no-stego -no-fusion -no-encchain -no-lnk -no-ole -no-pdf -no-iso
-no-pkg -no-peel -no-archive -no-chm"
                        ;;
                    hash|cluster)
                        flags="-file -db -format -output -pretty -max-in-memory
-name -type -hash -imphashes"
                        ;;
                    eval)
                        flags="-corpus -db -rules -fuzzy-db -baseline -candidate
-policy -out -report -json -verify-hashes -require-provenance -jobs
-max-file-size -on-error -quiet -heuristic-threshold -static-threshold
-stego-threshold -encchain-threshold -no-yara -no-heuristics -no-static
-no-stego -no-fusion -no-hash"
                        ;;
                    rules|coverage)
                        flags="-rules -db -fuzzy-db -format -output -pretty
-strict -profile -expect -record -include-info -frameworks -no-yara -quiet"
                        ;;
                    heldout)
                        flags="-root -db -url -source -sha256 -key-file -batch
-family -label -license -limit -notes -retries -out"
                        ;;
                    quarantine)
                        flags="-store -format -force -keep -threat -to"
                        ;;
                    canary)
                        flags="-dir -manifest -count -format"
                        ;;
                    feed)
                        flags="-feed -from -url -replace"
                        ;;
                    peel)
                        flags="-file -format -max-depth -max-nodes
-max-children -max-output -timeout"
                        ;;
                    firmware)
                        flags="-file -format -threshold -implants"
                        ;;
                    ps)
                        flags="-format -threshold -proc-root -feed"
                        ;;
                    installed)
                        flags="-format -threshold -feed -dpkg-info -pacman-local"
                        ;;
                    intake)
                        flags="-input -url -format -db -output -dry-run"
                        ;;
                    selftest)
                        flags="-db -rules -fuzzy-db -manifest -record -sign-key
-pubkey"
                        ;;
                    update)
                        flags="-from -url -db -pubkey -dry-run"
                        ;;
                    verify-self)
                        flags="-from -url -name -pubkey"
                        ;;
                    bundle)
                        flags="-db -db-version -min-engine -out -sign-key"
                        ;;
                    add-hash)
                        flags="-db -label"
                        ;;
                    add-fuzzy)
                        flags="-db -label"
                        ;;
                    completion)
                        flags=""
                        ;;
                    version|help)
                        flags=""
                        ;;
                    *)
                        return 0
                        ;;
                esac
                # Go's flag package accepts "-flag" and "--flag" alike, so the
                # word list carries both spellings of each flag; typing either
                # --dir or -dir completes.
                local word both=""
                for word in $flags -h --help; do
                    both+=" $word"
                    case "$word" in --*) ;; *) both+=" --${word#-}" ;; esac
                done
                COMPREPLY=( $(compgen -W "$both" -- "$cur") )
                return 0
                ;;
        esac
    fi

    # ── subcommands of the second word ───────────────────────────────────────
    if [ "$COMP_CWORD" -eq 2 ]; then
        case "${COMP_WORDS[1]}" in
            eval)        sub="validate run report diff gate policy help" ;;
            heldout)     sub="init add pull sync remove rm list manifest help" ;;
            rules)       sub="lint list help" ;;
            quarantine)  sub="add list restore verify delete help" ;;
            canary)      sub="plant check help" ;;
            feed)        sub="list check update help" ;;
            bundle)      sub="update checksums" ;;
            completion)  sub="bash zsh fish" ;;
            help)        sub="$top" ;;
            *)           return 0 ;;
        esac
        COMPREPLY=( $(compgen -W "$sub" -- "$cur") )
        return 0
    fi

    # ── top level ────────────────────────────────────────────────────────────
    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=( $(compgen -W "$top -h --help" -- "$cur") )
        return 0
    fi

    return 0
} &&
complete -F _cau cau cau-mcp
