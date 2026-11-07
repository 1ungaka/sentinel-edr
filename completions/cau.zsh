#compdef cau cau-mcp
# zsh completion for the CAU EDR command line (cau).
#
# Install (make install):     $(PREFIX)/share/zsh/site-functions/_cau
# Install (Debian):           /usr/share/zsh/vendor-completions/_cau
# Install (Arch):             /usr/share/zsh/site-functions/_cau
# Or print it from this binary: cau completion zsh
#
# The subcommand table mirrors the dispatch in main.go; cmd_completion_test.go
# asserts every command in "cau help" also appears here, so the two cannot
# drift apart silently.

_cau() {
    local -a top
    top=(
        scan hash cluster add-hash add-fuzzy eval heldout rules coverage honesty
        quarantine canary peel firmware boot-scan hwid ps net persist defend installed feed intake update
        selftest verify-self bundle version help
    )

    _arguments -C '1:command:->command' '*::arg:->args'

    case $state in
        command)
            _describe -t commands 'cau command' top
            ;;
        args)
            local -a sub
            case ${words[2]} in
                eval)
                    sub=(validate run report diff gate policy help)
                    ;;
                heldout)
                    sub=(init add pull sync remove rm list manifest help)
                    ;;
                rules)
                    sub=(lint list help)
                    ;;
                quarantine)
                    sub=(add list restore verify delete help)
                    ;;
                canary)
                    sub=(plant check help)
                    ;;
                feed)
                    sub=(list check update help)
                    ;;
                net)
                    sub=(block unblock blocks clear)
                    ;;
                bundle)
                    sub=(update checksums sbom keygen)
                    ;;
                *)
                    _files
                    return
                    ;;
            esac
            _describe -t subcommands 'cau subcommand' sub
            ;;
    esac
}
