# fish completion for the CAU EDR command line (cau).
#
# Install (make install):     $(PREFIX)/share/fish/vendor_completions.d/cau.fish
# Install (Arch):             /usr/share/fish/vendor_completions.d/cau.fish
# Or print it from this binary: cau completion fish

# Top level: no path completion, only the verbs.
complete -c cau -f
complete -c cau -n __fish_use_subcommand -a scan -d 'scan files and directories'
complete -c cau -n __fish_use_subcommand -a hash -d 'print SHA-256, imphash, TLSH and ssdeep digests'
complete -c cau -n __fish_use_subcommand -a cluster -d 'group PE files by import-table similarity'
complete -c cau -n __fish_use_subcommand -a add-hash -d 'append a hash signature to the database'
complete -c cau -n __fish_use_subcommand -a add-fuzzy -d 'append a TLSH / ssdeep / imphash signature'
complete -c cau -n __fish_use_subcommand -a eval -d 'corpus evaluation harness'
complete -c cau -n __fish_use_subcommand -a heldout -d 'encrypted held-out recall corpus'
complete -c cau -n __fish_use_subcommand -a rules -d 'lint or list the YARA rules'
complete -c cau -n __fish_use_subcommand -a coverage -d 'ATT&CK coverage matrix of the shipped content'
complete -c cau -n __fish_use_subcommand -a honesty -d 'coverage, measurements and content integrity in one document'
complete -c cau -n __fish_use_subcommand -a quarantine -d 'vault flagged files'
complete -c cau -n __fish_use_subcommand -a canary -d 'plant decoys and detect tampering'
complete -c cau -n __fish_use_subcommand -a peel -d 'walk an obfuscation chain'
complete -c cau -n __fish_use_subcommand -a firmware -d 'parse a UEFI firmware image'
complete -c cau -n __fish_use_subcommand -a boot-scan -d 'read the boot chain, read-only'
complete -c cau -n __fish_use_subcommand -a hwid -d 'snapshot and compare the hardware identity'
complete -c cau -n __fish_use_subcommand -a persist -d 'audit the host for persistence'
complete -c cau -n __fish_use_subcommand -a defend -d 'chain every layer into correlated incidents'
complete -c cau -n __fish_use_subcommand -a ps -d 'scan the live process table'
complete -c cau -n __fish_use_subcommand -a net -d 'scan the network plane; block confirmed peers'
complete -c cau -n '__fish_seen_subcommand_from net' -a 'block unblock blocks clear' -d 'manage network blocks'
complete -c cau -n __fish_use_subcommand -a installed -d 'audit installed-package maintainer scripts'
complete -c cau -n __fish_use_subcommand -a feed -d 'manage the abuse-intel feed'
complete -c cau -n __fish_use_subcommand -a intake -d 'ingest a threat-intel feed'
complete -c cau -n __fish_use_subcommand -a update -d 'install a signed signature-DB bundle'
complete -c cau -n __fish_use_subcommand -a selftest -d 'verify detection content integrity'
complete -c cau -n __fish_use_subcommand -a verify-self -d 'verify this binary against the release manifest'
complete -c cau -n __fish_use_subcommand -a bundle -d 'produce signed release artifacts (CI)'
complete -c cau -n __fish_use_subcommand -a version -d 'print the version'
complete -c cau -n __fish_use_subcommand -a help

# Second level: the subcommands that mirror main.go.
complete -c cau -n '__fish_seen_subcommand_from eval' -a 'validate run report diff gate policy help'
complete -c cau -n '__fish_seen_subcommand_from heldout' -a 'init add pull sync remove rm list manifest help'
complete -c cau -n '__fish_seen_subcommand_from rules' -a 'lint list help'
complete -c cau -n '__fish_seen_subcommand_from quarantine' -a 'add list restore verify delete help'
complete -c cau -n '__fish_seen_subcommand_from canary' -a 'plant check help'
complete -c cau -n '__fish_seen_subcommand_from feed' -a 'list check update help'
complete -c cau -n '__fish_seen_subcommand_from bundle' -a 'update checksums'

# The flags that are common to the scanning family.
complete -c cau -n '__fish_seen_subcommand_from scan hash cluster peel ps' -l file -d 'a single file'
complete -c cau -n '__fish_seen_subcommand_from scan' -l dir -d 'a directory to scan recursively'
complete -c cau -n '__fish_seen_subcommand_from scan' -l db -d 'hash signature database'
complete -c cau -n '__fish_seen_subcommand_from scan' -l rules -d 'YARA rules directory'
complete -c cau -n '__fish_seen_subcommand_from scan' -l fuzzy-db -d 'fuzzy-hash database'
complete -c cau -n '__fish_seen_subcommand_from scan hash cluster' -l format -d 'output format' -r -f -a 'text json sarif ocsf'
complete -c cau -n '__fish_seen_subcommand_from scan' -l format -d 'SIEM sink format' -r -f -a 'ecs cef leef gelf syslog syslog-ecs syslog-cef syslog-leef otlp'
complete -c cau -n '__fish_seen_subcommand_from scan' -l sink-url -d 'forward findings to a collector (udp/tcp/tls/https)' -r
complete -c cau -n '__fish_seen_subcommand_from scan' -l sink-format -d 'sink format for --sink-url' -r -f -a 'ecs cef leef gelf syslog syslog-ecs syslog-cef syslog-leef otlp'
complete -c cau -n '__fish_seen_subcommand_from scan hash cluster' -l output -d 'write the report to a file' -r
complete -c cau -n '__fish_seen_subcommand_from scan' -l fail-on -d 'findings tier that fails the run' -r -f -a 'clean heuristic malicious none'
complete -c cau -n '__fish_seen_subcommand_from scan' -l jobs -d 'parallel workers' -r
complete -c cau -n '__fish_seen_subcommand_from scan' -l interval -d 'run as a daemon on this interval' -r
complete -c cau -n '__fish_seen_subcommand_from scan' -l quarantine -d 'vault flagged files as they are found'
complete -c cau -n '__fish_seen_subcommand_from scan' -l pretty -d 'pretty-print JSON'
complete -c cau -n '__fish_seen_subcommand_from scan' -l quiet -d 'suppress the banner and progress'
complete -c cau -f -l help -d 'print help'
